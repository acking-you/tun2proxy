//! Correlate UDP DNS requests carried over one reliable TCP connection.

use std::collections::HashMap;

use hickory_proto::op::{Message, Query};

use crate::dns;

struct Pending {
    request: Vec<u8>,
    question: Query,
    client_id: u16,
}

#[derive(Default)]
pub(crate) struct Transactions {
    pending: HashMap<u16, Pending>,
}

impl Transactions {
    /// An identical UDP retry is already in flight on the reliable transport.
    /// Different requests may reuse a client ID; give each its own upstream ID.
    pub(crate) fn prepare(&mut self, request: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let query = dns::parse_data_to_dns_message(request, false)?;
        let question = dns::validate_dns_query(&query)?.clone();
        if self.pending.values().any(|pending| pending.request == request) {
            return Ok(None);
        }
        if self.pending.len() >= crate::MAX_OUTSTANDING_DNS_QUERIES {
            return Err(format!(
                "DNS-over-TCP outstanding query limit reached ({})",
                crate::MAX_OUTSTANDING_DNS_QUERIES
            ));
        }
        let mut upstream_id = query.id;
        while self.pending.contains_key(&upstream_id) {
            upstream_id = upstream_id.wrapping_add(1);
        }
        let mut forwarded = request.to_vec();
        forwarded[..2].copy_from_slice(&upstream_id.to_be_bytes());
        self.pending.insert(
            upstream_id,
            Pending {
                request: request.to_vec(),
                question,
                client_id: query.id,
            },
        );
        Ok(Some(forwarded))
    }

    pub(crate) fn complete(&mut self, response: &mut Message) -> Result<(), String> {
        let pending = self
            .pending
            .get(&response.id)
            .ok_or_else(|| format!("unsolicited DNS-over-TCP response ID {}", response.id))?;
        dns::validate_dns_response(response, response.id, &pending.question)?;
        let client_id = pending.client_id;
        self.pending.remove(&response.id);
        response.metadata.id = client_id;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{Name, RecordType};

    fn request(id: u16, name: &str) -> Vec<u8> {
        let mut query = Message::query();
        query.metadata.id = id;
        query.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
        query.to_vec().unwrap()
    }

    #[test]
    fn retries_and_id_collisions_preserve_both_queries_and_validate_responses() {
        let mut transactions = Transactions::default();
        let first = request(u16::MAX, "one.example.");
        let second = request(u16::MAX, "two.example.");
        let forwarded_first = transactions.prepare(&first).unwrap().unwrap();
        assert!(transactions.prepare(&first).unwrap().is_none());
        let forwarded_second = transactions.prepare(&second).unwrap().unwrap();
        assert_ne!(forwarded_first[..2], forwarded_second[..2]);
        assert!(transactions.prepare(&second).unwrap().is_none());

        let mut reply = dns::parse_data_to_dns_message(&forwarded_second, false).unwrap().into_response();
        let mut wrong_question = reply.clone();
        wrong_question.queries[0] = Query::query(Name::from_ascii("wrong.example.").unwrap(), RecordType::A);
        assert!(transactions.complete(&mut wrong_question).is_err());
        transactions.complete(&mut reply).unwrap();
        assert_eq!(reply.id, u16::MAX);
        assert_eq!(reply.queries[0].name().to_ascii(), "two.example.");

        let mut reply = dns::parse_data_to_dns_message(&forwarded_first, false).unwrap().into_response();
        transactions.complete(&mut reply).unwrap();
        assert_eq!(reply.id, u16::MAX);
        assert!(transactions.pending.is_empty());
        assert!(transactions.prepare(&first).unwrap().is_some());
    }

    #[test]
    fn capacity_limit_still_accepts_retries_without_losing_pending_requests() {
        let mut transactions = Transactions::default();
        let first = request(0, "one.example.");
        for id in 0..crate::MAX_OUTSTANDING_DNS_QUERIES as u16 {
            transactions.prepare(&request(id, "one.example.")).unwrap();
        }
        assert!(transactions.prepare(&first).unwrap().is_none());
        assert!(transactions.prepare(&request(4000, "one.example.")).is_err());
        assert_eq!(transactions.pending.len(), crate::MAX_OUTSTANDING_DNS_QUERIES);
    }
}
