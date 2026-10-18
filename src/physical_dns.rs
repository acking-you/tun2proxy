//! DNS portal shared by TCP and UDP, independent of socket-owner attribution.

use crate::direct::{self, BindInterface};
use std::{io, net::IpAddr, sync::Arc};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

static QUERIES: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(crate::MAX_OUTSTANDING_DNS_QUERIES);

pub(crate) async fn answer(request: &[u8], configured_dns: IpAddr, iface: &BindInterface, ipv6: bool, udp: bool) -> io::Result<Vec<u8>> {
    let mut query = crate::dns::parse_data_to_dns_message(request, false).map_err(io::Error::other)?;
    crate::dns::validate_dns_query(&query).map_err(io::Error::other)?;
    let max_size = udp.then_some(usize::from(query.max_payload()));
    let result = match QUERIES.try_acquire() {
        Ok(_permit) => direct::query_bound(request, configured_dns, iface).await,
        Err(_) => Err(io::Error::new(io::ErrorKind::WouldBlock, "physical DNS query capacity exhausted")),
    };
    let mut response = match result {
        Ok(bytes) => crate::dns::parse_data_to_dns_message(&bytes, false).map_err(io::Error::other)?,
        Err(error) => {
            log::warn!("Physical DNS query {} via {iface} failed: {error}", query.queries[0].name());
            query.metadata.message_type = hickory_proto::op::MessageType::Response;
            query.metadata.response_code = hickory_proto::op::ResponseCode::ServFail;
            query.answers.clear();
            query
        }
    };
    if !ipv6 {
        crate::dns::remove_ipv6_entries(&mut response);
    }
    encode_response(&response, max_size)
}

fn encode_response(response: &hickory_proto::op::Message, max_size: Option<usize>) -> io::Result<Vec<u8>> {
    let bytes = response.to_vec().map_err(io::Error::other)?;
    if max_size.is_some_and(|limit| bytes.len() > limit) {
        // The upstream TCP fallback can be larger than the client's UDP limit.
        // Let that client retry over TCP instead of emitting oversized DNS UDP.
        response.truncate().to_vec().map_err(io::Error::other)
    } else {
        Ok(bytes)
    }
}

pub(crate) async fn tcp<S>(stream: &mut S, configured_dns: IpAddr, iface: &BindInterface, ipv6: bool) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        // Read one prefix byte separately to distinguish EOF from a torn frame.
        let mut prefix = [0; 2];
        if stream.read(&mut prefix[..1]).await? == 0 {
            return Ok(());
        }
        stream.read_exact(&mut prefix[1..]).await?;
        let mut request = vec![0; u16::from_be_bytes(prefix) as usize];
        stream.read_exact(&mut request).await?;
        let response = answer(&request, configured_dns, iface, ipv6, false).await?;
        stream.write_u16(u16::try_from(response.len()).map_err(io::Error::other)?).await?;
        stream.write_all(&response).await?;
    }
}

pub(crate) async fn udp(
    mut stream: ipstack::IpStackUdpStream,
    configured_dns: IpAddr,
    iface: Arc<BindInterface>,
    ipv6: bool,
) -> io::Result<()> {
    let mut queries = tokio::task::JoinSet::new();
    let mut buffer = vec![0; u16::MAX as usize];
    loop {
        tokio::select! {
            received = stream.recv(&mut buffer), if queries.len() < 16 => {
                let Some(size) = received? else { return Ok(()); };
                let request = buffer[..size].to_vec();
                let iface = Arc::clone(&iface);
                queries.spawn(async move { answer(&request, configured_dns, &iface, ipv6, true).await });
            }
            completed = queries.join_next(), if !queries.is_empty() => {
                match completed {
                    Some(Ok(Ok(response))) => stream.send(&response)?,
                    Some(Ok(Err(error))) => log::warn!("Rejected physical DNS datagram: {error}"),
                    Some(Err(error)) => return Err(io::Error::other(error)),
                    None => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{Name, RData, Record, RecordType, rdata::A},
    };

    #[test]
    fn udp_limit_sets_truncation_without_truncating_tcp_answers() {
        let name = Name::from_ascii("game.example.test.").unwrap();
        let mut response = Message::new(42, MessageType::Response, OpCode::Query);
        response.add_query(Query::query(name.clone(), RecordType::A));
        for i in 1..80 {
            response.add_answer(Record::from_rdata(name.clone(), 30, RData::A(A::new(192, 0, 2, i))));
        }
        let tcp = encode_response(&response, None).unwrap();
        assert!(tcp.len() > 512);
        let udp = encode_response(&response, Some(512)).unwrap();
        assert!(udp.len() <= 512);
        let udp = Message::from_vec(&udp).unwrap();
        assert!(udp.truncation);
        assert_eq!(udp.id, 42);
        assert_eq!(udp.queries, response.queries);
        assert_eq!(Message::from_vec(&tcp).unwrap().answers.len(), 79);
    }
}
