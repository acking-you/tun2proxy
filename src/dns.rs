use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{
        Name, RData, Record,
        rdata::{A, AAAA},
    },
};
use std::{net::IpAddr, str::FromStr};

pub fn build_dns_response(mut request: Message, domain: &str, ip: IpAddr, ttl: u32) -> Result<Message, String> {
    let name = Name::from_str(domain).map_err(|e| e.to_string())?;
    let query_type = request.queries().first().ok_or("DnsRequest no query body")?.query_type();
    let record = match (query_type, ip) {
        (hickory_proto::rr::RecordType::A, IpAddr::V4(ip)) => Some(Record::from_rdata(name.clone(), ttl, RData::A(A(ip)))),
        (hickory_proto::rr::RecordType::AAAA, IpAddr::V6(ip)) => Some(Record::from_rdata(name, ttl, RData::AAAA(AAAA(ip)))),
        _ => None,
    };

    // We must indicate that this message is a response. Otherwise, implementations may not
    // recognize it.
    request = request.to_response();

    if let Some(record) = record {
        request.add_answer(record);
    }
    Ok(request)
}

pub fn remove_ipv6_entries(message: &mut Message) {
    message.answers_mut().retain(|answer| !matches!(answer.data(), RData::AAAA(_)));
}

pub fn extract_ipaddr_from_dns_message(message: &Message) -> Result<IpAddr, String> {
    if message.response_code() != ResponseCode::NoError {
        return Err(format!("{:?}", message.response_code()));
    }
    let mut cname = None;
    for answer in message.answers() {
        match answer.data() {
            RData::A(addr) => {
                return Ok(IpAddr::V4((*addr).into()));
            }
            RData::AAAA(addr) => {
                return Ok(IpAddr::V6((*addr).into()));
            }
            RData::CNAME(name) => {
                cname = Some(name.to_utf8());
            }
            _ => {}
        }
    }
    if let Some(cname) = cname {
        return Err(cname);
    }
    Err(format!("{:?}", message.answers()))
}

pub fn extract_domain_from_dns_message(message: &Message) -> Result<String, String> {
    let query = message.queries().first().ok_or("DnsRequest no query body")?;
    let name = query.name().to_string();
    Ok(name)
}

pub fn parse_data_to_dns_message(data: &[u8], used_by_tcp: bool) -> Result<Message, String> {
    if used_by_tcp {
        if data.len() < 2 {
            return Err("invalid dns data".into());
        }
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let data = data.get(2..len + 2).ok_or("invalid dns data")?;
        return parse_data_to_dns_message(data, false);
    }
    let message = Message::from_vec(data).map_err(|e| e.to_string())?;
    Ok(message)
}

#[cfg(test)]
mod tests {
    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{Name, RecordType},
    };

    use super::*;

    fn query(record_type: RecordType) -> Message {
        let mut message = Message::new(1, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(Name::from_ascii("example.com").unwrap(), record_type));
        message
    }

    #[test]
    fn virtual_dns_only_answers_the_requested_address_family() {
        let ipv4 = "198.18.0.10".parse().unwrap();

        let a_response = build_dns_response(query(RecordType::A), "example.com", ipv4, 5).unwrap();
        let aaaa_response = build_dns_response(query(RecordType::AAAA), "example.com", ipv4, 5).unwrap();
        let https_response = build_dns_response(query(RecordType::HTTPS), "example.com", ipv4, 5).unwrap();

        assert_eq!(a_response.answers().len(), 1);
        assert!(aaaa_response.answers().is_empty());
        assert!(https_response.answers().is_empty());
    }
}
