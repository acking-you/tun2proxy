use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        Name, RData, Record,
        rdata::{A, AAAA},
    },
};
use std::net::IpAddr;

const DNS_TCP_PREFIX_SIZE: usize = 2;
pub const MAX_CNAME_DEPTH: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressLookup {
    Address(IpAddr),
    Cname(String),
}

pub fn build_dns_response(mut request: Message, ip: Option<IpAddr>, ttl: u32) -> Result<Message, String> {
    let query = validate_dns_query(&request)?;
    let query_type = query.query_type();
    let query_class = query.query_class();
    let name = query.name().clone();
    let record = match (query_type, ip) {
        (hickory_proto::rr::RecordType::A, Some(IpAddr::V4(ip))) => Some(Record::from_rdata(name.clone(), ttl, RData::A(A(ip)))),
        (hickory_proto::rr::RecordType::AAAA, Some(IpAddr::V6(ip))) => Some(Record::from_rdata(name, ttl, RData::AAAA(AAAA(ip)))),
        _ => None,
    }
    .map(|mut record| {
        record.set_dns_class(query_class);
        record
    });

    request = request.to_response();
    request
        .set_authoritative(false)
        .set_truncated(false)
        .set_recursion_available(true)
        .set_authentic_data(false)
        .set_response_code(ResponseCode::NoError);
    request.answers_mut().clear();
    request.name_servers_mut().clear();
    request.additionals_mut().clear();
    _ = request.take_signature();

    if let Some(record) = record {
        request.add_answer(record);
    }
    Ok(request)
}

pub fn remove_ipv6_entries(message: &mut Message) {
    message.answers_mut().retain(|answer| !matches!(answer.data(), RData::AAAA(_)));
    message.name_servers_mut().retain(|record| !matches!(record.data(), RData::AAAA(_)));
    message.additionals_mut().retain(|record| !matches!(record.data(), RData::AAAA(_)));
}

pub fn extract_ipaddr_from_dns_message(message: &Message) -> Result<IpAddr, String> {
    let query = message.queries().first().ok_or("DNS response has no question")?;
    match extract_address_or_cname(message, query)? {
        AddressLookup::Address(ip) => Ok(ip),
        AddressLookup::Cname(name) => Err(name),
    }
}

pub fn extract_domain_from_dns_message(message: &Message) -> Result<String, String> {
    let query = message.queries().first().ok_or("DnsRequest no query body")?;
    // Display intentionally renders IDNA labels as Unicode. Proxy protocols
    // and OS resolvers need the wire-safe ASCII/Punycode representation.
    Ok(query.name().to_ascii())
}

pub fn validate_dns_query(message: &Message) -> Result<&Query, String> {
    if message.message_type() != MessageType::Query {
        return Err("DNS request is not a query".to_string());
    }
    if message.op_code() != OpCode::Query {
        return Err(format!("unsupported DNS opcode {:?}", message.op_code()));
    }
    if message.queries().len() != 1 {
        return Err(format!(
            "DNS request must contain exactly one question, got {}",
            message.queries().len()
        ));
    }
    Ok(&message.queries()[0])
}

pub fn validate_dns_response(message: &Message, request_id: u16, expected_query: &Query) -> Result<(), String> {
    if message.message_type() != MessageType::Response {
        return Err("DNS reply has the query bit set".to_string());
    }
    if message.op_code() != OpCode::Query {
        return Err(format!("DNS reply has unexpected opcode {:?}", message.op_code()));
    }
    if message.id() != request_id {
        return Err("DNS response ID mismatch".to_string());
    }
    let Some(actual_query) = message.queries().first() else {
        return Err("DNS response has no question".to_string());
    };
    if message.queries().len() != 1
        || !names_equal(actual_query.name(), expected_query.name())
        || actual_query.query_type() != expected_query.query_type()
        || actual_query.query_class() != expected_query.query_class()
    {
        return Err("DNS response question does not match the request".to_string());
    }
    Ok(())
}

pub fn extract_address_or_cname(message: &Message, query: &Query) -> Result<AddressLookup, String> {
    if message.response_code() != ResponseCode::NoError {
        return Err(format!("{:?}", message.response_code()));
    }

    let mut current = query.name().clone();
    let mut followed_cname = false;
    let want_ipv6 = query.query_type() == hickory_proto::rr::RecordType::AAAA;
    for _ in 0..MAX_CNAME_DEPTH {
        let mut cname = None;
        for answer in message.answers().iter().filter(|answer| names_equal(answer.name(), &current)) {
            match answer.data() {
                RData::A(address) if !want_ipv6 => {
                    return Ok(AddressLookup::Address(IpAddr::V4((*address).into())));
                }
                RData::AAAA(address) if want_ipv6 => {
                    return Ok(AddressLookup::Address(IpAddr::V6((*address).into())));
                }
                RData::CNAME(name) => cname = Some(name.0.clone()),
                _ => {}
            }
        }

        match cname {
            Some(name) if names_equal(&name, &current) => {
                return Err(format!("DNS CNAME loop at {}", current.to_ascii()));
            }
            Some(name) => {
                current = name;
                followed_cname = true;
            }
            None if followed_cname => return Ok(AddressLookup::Cname(current.to_ascii())),
            None => {
                return Err(format!(
                    "DNS response contained no {:?} address for {}",
                    query.query_type(),
                    current.to_ascii()
                ));
            }
        }
    }

    Err(format!(
        "DNS CNAME chain for {} exceeded {MAX_CNAME_DEPTH} records",
        query.name().to_ascii()
    ))
}

pub fn parse_data_to_dns_message(data: &[u8], used_by_tcp: bool) -> Result<Message, String> {
    if used_by_tcp {
        if data.len() < DNS_TCP_PREFIX_SIZE {
            return Err("invalid dns data".into());
        }
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() != len + DNS_TCP_PREFIX_SIZE {
            return Err("DNS-over-TCP frame length mismatch".into());
        }
        return parse_data_to_dns_message(&data[DNS_TCP_PREFIX_SIZE..], false);
    }
    Message::from_vec(data).map_err(|e| e.to_string())
}

pub fn drain_tcp_messages(buffer: &mut Vec<u8>) -> Result<Vec<Message>, String> {
    let mut messages = Vec::new();
    let mut consumed = 0;

    loop {
        let remaining = &buffer[consumed..];
        if remaining.len() < DNS_TCP_PREFIX_SIZE {
            break;
        }
        let message_len = u16::from_be_bytes([remaining[0], remaining[1]]) as usize;
        if message_len == 0 {
            return Err("empty DNS-over-TCP frame".to_string());
        }
        let frame_len = DNS_TCP_PREFIX_SIZE + message_len;
        if remaining.len() < frame_len {
            break;
        }
        messages.push(parse_data_to_dns_message(&remaining[DNS_TCP_PREFIX_SIZE..frame_len], false)?);
        consumed += frame_len;
    }

    if consumed != 0 {
        buffer.drain(..consumed);
    }
    Ok(messages)
}

fn names_equal(left: &Name, right: &Name) -> bool {
    left.to_ascii().eq_ignore_ascii_case(&right.to_ascii())
}

#[cfg(test)]
mod tests {
    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{Name, RecordType, rdata::CNAME},
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

        let a_response = build_dns_response(query(RecordType::A), Some(ipv4), 5).unwrap();
        let aaaa_response = build_dns_response(query(RecordType::AAAA), Some(ipv4), 5).unwrap();
        let https_response = build_dns_response(query(RecordType::HTTPS), Some(ipv4), 5).unwrap();

        assert_eq!(a_response.answers().len(), 1);
        assert!(aaaa_response.answers().is_empty());
        assert!(https_response.answers().is_empty());
        assert!(a_response.recursion_available());
        assert!(!a_response.truncated());
        assert!(!a_response.authentic_data());
    }

    #[test]
    fn extracted_idna_name_remains_ascii_for_proxy_transport() {
        let ascii = "rr1---sn-npoe7ndl.xn--ngstr-lra8j.com";
        let mut message = Message::new(2, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(Name::from_ascii(ascii).unwrap(), RecordType::A));

        assert_eq!(message.queries()[0].name().to_string(), "rr1---sn-npoe7ndl.ångströ.com");
        assert_eq!(extract_domain_from_dns_message(&message).unwrap(), ascii);
    }

    #[test]
    fn dns_response_validation_rejects_wrong_question_and_query_packets() {
        let expected = Query::query(Name::from_ascii("example.com").unwrap(), RecordType::A);
        let query_packet = query(RecordType::A);
        assert!(validate_dns_response(&query_packet, 1, &expected).is_err());

        let wrong = query(RecordType::AAAA).to_response();
        assert!(validate_dns_response(&wrong, 1, &expected).is_err());
    }

    #[test]
    fn address_lookup_follows_in_message_cname_chain() {
        let query = Query::query(Name::from_ascii("alias.example").unwrap(), RecordType::A);
        let mut response = Message::new(3, MessageType::Response, OpCode::Query);
        response.add_query(query.clone());
        response.add_answer(Record::from_rdata(
            Name::from_ascii("alias.example").unwrap(),
            60,
            RData::CNAME(CNAME(Name::from_ascii("target.example").unwrap())),
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("target.example").unwrap(),
            60,
            RData::A(A("203.0.113.7".parse().unwrap())),
        ));

        assert_eq!(
            extract_address_or_cname(&response, &query).unwrap(),
            AddressLookup::Address("203.0.113.7".parse().unwrap())
        );
    }

    #[test]
    fn tcp_message_drain_preserves_partial_frames() {
        let first = query(RecordType::A).to_vec().unwrap();
        let second = query(RecordType::AAAA).to_vec().unwrap();
        let mut wire = Vec::new();
        wire.extend_from_slice(&(first.len() as u16).to_be_bytes());
        wire.extend_from_slice(&first);
        wire.extend_from_slice(&(second.len() as u16).to_be_bytes());
        wire.extend_from_slice(&second);
        let first_frame_len = DNS_TCP_PREFIX_SIZE + first.len();
        let split = first_frame_len + 1;
        let mut buffered = wire[..split].to_vec();

        let messages = drain_tcp_messages(&mut buffered).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(buffered, wire[first_frame_len..split]);

        buffered.extend_from_slice(&wire[split..]);
        let messages = drain_tcp_messages(&mut buffered).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].queries()[0].query_type(), RecordType::AAAA);
        assert!(buffered.is_empty());
    }
}
