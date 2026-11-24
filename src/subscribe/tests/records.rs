//! Raw events of every network kind: decoding, the stream kind each policy
//! kind is requested as, and the value each measure takes from them.

use std::net::IpAddr;

use review_protocol::types::{ConnField, Measure, RawEventKind as PolicyRawEventKind};

use super::{SECS_PER_MINUTE, new_policy};
use crate::subscribe::time_series::{SECOND_TO_NANO, WindowBuilder};
use crate::subscribe::{
    Bootp, Conn, DceRpc, Dhcp, Dns, Event, Ftp, Http, Icmp, Kerberos, Ldap, MalformedDns, Mqtt,
    Nfs, Ntlm, Radius, Rdp, RequestStreamRecord, Smb, Smtp, Ssh, Tls, stream_record,
};

/// The 20 network kinds a time-series generation policy can count.
const NETWORK_KINDS: [PolicyRawEventKind; 20] = [
    PolicyRawEventKind::Bootp,
    PolicyRawEventKind::Conn,
    PolicyRawEventKind::DceRpc,
    PolicyRawEventKind::Dhcp,
    PolicyRawEventKind::Dns,
    PolicyRawEventKind::Ftp,
    PolicyRawEventKind::Http,
    PolicyRawEventKind::Icmp,
    PolicyRawEventKind::Kerberos,
    PolicyRawEventKind::Ldap,
    PolicyRawEventKind::MalformedDns,
    PolicyRawEventKind::Mqtt,
    PolicyRawEventKind::Nfs,
    PolicyRawEventKind::Ntlm,
    PolicyRawEventKind::Radius,
    PolicyRawEventKind::Rdp,
    PolicyRawEventKind::Smb,
    PolicyRawEventKind::Smtp,
    PolicyRawEventKind::Ssh,
    PolicyRawEventKind::Tls,
];

const ORIG: &str = "10.1.2.3";
const RESP: &str = "172.16.5.6";

/// Builds a record of a network kind with the fields every such kind shares,
/// followed by the kind's own fields.
macro_rules! record {
    ($kind:ident, $orig:expr, $resp:expr, { $($field:ident: $value:expr),* $(,)? }) => {
        bincode::serialize(&$kind {
            orig_addr: $orig,
            orig_port: 40_000,
            resp_addr: $resp,
            resp_port: 443,
            proto: 6,
            start_time: 1,
            duration: 2,
            orig_pkts: 3,
            resp_pkts: 4,
            orig_l2_bytes: 5,
            resp_l2_bytes: 6,
            $($field: $value),*
        })
        .expect("a record serializes")
    };
}

/// Returns a bincode-encoded giganto-client record of `kind` between `orig`
/// and `resp`, or `None` for a kind that is not a network kind.
#[allow(clippy::too_many_lines)] // One literal per network kind.
pub(super) fn network_record(
    kind: PolicyRawEventKind,
    orig: IpAddr,
    resp: IpAddr,
) -> Option<Vec<u8>> {
    let any: IpAddr = "0.0.0.0".parse().expect("valid address");
    Some(match kind {
        PolicyRawEventKind::Conn => record!(Conn, orig, resp, {
            conn_state: "SF".into(),
            service: "-".into(),
            orig_bytes: 7,
            resp_bytes: 8,
        }),
        PolicyRawEventKind::Dns => record!(Dns, orig, resp, {
            query: "example.com".into(),
            answer: vec!["192.0.2.1".into()],
            trans_id: 1,
            rtt: 1,
            qclass: 1,
            qtype: 1,
            rcode: 0,
            aa_flag: false,
            tc_flag: false,
            rd_flag: true,
            ra_flag: true,
            ttl: vec![60],
        }),
        PolicyRawEventKind::MalformedDns => record!(MalformedDns, orig, resp, {
            trans_id: 1,
            flags: 0,
            question_count: 1,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
            query_count: 1,
            resp_count: 0,
            query_bytes: 10,
            resp_bytes: 0,
            query_body: vec![vec![1, 2]],
            resp_body: Vec::new(),
        }),
        PolicyRawEventKind::Http => record!(Http, orig, resp, {
            method: "GET".into(),
            host: "example.com".into(),
            uri: "/".into(),
            referer: String::new(),
            version: "1.1".into(),
            user_agent: "test".into(),
            request_len: 0,
            response_len: 10,
            status_code: 200,
            status_msg: "OK".into(),
            username: String::new(),
            password: String::new(),
            cookie: String::new(),
            content_encoding: String::new(),
            content_type: "text/html".into(),
            cache_control: String::new(),
            filenames: Vec::new(),
            mime_types: Vec::new(),
            body: Vec::new(),
            state: String::new(),
        }),
        PolicyRawEventKind::Rdp => record!(Rdp, orig, resp, { cookie: "c".into() }),
        PolicyRawEventKind::Smtp => record!(Smtp, orig, resp, {
            mailfrom: "a@example.com".into(),
            date: String::new(),
            from: "a@example.com".into(),
            to: "b@example.com".into(),
            subject: "s".into(),
            agent: String::new(),
            state: String::new(),
        }),
        PolicyRawEventKind::Ntlm => record!(Ntlm, orig, resp, {
            protocol: "ntlm".into(),
            username: "u".into(),
            hostname: "h".into(),
            domainname: "d".into(),
            success: "true".into(),
        }),
        PolicyRawEventKind::Kerberos => record!(Kerberos, orig, resp, {
            client_time: 1,
            server_time: 2,
            error_code: 0,
            client_realm: "R".into(),
            cname_type: 1,
            cname: vec!["c".into()],
            realm: "R".into(),
            sname_type: 2,
            sname: vec!["s".into()],
            msg_type: 0,
            preauth: 0,
            req_etypes: Vec::new(),
            enc_part_etype: None,
            ticket_etype: None,
        }),
        PolicyRawEventKind::Ssh => record!(Ssh, orig, resp, {
            client: "c".into(),
            server: "s".into(),
            cipher_alg: String::new(),
            mac_alg: String::new(),
            compression_alg: String::new(),
            kex_alg: String::new(),
            host_key_alg: String::new(),
            hassh_algorithms: String::new(),
            hassh: String::new(),
            hassh_server_algorithms: String::new(),
            hassh_server: String::new(),
            client_shka: String::new(),
            server_shka: String::new(),
        }),
        PolicyRawEventKind::DceRpc => record!(DceRpc, orig, resp, {
            context: Vec::new(),
            request: vec!["r".into()],
        }),
        PolicyRawEventKind::Ftp => record!(Ftp, orig, resp, {
            user: "u".into(),
            password: String::new(),
            commands: Vec::new(),
        }),
        PolicyRawEventKind::Mqtt => record!(Mqtt, orig, resp, {
            protocol: "mqtt".into(),
            version: 4,
            client_id: "c".into(),
            connack_reason: 0,
            subscribe: Vec::new(),
            suback_reason: Vec::new(),
        }),
        PolicyRawEventKind::Ldap => record!(Ldap, orig, resp, {
            message_id: 1,
            version: 3,
            opcode: Vec::new(),
            result: Vec::new(),
            diagnostic_message: Vec::new(),
            object: Vec::new(),
            argument: Vec::new(),
        }),
        PolicyRawEventKind::Tls => record!(Tls, orig, resp, {
            server_name: "example.com".into(),
            alpn_protocol: String::new(),
            ja3: String::new(),
            version: "1.3".into(),
            client_cipher_suites: Vec::new(),
            client_extensions: Vec::new(),
            cipher: 0,
            extensions: Vec::new(),
            ja3s: String::new(),
            serial: String::new(),
            subject_country: String::new(),
            subject_org_name: String::new(),
            subject_common_name: String::new(),
            validity_not_before: 0,
            validity_not_after: 0,
            subject_alt_name: String::new(),
            issuer_country: String::new(),
            issuer_org_name: String::new(),
            issuer_org_unit_name: String::new(),
            issuer_common_name: String::new(),
            last_alert: 0,
        }),
        PolicyRawEventKind::Smb => record!(Smb, orig, resp, {
            command: 0,
            path: String::new(),
            service: String::new(),
            file_name: "f".into(),
            file_size: 1,
            resource_type: 0,
            fid: 0,
            create_time: 0,
            access_time: 0,
            write_time: 0,
            change_time: 0,
        }),
        PolicyRawEventKind::Nfs => record!(Nfs, orig, resp, {
            read_files: vec!["r".into()],
            write_files: Vec::new(),
        }),
        PolicyRawEventKind::Bootp => record!(Bootp, orig, resp, {
            op: 1,
            htype: 1,
            hops: 0,
            xid: 1,
            ciaddr: any,
            yiaddr: any,
            siaddr: any,
            giaddr: any,
            chaddr: vec![0; 6],
            sname: String::new(),
            file: String::new(),
        }),
        PolicyRawEventKind::Dhcp => record!(Dhcp, orig, resp, {
            msg_type: 1,
            ciaddr: any,
            yiaddr: any,
            siaddr: any,
            giaddr: any,
            subnet_mask: any,
            router: Vec::new(),
            domain_name_server: Vec::new(),
            req_ip_addr: any,
            lease_time: 0,
            server_id: any,
            param_req_list: Vec::new(),
            message: String::new(),
            renewal_time: 0,
            rebinding_time: 0,
            class_id: Vec::new(),
            client_id_type: 0,
            client_id: Vec::new(),
            options: Vec::new(),
            xid: 0,
            chaddr: Vec::new(),
            src_mac: None,
        }),
        PolicyRawEventKind::Radius => record!(Radius, orig, resp, {
            id: 1,
            code: 1,
            resp_code: 2,
            auth: String::new(),
            resp_auth: String::new(),
            user_name: Vec::new(),
            user_passwd: Vec::new(),
            chap_passwd: Vec::new(),
            nas_ip: any,
            nas_port: 0,
            state: Vec::new(),
            nas_id: Vec::new(),
            nas_port_type: 0,
            message: String::new(),
        }),
        PolicyRawEventKind::Icmp => bincode::serialize(&Icmp {
            orig_addr: orig,
            resp_addr: resp,
            proto: 1,
            start_time: 1,
            duration: 2,
            orig_pkts: 3,
            resp_pkts: 4,
            orig_l2_bytes: 5,
            resp_l2_bytes: 6,
            icmp_type: 8,
            icmp_code: 0,
            id: 1,
            seq_num: 1,
            data_len: 0,
            payload: Vec::new(),
        })
        .expect("a record serializes"),
        _ => return None,
    })
}

fn conn_record(
    duration: i64,
    orig_bytes: u64,
    resp_bytes: u64,
    orig_pkts: u64,
    resp_pkts: u64,
) -> Vec<u8> {
    bincode::serialize(&Conn {
        orig_addr: ORIG.parse().unwrap(),
        orig_port: 40_000,
        resp_addr: RESP.parse().unwrap(),
        resp_port: 443,
        proto: 6,
        conn_state: "SF".into(),
        start_time: 0,
        duration,
        service: "-".into(),
        orig_bytes,
        resp_bytes,
        orig_pkts,
        resp_pkts,
        orig_l2_bytes: 0,
        resp_l2_bytes: 0,
    })
    .unwrap()
}

/// Every policy kind, found by trying each number review-protocol could use.
fn all_policy_kinds() -> Vec<PolicyRawEventKind> {
    (0..=u32::from(u8::MAX))
        .filter_map(|n| PolicyRawEventKind::try_from(n).ok())
        .collect()
}

#[test]
fn record_of_each_network_kind_decodes_with_its_addresses() {
    let orig: IpAddr = ORIG.parse().unwrap();
    let resp: IpAddr = RESP.parse().unwrap();
    for kind in NETWORK_KINDS {
        let bytes = network_record(kind, orig, resp).expect("a network kind has a record");
        let event = Event::try_new(stream_record(kind).unwrap(), &bytes)
            .unwrap_or_else(|e| panic!("{kind:?} decodes: {e:#}"));
        assert_eq!(event.orig_addr(), orig, "{kind:?}");
        assert_eq!(event.resp_addr(), resp, "{kind:?}");
    }
}

#[test]
fn each_network_kind_maps_to_the_stream_kind_of_the_same_name() {
    let mut network = Vec::new();
    for kind in all_policy_kinds() {
        match stream_record(kind) {
            Ok(record) => {
                assert_eq!(format!("{record:?}"), format!("{kind:?}"));
                network.push(kind);
            }
            Err(e) => {
                assert!(
                    network_record(kind, ORIG.parse().unwrap(), RESP.parse().unwrap()).is_none()
                );
                assert_eq!(
                    e.to_string(),
                    format!("{kind:?} is not a network raw event kind")
                );
            }
        }
    }
    let mut expected = NETWORK_KINDS.to_vec();
    expected.sort_unstable_by_key(|kind| u32::from(*kind));
    assert_eq!(network, expected);
}

#[test]
fn non_network_kinds_are_not_converted() {
    for kind in [
        PolicyRawEventKind::ProcessCreate,
        PolicyRawEventKind::Netflow5,
        PolicyRawEventKind::Netflow9,
        PolicyRawEventKind::FileDelete,
    ] {
        assert!(stream_record(kind).is_err(), "{kind:?}");
    }
}

#[test]
fn non_network_stream_kinds_are_not_decoded() {
    let bytes = network_record(
        PolicyRawEventKind::Conn,
        ORIG.parse().unwrap(),
        RESP.parse().unwrap(),
    )
    .unwrap();
    for record in [
        RequestStreamRecord::Log,
        RequestStreamRecord::Pcap,
        RequestStreamRecord::FileCreate,
        RequestStreamRecord::FileDelete,
    ] {
        assert!(Event::try_new(record, &bytes).is_err(), "{record:?}");
    }
}

/// Feeds `events` (raw records within one 1-hour window) and an event of the
/// next window to a builder for `policy`, and returns the closed window.
fn closed_window(
    policy: &review_protocol::types::TimeSeriesGenerationPolicy,
    events: &[Vec<u8>],
) -> Vec<f64> {
    const WINDOW_START: i64 = 1_700_000_000 / 3600 * 3600;
    let record = stream_record(policy.raw_event_kind).unwrap();
    let mut builder = WindowBuilder::try_new(policy, 0).unwrap();
    let at = |secs: i64| (WINDOW_START + secs) * SECOND_TO_NANO;
    for (i, bytes) in events.iter().enumerate() {
        let event = Event::try_new(record, bytes).unwrap();
        let offset = i64::try_from(i).unwrap() * 60;
        assert!(builder.add(at(offset), &event).unwrap().is_none());
    }
    let next = Event::try_new(record, events.last().unwrap()).unwrap();
    builder
        .add(at(3600), &next)
        .unwrap()
        .expect("an event of the next window closes the window")
        .series
}

fn hourly_policy(
    kind: PolicyRawEventKind,
    measure: Measure,
) -> review_protocol::types::TimeSeriesGenerationPolicy {
    let mut policy = new_policy(1);
    policy.raw_event_kind = kind;
    policy.measure = measure;
    policy.slot_size = std::time::Duration::from_secs(15 * SECS_PER_MINUTE);
    policy.window_size = std::time::Duration::from_secs(4 * 15 * SECS_PER_MINUTE);
    policy
}

#[test]
fn count_adds_one_per_raw_event_of_every_network_kind() {
    for kind in NETWORK_KINDS {
        let record = network_record(kind, ORIG.parse().unwrap(), RESP.parse().unwrap()).unwrap();
        let events = vec![record; 3];
        let series = closed_window(&hourly_policy(kind, Measure::Count), &events);
        assert_eq!(series, [3.0, 0.0, 0.0, 0.0], "{kind:?}");
    }
}

#[test]
fn sum_adds_the_matching_conn_field() {
    let events = [
        conn_record(1_000, 10, 100, 1_000_000, 10_000_000),
        conn_record(2_000, 20, 200, 2_000_000, 20_000_000),
    ];
    for (field, expected) in [
        (ConnField::Duration, 3_000.0),
        (ConnField::OrigBytes, 30.0),
        (ConnField::RespBytes, 300.0),
        (ConnField::OrigPkts, 3_000_000.0),
        (ConnField::RespPkts, 30_000_000.0),
    ] {
        let policy = hourly_policy(PolicyRawEventKind::Conn, Measure::Sum(field));
        let series = closed_window(&policy, &events);
        assert_eq!(series, [expected, 0.0, 0.0, 0.0], "{field:?}");
    }
}
