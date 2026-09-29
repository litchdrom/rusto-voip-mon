//! SIP message extraction from on-disk pcap archives.
//!
//! When the `sip_msg` database table is missing, unpopulated, or
//! schema-mismatched (as on one of our test installs), the CDR
//! detail page can still surface the call's SIP conversation by
//! parsing the merged SIP+RTP pcap directly. VoIPmonitor always
//! writes the SIP wire format into the `SIP_*.tar.zst` archive, so
//! the pcap is the canonical source.
//!
//! Format we read:
//!     [24-byte pcap global header]
//!     [16-byte record header][Ethernet/IPv4/IPv6/UDP/TCP][payload]
//!     [16-byte record header]…
//!
//! For each record we hand off the layer-2/3/4 header to
//! `etherparse`, then look at the SIP-shaped UDP payload. Only
//! unencrypted SIP — port 5060 / 5061 — is parseable (TLS would
//! require the key material). Port 5061 SIP/TLS packets are passed
//! through as-is so the analyst can at least see something landed.
//!
//! Returns a `Vec<SipMessage>` shaped exactly like the sip_msg DB
//! query result, so the existing `render_sip_timeline` can consume
//! either source unchanged.

use etherparse::SlicedPacket;
use std::net::IpAddr;
use std::str;

use super::SipMessage;

/// Parse a SIP conversation out of a pcap byte buffer (merged
/// SIP+RTP, single global header). Each UDP packet whose
/// destination or source port is 5060/5061 is decoded as a SIP
/// message; everything else is ignored (RTP, RTCP, ARP, …).
///
/// Returns up to `limit` messages, oldest first. The limit matches
/// the DB query's cap so the rendered timeline is consistent
/// regardless of which source supplied the data.
///
/// On malformed input (truncated pcap, bad headers, invalid UTF-8
/// in the SIP body) the parser skips the offending record and keeps
/// going — a single bad packet shouldn't blank the whole timeline.
pub fn parse_sip_messages_from_pcap(pcap_bytes: &[u8], limit: usize) -> Vec<SipMessage> {
    const PCAP_MAGIC_LE: u32 = 0xa1b2_c3d4;
    const PCAP_MAGIC_BE: u32 = 0xd4c3_b2a1;
    const LINKTYPE_ETHERNET: u32 = 1;
    const SIP_PORTS: &[u16] = &[5060, 5061];

    if pcap_bytes.len() < 24 {
        return Vec::new();
    }
    let magic = u32::from_ne_bytes(pcap_bytes[0..4].try_into().unwrap());
    let little_endian = match magic {
        PCAP_MAGIC_LE => true,
        PCAP_MAGIC_BE => false,
        _ => return Vec::new(),
    };

    let read_u32 = |b: &[u8]| -> u32 {
        if little_endian {
            u32::from_le_bytes(b.try_into().unwrap())
        } else {
            u32::from_be_bytes(b.try_into().unwrap())
        }
    };

    // Linktype lives in the pcap global header at offset 20.
    let linktype = read_u32(&pcap_bytes[20..24]);
    if linktype != LINKTYPE_ETHERNET {
        // We only handle Ethernet-framed pcaps (the only flavour
        // VoIPmonitor emits). Linux cooked / raw-IP / etc. — bail.
        return Vec::new();
    }

    let mut out: Vec<SipMessage> = Vec::new();
    let mut cursor: usize = 24; // skip global header

    while cursor + 16 <= pcap_bytes.len() && out.len() < limit {
        // Per-record header: ts_sec(4) + ts_usec(4) + incl_len(4) + orig_len(4)
        let _ts_sec = read_u32(&pcap_bytes[cursor..cursor + 4]);
        let ts_usec = read_u32(&pcap_bytes[cursor + 4..cursor + 8]);
        let incl_len = read_u32(&pcap_bytes[cursor + 8..cursor + 12]) as usize;
        let _orig_len = read_u32(&pcap_bytes[cursor + 12..cursor + 16]);
        cursor += 16;

        if cursor + incl_len > pcap_bytes.len() {
            break; // truncated record — give up rather than panic
        }
        let packet = &pcap_bytes[cursor..cursor + incl_len];
        cursor += incl_len;

        let parsed = match SlicedPacket::from_ethernet(packet) {
            Ok(p) => p,
            Err(_) => continue, // skip unparseable records
        };
        let net = match parsed.net {
            Some(n) => n,
            None => continue,
        };
        let transport = match parsed.transport {
            Some(t) => t,
            None => continue,
        };
        // We only decode UDP. TCP SIP messages (rare but valid —
        // TCP/TLS-over-TCP) are skipped; the analyst sees the gap
        // and can pull the pcap for the full content.
        let (src_port, dst_port, payload) = match transport {
            etherparse::TransportSlice::Udp(u) => {
                (u.source_port(), u.destination_port(), u.payload())
            }
            _ => continue,
        };
        if !SIP_PORTS.contains(&src_port) && !SIP_PORTS.contains(&dst_port) {
            continue;
        }

        let src_ip = match &net {
            etherparse::NetSlice::Ipv4(ip) => IpAddr::V4(ip.header().source_addr()),
            etherparse::NetSlice::Ipv6(ip) => IpAddr::V6(ip.header().source_addr()),
            _ => continue, // ARP / non-IP — skip
        };
        let dst_ip = match &net {
            etherparse::NetSlice::Ipv4(ip) => IpAddr::V4(ip.header().destination_addr()),
            etherparse::NetSlice::Ipv6(ip) => IpAddr::V6(ip.header().destination_addr()),
            _ => continue, // ARP / non-IP — skip
        };

        // SIP is ASCII text — invalid UTF-8 in the SIP body is
        // common (SDP can carry arbitrary byte payloads). Decode
        // lossily so the rest of the message stays readable.
        let body = String::from_utf8_lossy(payload).into_owned();
        if body.is_empty() {
            continue;
        }
        // Reconstruct timestamp from the pcap record header.
        let calldate = ts_usec_to_datetime(_ts_sec, ts_usec);
        let method = parse_sip_method(&body);
        let (response_num, response_text) = parse_sip_response(&body, 0);
        // Direction is decided later by the caller (we don't know
        // the CDR's sipcallerip from inside this module).
        // CSeq is needed for transaction pairing in the sngrep call-flow
        // visualisation — INVITE ↔ 200, BYE ↔ 200, etc. Parse it once
        // here and carry it on the SipMessage so the renderer doesn't
        // have to re-walk the body.
        let (cseq_num, cseq_method) = crate::cdr::parse_cseq(&body)
            .map(|(n, m)| (Some(n), Some(m)))
            .unwrap_or((None, None));
        out.push(SipMessage {
            id: 0,
            calldate,
            method,
            response_num,
            response_text,
            from_num: extract_sip_header(&body, "From"),
            to_num: extract_sip_header(&body, "To"),
            src_ip_str: src_ip.to_string(),
            dst_ip_str: dst_ip.to_string(),
            direction: String::new(), // filled in by caller
            content_type: extract_sip_header(&body, "Content-Type"),
            content: body,
            cseq_num,
            cseq_method,
        });
    }
    out
}

/// Convert pcap record header `(ts_sec, ts_usec)` to a
/// `NaiveDateTime`. The pcap epoch is 1970-01-01 UTC; chrono takes
/// a count of seconds + nanos, so we add the microsecond component.
fn ts_usec_to_datetime(ts_sec: u32, ts_usec: u32) -> chrono::NaiveDateTime {
    use chrono::TimeZone;
    use chrono::Utc;
    let total_nanos = (ts_sec as i64) * 1_000_000_000 + (ts_usec as i64) * 1_000;
    Utc.timestamp_opt(total_nanos / 1_000_000_000, (total_nanos % 1_000_000_000) as u32)
        .single()
        .map(|dt| dt.naive_utc())
        .unwrap_or_else(|| {
            Utc.timestamp_opt(0, 0).single().unwrap().naive_utc()
        })
}

/// Pull the value of a single header line out of a SIP message.
/// Case-insensitive header name match (SIP headers are
/// case-insensitive). Returns the bare value with whitespace and
/// the `name:` prefix stripped. Returns "" if not found.
fn extract_sip_header(body: &str, header_name: &str) -> String {
    let lc_name = header_name.to_ascii_lowercase();
    // `str::lines()` handles both \n and \r\n correctly without
    // emitting empty entries between CRLF pairs (which split-on-\r|\n
    // does, breaking the take_while-loop approach).
    for line in body.lines() {
        let lc = line.to_ascii_lowercase();
        if let Some(rest) = lc.strip_prefix(&format!("{lc_name}:")) {
            // The original (mixed-case) line preserves any params on
            // the From/To headers; strip the same prefix length off it.
            let prefix_len = lc.len() - rest.len();
            return line[prefix_len..].trim().to_string();
        }
    }
    // Multi-line header continuations (RFC 3261 §7.3.1 leading
    // whitespace) are out of scope for this minimal pass.
    String::new()
}

/// Reuse the existing body-parsing helpers from the DB-query
/// module. They're `pub(super)` so we can call them here without
/// re-exporting them globally.
use super::{parse_sip_method, parse_sip_response};

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal Ethernet/IPv4/UDP packet wrapping a given
    /// payload. Hand-rolled — the etherparse `PacketBuilder` API
    /// takes some setup we'd rather not depend on just for tests.
    /// Layout:
    ///   [14B Ethernet][20B IPv4][8B UDP][payload]
    /// Header checksums are zeroed (the parser doesn't validate
    /// them) — real packets will have correct checksums and parse
    /// identically.
    fn build_pcap_record(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let udp_len = (8 + payload.len()) as u16;
        let ip_total_len = (20 + udp_len) as u16;
        let incl_len = (14 + ip_total_len as usize) as u32;

        let mut pkt = Vec::with_capacity(incl_len as usize);
        // Ethernet header (14 bytes): dst(6) + src(6) + ethertype(2)
        pkt.extend_from_slice(&[0u8; 6]);           // dst MAC
        pkt.extend_from_slice(&[0u8; 6]);           // src MAC
        pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
        // IPv4 header (20 bytes, no options)
        pkt.push(0x45);                              // version=4, IHL=5
        pkt.push(0x00);                              // DSCP/ECN
        pkt.extend_from_slice(&ip_total_len.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());  // identification
        pkt.extend_from_slice(&0u16.to_be_bytes());  // flags + frag offset
        pkt.push(64);                                // TTL
        pkt.push(17);                                // protocol = UDP
        pkt.extend_from_slice(&0u16.to_be_bytes());  // header checksum
        pkt.extend_from_slice(&src_ip);
        pkt.extend_from_slice(&dst_ip);
        // UDP header (8 bytes)
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&udp_len.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());  // checksum
        // Payload
        pkt.extend_from_slice(payload);

        // pcap record header: ts_sec(4) + ts_usec(4) + incl_len(4) + orig_len(4)
        let mut record = Vec::with_capacity(16 + pkt.len());
        record.extend_from_slice(&0u32.to_le_bytes());          // ts_sec
        record.extend_from_slice(&123456u32.to_le_bytes());     // ts_usec
        record.extend_from_slice(&incl_len.to_le_bytes());
        record.extend_from_slice(&incl_len.to_le_bytes());
        record.extend_from_slice(&pkt);
        record
    }

    /// Build a complete pcap file with one global header followed
    /// by the given record bytes.
    fn build_pcap(records: &[Vec<u8>]) -> Vec<u8> {
        let mut pcap = Vec::new();
        // pcap global header: magic + version + tz + sigfigs + snaplen + linktype
        pcap.extend_from_slice(&0xa1b2c3d4_u32.to_le_bytes()); // magic (little-endian)
        pcap.extend_from_slice(&2u16.to_le_bytes());           // version major
        pcap.extend_from_slice(&4u16.to_le_bytes());           // version minor
        pcap.extend_from_slice(&0i32.to_le_bytes());           // tz
        pcap.extend_from_slice(&0u32.to_le_bytes());           // sigfigs
        pcap.extend_from_slice(&65535u32.to_le_bytes());       // snaplen
        pcap.extend_from_slice(&1u32.to_le_bytes());           // linktype = Ethernet
        for r in records {
            pcap.extend_from_slice(r);
        }
        pcap
    }

    #[test]
    fn parses_invite_then_200_ok() {
        let invite = b"INVITE sip:alice@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1\r\nFrom: <sip:alice@example.com>\r\nTo: <sip:bob@example.com>\r\nContent-Length: 0\r\n\r\n";
        let response = b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 10.0.0.2\r\nFrom: <sip:bob@example.com>\r\nTo: <sip:alice@example.com>\r\nContent-Length: 0\r\n\r\n";
        let pcap = build_pcap(&[
            build_pcap_record([10, 0, 0, 1], [10, 0, 0, 2], 5060, 5060, invite),
            build_pcap_record([10, 0, 0, 2], [10, 0, 0, 1], 5060, 5060, response),
        ]);
        let msgs = parse_sip_messages_from_pcap(&pcap, 100);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].method, "INVITE");
        assert_eq!(msgs[1].response_num, 200);
        assert_eq!(msgs[1].response_text, "OK");
        // Direction + IP columns populated.
        assert_eq!(msgs[0].src_ip_str, "10.0.0.1");
        assert_eq!(msgs[0].dst_ip_str, "10.0.0.2");
    }

    #[test]
    fn skips_non_sip_ports() {
        let rtp = b"\x80\x08\x00\x00payload"; // fake RTP-shaped
        let pcap = build_pcap(&[
            build_pcap_record([10, 0, 0, 1], [10, 0, 0, 2], 16384, 16384, rtp),
        ]);
        let msgs = parse_sip_messages_from_pcap(&pcap, 100);
        assert!(msgs.is_empty(), "RTP packets must be skipped, got {:?}", msgs);
    }

    #[test]
    fn extracts_from_and_to_headers() {
        let invite = b"INVITE sip:bob@example.com SIP/2.0\r\nFrom: <sip:alice@example.com>;tag=abc\r\nTo: <sip:bob@example.com>\r\n\r\n";
        let pcap = build_pcap(&[
            build_pcap_record([10, 0, 0, 1], [10, 0, 0, 2], 5060, 5060, invite),
        ]);
        let msgs = parse_sip_messages_from_pcap(&pcap, 100);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].from_num, "<sip:alice@example.com>;tag=abc");
        assert_eq!(msgs[0].to_num, "<sip:bob@example.com>");
    }

    #[test]
    fn empty_pcap_returns_empty_vec() {
        assert!(parse_sip_messages_from_pcap(&[], 100).is_empty());
        // Just the 24-byte global header, no records.
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&0xa1b2c3d4_u32.to_le_bytes());
        hdr.extend_from_slice(&[0u8; 20]);
        hdr[20..24].copy_from_slice(&1u32.to_le_bytes()); // linktype = Ethernet
        assert!(parse_sip_messages_from_pcap(&hdr, 100).is_empty());
    }

    #[test]
    fn truncates_at_limit() {
        // Five INVITEs, limit=3 — only the first three survive.
        let invite = b"INVITE sip:a@example.com SIP/2.0\r\n\r\n";
        let records: Vec<Vec<u8>> = (0..5)
            .map(|i| {
                build_pcap_record(
                    [10, 0, 0, 1 + i],
                    [10, 0, 0, 2],
                    5060,
                    5060,
                    invite,
                )
            })
            .collect();
        let pcap = build_pcap(&records);
        let msgs = parse_sip_messages_from_pcap(&pcap, 3);
        assert_eq!(msgs.len(), 3);
    }
}
