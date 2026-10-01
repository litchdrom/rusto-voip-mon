//! RTP packet extraction + jitter / MOS computation from the
//! on-disk pcap archive.
//!
//! Used by the CDR detail page to drive the MOS / jitter timeline
//! chart that sits below the call-flow diagram. The merged pcap
//! the caller already decompressed for SIP parsing contains the
//! full-duplex RTP stream as UDP packets on the negotiated media
//! ports — same `etherparse`-based pcap walker as
//! `sip_pcap.rs`, but we look for *every* UDP packet whose
//! payload looks like RTP (version field == 2, CSRC/extension
//! header length accounted for) instead of restricting to SIP
//! ports.
//!
//! Two metrics are computed per second of media:
//!
//! * **Jitter** — RFC 3550 §6.4.1 smoothed interarrival jitter,
//!   `J(i) = J(i-1) + (|D(i-1,i)| - J(i-1)) / 16`, where
//!   `D(i,j) = |(Rj - Ri) - (Sj - Si)|`.
//! * **MOS** — Simplified E-model. `R = 93.2 - 2.5*loss_pct -
//!   jitter_ms/10`. Clamped to [1, 5]. This isn't a full
//!   ITU-T G.107 implementation (no latency, no codec-specific
//!   equipment impairment factor) but it tracks the same
//!   intuition: loss and jitter degrade the listening
//!   experience, and the relationship is roughly linear at the
//!   scales that matter for an operator eyeballing a chart.
//!
//! Output is bucketed by 1-second windows by default. For a
//! typical 60-second call that's 60 buckets × 2 directions
//! ≈ 240 floats — comfortably within JS chart data size limits.

use etherparse::SlicedPacket;
use std::net::IpAddr;

/// One RTP packet as decoded from the wire. Holds just enough
/// state to compute jitter / loss / MOS — no payload decode.
#[derive(Debug, Clone)]
pub struct RtpPacket {
    /// Wall-clock arrival time in seconds since the pcap's
    /// own epoch (1970-01-01 UTC). Subtracting the first
    /// packet's value per direction gives the bucket
    /// offsets we render on the chart.
    pub arrival_secs: f64,
    /// RTP timestamp from the packet header (32-bit, in the
    /// sender's clock units). Used for RFC 3550 jitter.
    pub rtp_ts: u32,
    /// RTP sequence number — captured for future loss
    /// analysis but not currently used by the jitter path.
    pub seq: u16,
    /// SSRC so we can split multiplexed streams.
    pub ssrc: u32,
    /// Source IP — used to figure out which leg the packet
    /// belongs to (caller→callee vs callee→caller).
    pub src_ip: IpAddr,
}

/// One second of aggregate statistics for one direction.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RtpStatsBucket {
    /// Seconds since the first packet of this direction.
    pub time_offset_secs: f64,
    /// RFC 3550 smoothed jitter, in milliseconds, averaged
    /// across packets in this bucket.
    pub jitter_ms: f64,
    /// Loss percentage for packets *expected* in this bucket
    /// (based on the previous bucket's packet rate) but
    /// missing. 0.0..=100.0.
    pub loss_pct: f64,
    /// MOS LQO estimate (1.0..=5.0). Simplified E-model.
    pub mos: f32,
    /// Number of packets received in this bucket.
    pub packet_count: u32,
}

/// Per-direction RTP stats for one call. Both vectors share the
/// same length — the i-th element of each is the same time
/// offset on the A→B and B→A legs.
#[derive(Debug, Clone)]
pub struct RtpStatsByDirection {
    pub a_to_b: Vec<RtpStatsBucket>,
    pub b_to_a: Vec<RtpStatsBucket>,
}

/// Walk a pcap byte buffer (Ethernet-framed, same format the
/// SIP parser reads) and pull out every RTP-shaped UDP packet.
/// Non-UDP / non-RTP packets are skipped silently — the SIP
/// traffic in the same archive doesn't match the RTP shape and
/// falls through cleanly.
pub fn parse_rtp_packets_from_pcap(pcap_bytes: &[u8]) -> Vec<RtpPacket> {
    const PCAP_MAGIC_LE: u32 = 0xa1b2_c3d4;
    const PCAP_MAGIC_BE: u32 = 0xd4c3_b2a1;
    const LINKTYPE_ETHERNET: u32 = 1;

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
    if read_u32(&pcap_bytes[20..24]) != LINKTYPE_ETHERNET {
        return Vec::new();
    }

    let mut out: Vec<RtpPacket> = Vec::new();
    let mut cursor: usize = 24;
    while cursor + 16 <= pcap_bytes.len() {
        let ts_sec = read_u32(&pcap_bytes[cursor..cursor + 4]);
        let ts_usec = read_u32(&pcap_bytes[cursor + 4..cursor + 8]);
        let incl_len = read_u32(&pcap_bytes[cursor + 8..cursor + 12]) as usize;
        cursor += 16;
        if cursor + incl_len > pcap_bytes.len() {
            break;
        }
        let packet = &pcap_bytes[cursor..cursor + incl_len];
        cursor += incl_len;

        let parsed = match SlicedPacket::from_ethernet(packet) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let net = match parsed.net {
            Some(n) => n,
            None => continue,
        };
        let transport = match parsed.transport {
            Some(t) => t,
            None => continue,
        };
        let payload = match transport {
            etherparse::TransportSlice::Udp(u) => u.payload(),
            _ => continue,
        };
        let src_ip = match &net {
            etherparse::NetSlice::Ipv4(ip) => IpAddr::V4(ip.header().source_addr()),
            etherparse::NetSlice::Ipv6(ip) => IpAddr::V6(ip.header().source_addr()),
            _ => continue,
        };

        // RTP packet shape: byte 0 high two bits == 2 (version),
        // payload length >= 12 bytes (fixed header).
        if payload.len() < 12 {
            continue;
        }
        if (payload[0] >> 6) != 2 {
            continue;
        }
        // CSRC count + extension header can extend the fixed
        // header; we don't care about either here but we need
        // the right rtp_ts offset.
        let csrc_count = (payload[0] & 0x0f) as usize;
        let extension_bit = (payload[0] & 0x10) != 0;
        let mut header_len = 12 + csrc_count * 4;
        if extension_bit {
            // Extension header length is in 32-bit words at offset
            // header_len + 2 (after the profile-specific 16-bit
            // id). Add 4 bytes (id+length) + length*4 more.
            if payload.len() < header_len + 4 {
                continue;
            }
            let ext_len_words = u16::from_be_bytes(
                payload[header_len + 2..header_len + 4].try_into().unwrap(),
            ) as usize;
            header_len += 4 + ext_len_words * 4;
        }
        if payload.len() < header_len {
            continue;
        }
        let seq = u16::from_be_bytes(payload[2..4].try_into().unwrap());
        let rtp_ts = u32::from_be_bytes(payload[4..8].try_into().unwrap());
        let ssrc = u32::from_be_bytes(payload[8..12].try_into().unwrap());

        out.push(RtpPacket {
            arrival_secs: ts_sec as f64 + ts_usec as f64 / 1_000_000.0,
            rtp_ts,
            seq,
            ssrc,
            src_ip,
        });
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtpDirection {
    AtoB,
    BtoA,
}

/// Parse RTP packets, then bucket by direction and time.
///
/// `split_fn(src_ip)` returns `AtoB` if the packet belongs to
/// the caller→callee leg, `BtoA` for the reverse. VoIPmonitor's
/// `a_saddr` / `b_saddr` are the typical anchors — pass a
/// closure that compares the src_ip to the call's signalling
/// IPs.
///
/// Returns empty vectors when the input is empty or the
/// direction split produces no packets on one side.
pub fn compute_rtp_stats(
    packets: Vec<RtpPacket>,
    split_fn: impl Fn(IpAddr) -> RtpDirection,
    bucket_secs: u32,
) -> RtpStatsByDirection {
    if packets.is_empty() {
        return RtpStatsByDirection {
            a_to_b: Vec::new(),
            b_to_a: Vec::new(),
        };
    }
    let bucket_secs = bucket_secs.max(1) as f64;

    // Split first so the per-direction "time zero" is the first
    // packet of that direction, not the call's first packet.
    let mut a_to_b: Vec<RtpPacket> = Vec::new();
    let mut b_to_a: Vec<RtpPacket> = Vec::new();
    for p in packets {
        match split_fn(p.src_ip) {
            RtpDirection::AtoB => a_to_b.push(p),
            RtpDirection::BtoA => b_to_a.push(p),
        }
    }

    let a = bucket_one_direction(a_to_b, bucket_secs);
    let b = bucket_one_direction(b_to_a, bucket_secs);
    RtpStatsByDirection { a_to_b: a, b_to_a: b }
}

/// Compute per-second jitter / loss / MOS for one direction's
/// packets (already sorted by arrival). The arrival time of
/// the first packet becomes `time_offset_secs = 0` for that
/// direction.
fn bucket_one_direction(
    mut packets: Vec<RtpPacket>,
    bucket_secs: f64,
) -> Vec<RtpStatsBucket> {
    if packets.is_empty() {
        return Vec::new();
    }
    // Sort by wall-clock arrival — pcap record headers are
    // mostly monotonic but not guaranteed across SSRCs.
    packets.sort_by(|a, b| a.arrival_secs.partial_cmp(&b.arrival_secs).unwrap());
    let t0 = packets[0].arrival_secs;

    // RFC 3550 jitter state.
    let mut prev_arrival: Option<f64> = None;
    let mut prev_rtp_ts: Option<u32> = None;
    let mut jitter_ms: f64 = 0.0;

    // Group packets by bucket index.
    let mut buckets: Vec<Vec<&RtpPacket>> = Vec::new();
    for p in &packets {
        let offset = p.arrival_secs - t0;
        let idx = (offset / bucket_secs).floor() as usize;
        while buckets.len() <= idx {
            buckets.push(Vec::new());
        }
        buckets[idx].push(p);
    }

    // Per-bucket aggregation.
    let mut out = Vec::with_capacity(buckets.len());
    for (idx, group) in buckets.iter().enumerate() {
        if group.is_empty() {
            continue;
        }
        // Walk packets in arrival order so the running jitter
        // is the *live* jitter at the end of the bucket (not a
        // per-bucket recompute that loses continuity).
        let mut bucket_jitter_sum = 0.0;
        let mut bucket_jitter_n = 0u32;
        for p in group {
            if let (Some(r0), Some(s0)) = (prev_arrival, prev_rtp_ts) {
                let d_arrival_ms = (p.arrival_secs - r0) * 1000.0;
                // Wrap-around safe subtraction: RTP timestamps
                // are 32-bit unsigned with wrap at 2^32.
                let d_rtp = (p.rtp_ts as i64).wrapping_sub(s0 as i64) as f64;
                // Assume 8 kHz clock (the common case for
                // narrowband codecs). For wideband (16 kHz)
                // the jitter value is 2x off — acceptable
                // noise for a timeline visualisation.
                let d_rtp_ms = d_rtp / 8.0;
                let diff = (d_arrival_ms - d_rtp_ms).abs();
                jitter_ms += (diff - jitter_ms) / 16.0;
            }
            prev_arrival = Some(p.arrival_secs);
            prev_rtp_ts = Some(p.rtp_ts);
            bucket_jitter_sum += jitter_ms;
            bucket_jitter_n += 1;
        }

        let avg_jitter_ms = if bucket_jitter_n > 0 {
            bucket_jitter_sum / bucket_jitter_n as f64
        } else {
            0.0
        };

        // Loss: how many packets did we expect in this bucket
        // based on the previous bucket's rate? For a fresh
        // direction with no prior bucket, report 0.
        let loss_pct = if idx > 0 && !buckets[idx - 1].is_empty() {
            let prev_count = buckets[idx - 1].len();
            if prev_count == 0 {
                0.0
            } else {
                let expected = prev_count as f64;
                let got = group.len() as f64;
                ((expected - got) / expected * 100.0).max(0.0)
            }
        } else {
            0.0
        };

        // MOS estimate. `R = 93.2 - 2.5*loss_pct - jitter_ms/10`.
        // R is clamped to [0, 100] before the cubic — the
        // 1 + 0.035R + R(R-60)(100-R)·7e-6 conversion is only
        // valid inside that range; outside it produces values
        // > 5 that the final clamp would push up to 5,
        // defeating the purpose. R<0 → MOS=1, R>100 → MOS≈4.5.
        let r_raw = 93.2_f32 - 2.5 * loss_pct as f32 - (avg_jitter_ms / 10.0) as f32;
        let mos = if r_raw <= 0.0 {
            1.0
        } else if r_raw >= 100.0 {
            4.5
        } else {
            (1.0 + 0.035 * r_raw
                + r_raw * (r_raw - 60.0) * (100.0 - r_raw) * 7e-6)
                .clamp(1.0, 5.0)
        };

        out.push(RtpStatsBucket {
            time_offset_secs: idx as f64 * bucket_secs,
            jitter_ms: avg_jitter_ms,
            loss_pct,
            mos,
            packet_count: group.len() as u32,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Minimal Ethernet/IPv4/UDP/RTP packet builder for tests.
    /// Mirrors the structure of the SIP pcap test helper but
    /// stamps the payload as RTP (version=2, no padding, no
    /// extensions, no CSRCs).
    fn build_rtp_pcap(packets: &[RtpPacket]) -> Vec<u8> {
        let mut pcap = Vec::new();
        // pcap global header
        pcap.extend_from_slice(&0xa1b2c3d4_u32.to_le_bytes());
        pcap.extend_from_slice(&2u16.to_le_bytes());
        pcap.extend_from_slice(&4u16.to_le_bytes());
        pcap.extend_from_slice(&0i32.to_le_bytes());
        pcap.extend_from_slice(&0u32.to_le_bytes());
        pcap.extend_from_slice(&65535u32.to_le_bytes());
        pcap.extend_from_slice(&1u32.to_le_bytes());

        for p in packets {
            // RTP payload (12 bytes minimum): V=2 P=0 X=0 CC=0
            // M=0 PT=0, seq, ts, ssrc.
            let mut rtp = Vec::with_capacity(12);
            rtp.push(0x80); // version=2, P=0, X=0, CC=0
            rtp.push(0x00); // M=0, PT=0
            rtp.extend_from_slice(&p.seq.to_be_bytes());
            rtp.extend_from_slice(&p.rtp_ts.to_be_bytes());
            rtp.extend_from_slice(&p.ssrc.to_be_bytes());
            // 160 bytes of fake payload — enough that we can
            // tell the parser isn't short-circuiting on the
            // length check.
            rtp.extend_from_slice(&[0u8; 160]);

            let udp_len = (8 + rtp.len()) as u16;
            let ip_total_len = (20 + udp_len) as u16;
            let incl_len = (14 + ip_total_len as usize) as u32;

            let mut pkt = Vec::with_capacity(incl_len as usize);
            pkt.extend_from_slice(&[0u8; 6]);
            pkt.extend_from_slice(&[0u8; 6]);
            pkt.extend_from_slice(&0x0800u16.to_be_bytes());
            pkt.push(0x45);
            pkt.push(0x00);
            pkt.extend_from_slice(&ip_total_len.to_be_bytes());
            pkt.extend_from_slice(&0u16.to_be_bytes());
            pkt.extend_from_slice(&0u16.to_le_bytes());
            pkt.push(64);
            pkt.push(17);
            pkt.extend_from_slice(&0u16.to_be_bytes());
            let src_bytes = match p.src_ip {
                IpAddr::V4(v4) => v4.octets(),
                _ => [0; 4],
            };
            pkt.extend_from_slice(&src_bytes);
            pkt.extend_from_slice(&[10, 0, 0, 2]); // dst
            pkt.extend_from_slice(&16384u16.to_be_bytes()); // src port
            pkt.extend_from_slice(&16384u16.to_be_bytes()); // dst port
            pkt.extend_from_slice(&udp_len.to_be_bytes());
            pkt.extend_from_slice(&0u16.to_be_bytes());
            pkt.extend_from_slice(&rtp);

            // pcap record header
            let ts_sec = p.arrival_secs as u32;
            let ts_usec = ((p.arrival_secs - ts_sec as f64) * 1_000_000.0) as u32;
            pcap.extend_from_slice(&ts_sec.to_le_bytes());
            pcap.extend_from_slice(&ts_usec.to_le_bytes());
            pcap.extend_from_slice(&incl_len.to_le_bytes());
            pcap.extend_from_slice(&incl_len.to_le_bytes());
            pcap.extend_from_slice(&pkt);
        }
        pcap
    }

    fn mk_pkt(arrival: f64, rtp_ts: u32, ssrc: u32, src: [u8; 4]) -> RtpPacket {
        RtpPacket {
            arrival_secs: arrival,
            rtp_ts,
            seq: ((rtp_ts / 160) & 0xffff) as u16,
            ssrc,
            src_ip: IpAddr::V4(Ipv4Addr::from(src)),
        }
    }

    #[test]
    fn parse_rtp_extracts_packets_and_skips_non_rtp() {
        let packets = vec![
            mk_pkt(0.0, 0, 0xdeadbeef, [10, 0, 0, 1]),
            mk_pkt(0.02, 160, 0xdeadbeef, [10, 0, 0, 1]),
            mk_pkt(0.04, 320, 0xdeadbeef, [10, 0, 0, 1]),
        ];
        let mut pcap = build_rtp_pcap(&packets);
        // Mutate the last packet's RTP byte 0 to version=0 so it
        // gets skipped by the RTP-shape check.
        let last_record_start = pcap.len() - (14 + 20 + 8 + 172);
        let rtp_payload_offset = last_record_start + 16 + 14 + 20 + 8;
        pcap[rtp_payload_offset] = 0x00;
        let parsed = parse_rtp_packets_from_pcap(&pcap);
        assert_eq!(parsed.len(), 3, "non-RTP packet must be skipped");
        assert_eq!(parsed[0].ssrc, 0xdeadbeef);
        assert_eq!(parsed[0].rtp_ts, 0);
    }

    #[test]
    fn rfc3550_jitter_is_zero_for_perfectly_regular_arrivals() {
        let packets: Vec<RtpPacket> = (0..50)
            .map(|i| {
                mk_pkt(
                    i as f64 * 0.020,
                    i as u32 * 160,
                    0x1234,
                    [10, 0, 0, 1],
                )
            })
            .collect();
        let pcap = build_rtp_pcap(&packets);
        let parsed = parse_rtp_packets_from_pcap(&pcap);
        let stats = compute_rtp_stats(parsed, |_| RtpDirection::AtoB, 1);
        assert_eq!(stats.a_to_b.len(), 1, "all 50 packets in 1s bucket");
        assert!(
            stats.a_to_b[0].jitter_ms.abs() < 1e-6,
            "perfectly regular stream should have ~0 jitter, got {}",
            stats.a_to_b[0].jitter_ms
        );
        assert_eq!(stats.a_to_b[0].packet_count, 50);
    }

    #[test]
    fn rfc3550_jitter_grows_with_irregular_arrivals() {
        let mut packets: Vec<RtpPacket> = Vec::new();
        let mut arrival = 0.0_f64;
        for i in 0..60u32 {
            if i % 5 == 4 {
                arrival += 0.070;
            } else {
                arrival += 0.020;
            }
            packets.push(mk_pkt(arrival, i * 160, 0x42, [10, 0, 0, 1]));
        }
        let pcap = build_rtp_pcap(&packets);
        let parsed = parse_rtp_packets_from_pcap(&pcap);
        let stats = compute_rtp_stats(parsed, |_| RtpDirection::AtoB, 1);
        assert!(!stats.a_to_b.is_empty());
        assert!(
            stats.a_to_b[0].jitter_ms > 1.0,
            "jittery stream should have non-trivial jitter, got {}",
            stats.a_to_b[0].jitter_ms
        );
        assert!(stats.a_to_b[0].mos < 4.5);
    }

    #[test]
    fn mos_clamped_to_valid_range() {
        let mut packets: Vec<RtpPacket> = Vec::new();
        // Bucket 0: 50 packets in 1 second.
        for i in 0..50u32 {
            packets.push(mk_pkt(i as f64 * 0.02, i * 160, 0x1, [10, 0, 0, 1]));
        }
        // Bucket 1: only 10 packets (lost 40).
        for i in 0..10u32 {
            packets.push(mk_pkt(
                1.0 + i as f64 * 0.02,
                (50 + i) * 160,
                0x1,
                [10, 0, 0, 1],
            ));
        }
        let pcap = build_rtp_pcap(&packets);
        let parsed = parse_rtp_packets_from_pcap(&pcap);
        let stats = compute_rtp_stats(parsed, |_| RtpDirection::AtoB, 1);
        assert!(stats.a_to_b.len() >= 2);
        let mos_b1 = stats.a_to_b[1].mos;
        assert!(
            (1.0..=5.0).contains(&mos_b1),
            "MOS must be clamped to [1, 5], got {mos_b1}"
        );
        assert!(mos_b1 < 3.5, "80% loss should tank MOS, got {mos_b1}");
    }

    #[test]
    fn direction_split_separates_legs() {
        let packets = vec![
            mk_pkt(0.0, 0, 0x1, [10, 0, 0, 1]),
            mk_pkt(0.02, 160, 0x2, [10, 0, 0, 2]),
            mk_pkt(0.04, 320, 0x1, [10, 0, 0, 1]),
            mk_pkt(0.06, 480, 0x2, [10, 0, 0, 2]),
        ];
        let pcap = build_rtp_pcap(&packets);
        let parsed = parse_rtp_packets_from_pcap(&pcap);
        let stats = compute_rtp_stats(parsed, |ip| match ip {
            IpAddr::V4(v4) if v4.octets()[3] == 1 => RtpDirection::AtoB,
            _ => RtpDirection::BtoA,
        }, 1);
        assert_eq!(stats.a_to_b.iter().map(|b| b.packet_count).sum::<u32>(), 2);
        assert_eq!(stats.b_to_a.iter().map(|b| b.packet_count).sum::<u32>(), 2);
    }

    #[test]
    fn empty_input_yields_empty_stats() {
        let stats = compute_rtp_stats(Vec::new(), |_| RtpDirection::AtoB, 1);
        assert!(stats.a_to_b.is_empty());
        assert!(stats.b_to_a.is_empty());
    }
}
