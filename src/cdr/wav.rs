//! G.711 → WAV audio extraction from an RTP stream.
//!
//! Why this exists
//! ---------------
//! The obvious source for call audio is `sip_msg.rtp_payload_data`,
//! but that column is only populated when the VoIPmonitor install is
//! configured to store RTP payloads in the database (`store_rtp_payload=yes`).
//! On most installs it is empty, so a player built on it would be a
//! dead button for most operators.
//!
//! The pcap archive is a different story: the RTP media is always on
//! disk (that is the whole point of `PCAP_DIR`), and the detail page
//! already extracts the merged SIP+RTP pcap for the SIP timeline and
//! the RTP chart. So the audio comes from the same proven path —
//! decode the G.711 payload straight out of the RTP packets.
//!
//! Scope
//! -----
//! Only the two payload types that map losslessly onto a WAV file are
//! supported:
//!
//!   PT 0 — PCMU (G.711 µ-law), 8 kHz
//!   PT 8 — PCMA (G.711 A-law), 8 kHz
//!
//! Every other payload type (G.729, Opus, GSM, ...) needs a real
//! codec implementation and a container this app would have to mux
//! itself. Those return `None` and the UI simply doesn't offer a
//! player for that leg — no dead buttons.
//!
//! Output is 16-bit PCM WAV, which every browser can play natively.

use crate::cdr::rtp_pcap::RtpPacket;

/// Sample rate for G.711 in RTP. Both µ-law and A-law are defined as
/// 8 kHz (the RTP clock rate for PT 0 / PT 8).
const G711_SAMPLE_RATE: u32 = 8000;

/// RTP payload type for PCMU (G.711 µ-law).
pub const PT_PCMU: u8 = 0;
/// RTP payload type for PCMA (G.711 A-law).
pub const PT_PCMA: u8 = 8;

/// True when the payload type is one we can decode into a WAV.
pub fn is_wav_capable(payload_type: u8) -> bool {
    matches!(payload_type, PT_PCMU | PT_PCMA)
}

/// Human-readable codec label for the UI.
pub fn codec_label(payload_type: u8) -> &'static str {
    match payload_type {
        PT_PCMU => "G.711 u-law",
        PT_PCMA => "G.711 A-law",
        _ => "unsupported",
    }
}

/// Decode one G.711 µ-law byte to a signed 16-bit linear sample.
///
/// The µ-law encoding is: invert the sign bit, then the exponent is
/// the next 3 bits (biased by 33), then a 4-bit mantissa. This is
/// the standard ITU-T G.711 table, computed rather than tabulated so
/// there's no 256-entry table to get wrong.
pub fn decode_ulaw(byte: u8) -> i16 {
    const BIAS: i32 = 0x84; // 132
    let u = !byte; // complement: undo the sign-bit inversion
    let exponent = ((u >> 4) & 0x07) as i32;
    let mantissa = (u & 0x0f) as i32;
    let mut sample = ((mantissa << 3) + BIAS) << exponent;
    sample -= BIAS;
    // The original sign bit (bit 7 of the *complemented* value is the
    // sign after the complement) makes the result negative.
    if u & 0x80 != 0 {
        sample = -sample;
    }
    sample as i16
}

/// Decode one G.711 A-law byte to a signed 16-bit linear sample.
///
/// A-law: the sign bit is bit 7, the exponent is bits 4..6, the
/// mantissa is bits 0..3. During decoding the exponent is biased by
/// -1 and the mantissa is shifted left by 4 before being scaled.
///
/// **Sign convention:** A-law's sign bit is INVERTED relative to
/// two's complement -- bit 7 SET means POSITIVE. This is the opposite
/// of u-law, where bit 7 set means negative, and getting it backwards
/// plays the recording back with the polarity flipped. The XOR with
/// 0x55 below does not touch bit 7 (0x55's bit 7 is 0), so the
/// original byte's bit 7 is still the sign.
///
/// The conventional "digital zero" codes confirm it: 0xD5 is positive
/// zero (decodes to +8, A-law's smallest step) and 0x55 is negative
/// zero (decodes to -8).
pub fn decode_alaw(byte: u8) -> i16 {
    let a = byte ^ 0x55; // the standard A-law inversion
    let negative = (a & 0x80) == 0;
    let exponent = ((a >> 4) & 0x07) as i32;
    let mantissa = (a & 0x0f) as i32;
    let mut sample = match exponent {
        0 => (mantissa << 4) + 8,
        _ => ((mantissa << 4) + 0x108) << (exponent - 1),
    };
    if negative {
        sample = -sample;
    }
    sample as i16
}

/// Wrap a mono PCM sample stream in a RIFF/WAVE container.
///
/// 16-bit little-endian PCM, mono, at `sample_rate`. The header is
/// the canonical 44-byte one every WAV reader expects.
pub fn write_wav(samples: &[i16], sample_rate: u32) -> Vec<u8> {
    let data_len = (samples.len() * 2) as u32;
    let mut out = Vec::with_capacity(44 + data_len as usize);

    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&(36 + data_len).to_le_bytes()); // file size - 8
    out.extend_from_slice(b"WAVE");

    // "fmt " chunk — PCM, mono, 16-bit.
    out.extend_from_slice(b"fmt ");
    out.extend_from_slice(&16u32.to_le_bytes()); // chunk size
    out.extend_from_slice(&1u16.to_le_bytes()); // format 1 = PCM
    out.extend_from_slice(&1u16.to_le_bytes()); // channels = mono
    out.extend_from_slice(&sample_rate.to_le_bytes());
    out.extend_from_slice(&(sample_rate * 2).to_le_bytes()); // byte rate
    out.extend_from_slice(&2u16.to_le_bytes()); // block align
    out.extend_from_slice(&16u16.to_le_bytes()); // bits per sample

    // "data" chunk
    out.extend_from_slice(b"data");
    out.extend_from_slice(&data_len.to_le_bytes());
    for s in samples {
        out.extend_from_slice(&s.to_le_bytes());
    }

    out
}

/// Decode the RTP packets of one leg into a WAV file.
///
/// `packets` should already be filtered to the leg's direction; this
/// function additionally filters by payload type so a leg that
/// renegotiated mid-call (or carries a mix of media and comfort
/// noise) still produces the audio it can.
///
/// Returns `None` when the payload type is not G.711, or when there
/// is no media at all — the caller then omits the player rather than
/// shipping an empty file.
pub fn encode_wav_from_rtp(packets: &[RtpPacket], payload_type: u8) -> Option<Vec<u8>> {
    if !is_wav_capable(payload_type) {
        return None;
    }

    // Collect the media in capture order. RTP packets can arrive out
    // of order on the wire, but VoIPmonitor's archive is written in
    // capture order, which for a single stream is close enough to
    // playback order. Sorting by sequence number would be more
    // correct but breaks across SSRC changes and 16-bit wraparound;
    // for intelligibility the capture order is what a phone hears
    // anyway.
    let media: Vec<&RtpPacket> = packets
        .iter()
        .filter(|p| p.payload_type == payload_type)
        .collect();

    if media.is_empty() {
        return None;
    }

    // Average media samples per packet — used to size the silence we
    // insert for dropped packets.
    let total_samples: usize = media.iter().map(|p| p.payload.len()).sum();
    let avg_samples = (total_samples / media.len()).max(1);

    let mut samples: Vec<i16> = Vec::with_capacity(total_samples);
    let mut prev_seq: Option<u16> = None;

    for p in &media {
        // Gap fill. RTP sequence numbers increment by one per packet,
        // so a jump means packets were lost in transit. Without this
        // the recording would be time-compressed — the player would
        // run the surviving audio faster than it was spoken, which
        // is the classic "chipmunk" artefact and makes a lossy call
        // much harder to follow than the real thing.
        //
        // `wrapping_sub` handles the 16-bit sequence wraparound
        // (65535 -> 0), and a huge jump means an SSRC change or a
        // sequence reset rather than loss, so we cap the fill.
        if let Some(prev) = prev_seq {
            let lost = p.seq.wrapping_sub(prev.wrapping_add(1));
            // Up to 200 missing packets (4 seconds at 20 ms ptime)
            // is treated as loss; beyond that it's a stream reset.
            if lost > 0 && lost <= 200 {
                samples.extend(std::iter::repeat(0i16).take(lost as usize * avg_samples));
            }
        }
        prev_seq = Some(p.seq);

        match payload_type {
            PT_PCMU => samples.extend(p.payload.iter().map(|&b| decode_ulaw(b))),
            PT_PCMA => samples.extend(p.payload.iter().map(|&b| decode_alaw(b))),
            _ => unreachable!("is_wav_capable already filtered this"),
        }
    }

    if samples.is_empty() {
        return None;
    }
    Some(write_wav(&samples, G711_SAMPLE_RATE))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn pkt(pt: u8, payload: Vec<u8>) -> RtpPacket {
        RtpPacket {
            arrival_secs: 0.0,
            rtp_ts: 0,
            seq: 0,
            ssrc: 1,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            payload_type: pt,
            payload,
        }
    }

    #[test]
    fn ulaw_round_trips_the_known_anchors() {
        // Silence in µ-law is 0xFF, and it must decode to exactly 0.
        assert_eq!(decode_ulaw(0xFF), 0);
        // 0x7F is the other conventional silence value -- also 0.
        assert_eq!(decode_ulaw(0x7F), 0);
        // The extremes of the encoding map to the extremes of the
        // u-law range: 0x00 -> -32124, 0x80 -> +32124. (u-law's
        // maximum is 32124, NOT 32767 -- the encoding can't reach
        // full scale.)
        assert_eq!(decode_ulaw(0x00), -32124);
        assert_eq!(decode_ulaw(0x80), 32124);
    }

    #[test]
    fn alaw_round_trips_the_known_anchors() {
        // A-law has no exact zero code point -- segment 0's smallest
        // step is 8, so the conventional "digital zero" codes decode
        // to +8 / -8 rather than 0. That's inaudible (8/32768 of full
        // scale) and is what the ITU reference decoder produces.
        assert_eq!(decode_alaw(0xD5), 8);
        assert_eq!(decode_alaw(0x55), -8);
        // A-law's maximum magnitude is 32256 (larger than u-law's
        // 32124 -- the two encodings don't share a range). The
        // extremes are the codes with segment 7 and mantissa 15:
        // 0xAA -> +32256, 0x2A -> -32256.
        assert_eq!(decode_alaw(0xAA), 32256);
        assert_eq!(decode_alaw(0x2A), -32256);
    }

    #[test]
    fn g711_decoders_stay_inside_their_own_ranges() {
        // u-law peaks at 32124, A-law at 32256. Neither reaches
        // i16::MAX -- that is a property of the encodings, not a bug.
        for b in 0u16..=255 {
            let b = b as u8;
            let u = decode_ulaw(b);
            let a = decode_alaw(b);
            assert!((u as i32).abs() <= 32124, "u-law {b:#04x} -> {u}");
            assert!((a as i32).abs() <= 32256, "a-law {b:#04x} -> {a}");
        }
    }

    #[test]
    fn wav_header_is_the_canonical_44_bytes() {
        let wav = write_wav(&[0, 1, -1], G711_SAMPLE_RATE);
        assert_eq!(&wav[0..4], b"RIFF");
        assert_eq!(&wav[8..12], b"WAVE");
        assert_eq!(&wav[12..16], b"fmt ");
        // fmt chunk size
        assert_eq!(u32::from_le_bytes(wav[16..20].try_into().unwrap()), 16);
        // PCM
        assert_eq!(u16::from_le_bytes(wav[20..22].try_into().unwrap()), 1);
        // mono
        assert_eq!(u16::from_le_bytes(wav[22..24].try_into().unwrap()), 1);
        // sample rate
        assert_eq!(
            u32::from_le_bytes(wav[24..28].try_into().unwrap()),
            G711_SAMPLE_RATE
        );
        // byte rate = rate * channels * bytes_per_sample
        assert_eq!(
            u32::from_le_bytes(wav[28..32].try_into().unwrap()),
            G711_SAMPLE_RATE * 2
        );
        // block align
        assert_eq!(u16::from_le_bytes(wav[32..34].try_into().unwrap()), 2);
        // bits per sample
        assert_eq!(u16::from_le_bytes(wav[34..36].try_into().unwrap()), 16);
        // data chunk
        assert_eq!(&wav[36..40], b"data");
        // 3 samples * 2 bytes
        assert_eq!(u32::from_le_bytes(wav[40..44].try_into().unwrap()), 6);
        // RIFF size field covers everything after the first 8 bytes
        assert_eq!(u32::from_le_bytes(wav[4..8].try_into().unwrap()), 44 - 8 + 6);
        assert_eq!(wav.len(), 50);
    }

    #[test]
    fn wav_payload_is_little_endian_signed_16_bit() {
        let wav = write_wav(&[0x0102, -2], G711_SAMPLE_RATE);
        // 0x0102 = 258 -> 02 01
        assert_eq!(&wav[44..46], &[0x02, 0x01]);
        // -2 -> FE FF
        assert_eq!(&wav[46..48], &[0xFE, 0xFF]);
    }

    #[test]
    fn encode_rejects_non_g711_payload_types() {
        let packets = vec![pkt(8, vec![0xD5; 10])];
        assert!(encode_wav_from_rtp(&packets, 8).is_some());
        // Opus / G.729 / dynamic PTs are not decodable here.
        assert!(encode_wav_from_rtp(&packets, 111).is_none());
        assert!(encode_wav_from_rtp(&packets, 96).is_none());
        assert!(encode_wav_from_rtp(&packets, 18).is_none());
    }

    #[test]
    fn encode_returns_none_when_there_is_no_media() {
        // Only a PT 8 packet in the stream, but we asked for PT 0.
        let packets = vec![pkt(8, vec![0xD5; 8])];
        assert!(encode_wav_from_rtp(&packets, 0).is_none());
        // Right type but empty payloads.
        assert!(encode_wav_from_rtp(&[pkt(0, vec![])], 0).is_none());
        // No packets at all.
        assert!(encode_wav_from_rtp(&[], 0).is_none());
    }

    #[test]
    fn encode_skips_packets_of_other_payload_types() {
        // A leg carrying comfort noise (PT 13) alongside PCMU (PT 0)
        // must still produce the PCMU audio, and only the PCMU bytes.
        let packets = vec![
            pkt(13, vec![0x00; 4]),
            pkt(0, vec![0xFF, 0x00]),
        ];
        let wav = encode_wav_from_rtp(&packets, 0).expect("must produce a wav");
        // 44-byte header + 2 samples * 2 bytes = 48
        assert_eq!(wav.len(), 48);
        // The two PCMU samples decode to silence then the negative extreme.
        assert_eq!(i16::from_le_bytes(wav[44..46].try_into().unwrap()), 0);
        assert_eq!(
            i16::from_le_bytes(wav[46..48].try_into().unwrap()),
            decode_ulaw(0x00)
        );
    }

    #[test]
    fn dropped_packets_are_filled_with_silence() {
        // Two packets 20ms apart at 8 kHz = 160 samples each.
        // A sequence jump of 3 means 2 packets were lost in between
        // (seq 1 -> seq 4 is a gap of 2 missing packets).
        let mut a = pkt(0, vec![0xFF; 160]);
        a.seq = 1;
        let mut b = pkt(0, vec![0xFF; 160]);
        b.seq = 4;
        let wav = encode_wav_from_rtp(&[a, b], 0).expect("must produce a wav");
        // 44-byte header + (160 + 2*160 + 160) samples * 2 bytes
        assert_eq!(wav.len(), 44 + 4 * 160 * 2);
    }

    #[test]
    fn a_sequence_reset_is_not_treated_as_loss() {
        // seq 60000 -> seq 10 is a wraparound/reset, not 60000
        // lost packets. The gap fill must not blow the file up.
        let mut a = pkt(0, vec![0xFF; 160]);
        a.seq = 60000;
        let mut b = pkt(0, vec![0xFF; 160]);
        b.seq = 10;
        let wav = encode_wav_from_rtp(&[a, b], 0).expect("must produce a wav");
        // Only the two real packets — no silence inserted.
        assert_eq!(wav.len(), 44 + 2 * 160 * 2);
    }

    #[test]
    fn contiguous_packets_produce_no_silence() {
        let mut a = pkt(0, vec![0xFF; 160]);
        a.seq = 1;
        let mut b = pkt(0, vec![0xFF; 160]);
        b.seq = 2;
        let wav = encode_wav_from_rtp(&[a, b], 0).expect("must produce a wav");
        assert_eq!(wav.len(), 44 + 2 * 160 * 2);
    }

    /// Build a pcap containing raw RTP payloads verbatim (Ethernet /
    /// IPv4 / UDP framing), the same shape `build_pcap_bytes` returns
    /// for a real call.
    fn build_raw_rtp_pcap(rtp_payloads: &[Vec<u8>]) -> Vec<u8> {
        let mut pcap = Vec::new();
        pcap.extend_from_slice(&0xa1b2c3d4_u32.to_le_bytes());
        pcap.extend_from_slice(&2u16.to_le_bytes());
        pcap.extend_from_slice(&4u16.to_le_bytes());
        pcap.extend_from_slice(&0i32.to_le_bytes());
        pcap.extend_from_slice(&0u32.to_le_bytes());
        pcap.extend_from_slice(&65535u32.to_le_bytes());
        pcap.extend_from_slice(&1u32.to_le_bytes());

        for (i, rtp) in rtp_payloads.iter().enumerate() {
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
            pkt.extend_from_slice(&[10, 0, 0, 1]);
            pkt.extend_from_slice(&[10, 0, 0, 2]);
            pkt.extend_from_slice(&16384u16.to_be_bytes());
            pkt.extend_from_slice(&16384u16.to_be_bytes());
            pkt.extend_from_slice(&udp_len.to_be_bytes());
            pkt.extend_from_slice(&0u16.to_be_bytes());
            pkt.extend_from_slice(rtp);

            pcap.extend_from_slice(&(1_700_000_000u32 + i as u32).to_le_bytes());
            pcap.extend_from_slice(&0u32.to_le_bytes());
            pcap.extend_from_slice(&incl_len.to_le_bytes());
            pcap.extend_from_slice(&incl_len.to_le_bytes());
            pcap.extend_from_slice(&pkt);
        }
        pcap
    }

    fn rtp_pcmu(seq: u16, media: &[u8]) -> Vec<u8> {
        let mut rtp = Vec::new();
        rtp.push(0x80); // V=2 P=0 X=0 CC=0
        rtp.push(0x00); // M=0 PT=0 (PCMU)
        rtp.extend_from_slice(&seq.to_be_bytes());
        rtp.extend_from_slice(&(seq as u32 * 160).to_be_bytes());
        rtp.extend_from_slice(&0x1122_3344u32.to_be_bytes());
        rtp.extend_from_slice(media);
        rtp
    }

    #[test]
    fn end_to_end_pcap_to_playable_wav() {
        // The whole chain the audio endpoint runs: a pcap off disk,
        // through the RTP parser, into a WAV a browser can play.
        let pcap = build_raw_rtp_pcap(&[
            rtp_pcmu(1, &[0xFF; 160]),
            rtp_pcmu(2, &[0x00; 160]),
        ]);

        let packets = crate::cdr::rtp_pcap::parse_rtp_packets_from_pcap(&pcap);
        assert_eq!(packets.len(), 2);
        assert!(packets.iter().all(|p| p.payload_type == PT_PCMU));

        let wav = encode_wav_from_rtp(&packets, PT_PCMU).expect("must produce a wav");

        // Container shape
        assert_eq!(&wav[0..4], b"RIFF");
        assert_eq!(&wav[8..12], b"WAVE");
        assert_eq!(&wav[36..40], b"data");
        // 320 samples * 2 bytes
        assert_eq!(u32::from_le_bytes(wav[40..44].try_into().unwrap()), 640);
        assert_eq!(wav.len(), 44 + 640);

        // And the samples themselves: the first packet is µ-law
        // silence (0xFF -> 0), the second is the negative extreme
        // (0x00 -> -32124). The second packet's first sample sits at
        // sample index 160, i.e. byte offset 44 + 160*2 = 364.
        assert_eq!(i16::from_le_bytes(wav[44..46].try_into().unwrap()), 0);
        // ...and the last sample of the first packet is silence too.
        assert_eq!(
            i16::from_le_bytes(wav[362..364].try_into().unwrap()),
            0
        );
        assert_eq!(
            i16::from_le_bytes(wav[364..366].try_into().unwrap()),
            decode_ulaw(0x00)
        );
        assert_eq!(
            i16::from_le_bytes(wav[364..366].try_into().unwrap()),
            -32124
        );
    }

    #[test]
    fn end_to_end_pcap_to_playable_wav_for_a_law() {
        // Same chain for A-law, including the inverted sign bit.
        let mut rtp = Vec::new();
        rtp.push(0x80);
        rtp.push(0x08); // PT=8 (PCMA)
        rtp.extend_from_slice(&1u16.to_be_bytes());
        rtp.extend_from_slice(&160u32.to_be_bytes());
        rtp.extend_from_slice(&1u32.to_be_bytes());
        rtp.extend_from_slice(&[0xD5; 160]); // positive zero
        let pcap = build_raw_rtp_pcap(&[rtp]);

        let packets = crate::cdr::rtp_pcap::parse_rtp_packets_from_pcap(&pcap);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].payload_type, PT_PCMA);

        let wav = encode_wav_from_rtp(&packets, PT_PCMA).expect("must produce a wav");
        assert_eq!(wav.len(), 44 + 320);
        // 0xD5 is A-law's positive zero: +8 (its smallest step).
        assert_eq!(i16::from_le_bytes(wav[44..46].try_into().unwrap()), 8);
    }

    #[test]
    fn wav_capable_covers_exactly_the_two_g711_types() {
        assert!(is_wav_capable(PT_PCMU));
        assert!(is_wav_capable(PT_PCMA));
        assert!(!is_wav_capable(3)); // GSM
        assert!(!is_wav_capable(9)); // G.722
        assert!(!is_wav_capable(111)); // Opus
        assert!(!is_wav_capable(101)); // telephone-event
    }
}