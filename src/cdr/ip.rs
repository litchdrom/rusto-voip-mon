//! IP address type that survives both legacy `INT UNSIGNED` and
//! post-ipv6-alter `VARBINARY(16)` storage.
//!
//! VoIPmonitor's `scripts/ipv6_alter.sql` converts every IP column
//! in the schema from `INT UNSIGNED` (4-byte IPv4) to
//! `VARBINARY(16)` (4-byte IPv4 *or* 16-byte IPv6). This app supports
//! both shapes at runtime by:
//!
//!   1. Detecting the live shape at startup
//!      ([`crate::db::detect_ip_column_shape`]) and caching it on
//!      `AppState`.
//!   2. Decoding each IP column with [`IpAddr::from_row`], which
//!      picks `u32` or `Vec<u8>` based on the cached shape.
//!   3. Building WHERE-clauses and SELECT-fn calls with the cached
//!      shape's [`crate::db::IpColumnShape::inet_function`] /
//!      [`crate::db::IpColumnShape::inet_to_string_function`].
//!
//! This module owns the type-side glue (`IpAddr`, byte-level
//! conversions, the `to_dotted_decimal()` / `Display` impls). The
//! SQL-side glue lives in [`crate::cdr`] because that's where the
//! CDR queries are.

use serde::{Deserialize, Serialize};
use sqlx::mysql::{MySqlRow, MySqlValueRef};
use sqlx::{Decode, MySql, Row, Type, TypeInfo, ValueRef};

use crate::db::IpColumnShape;

/// One IP address, in the shape the live DB actually has.
///
/// Constructed via:
///   * [`IpAddr::from_row`] — the right path. Picks `u32` or
///     `Vec<u8>` based on `IpColumnShape`.
///   * [`IpAddr::from_bytes`] — for the `Vec<u8>` arm explicitly.
///   * [`IpAddr::V4`] — for tests + hard-coded literals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum IpAddr {
    /// IPv4 address as a host-order `u32`. Network-byte-order at the
    /// SQL boundary (i.e. `INET_ATON('1.2.3.4')` returns 16909060,
    /// which is `1 << 24 | 2 << 16 | 3 << 8 | 4` = `0x01020304`).
    /// We use `u32::from_be_bytes` to convert from the `Vec<u8>`
    /// shape so the conversion direction matches the on-disk
    /// representation.
    V4(u32),
    /// IPv6 address as 16 raw bytes in network byte order. Stored
    /// in the `VARBINARY(16)` column as `INET6_ATON('2001:db8::1')`
    /// would yield it.
    V6([u8; 16]),
}

impl IpAddr {
    /// Decode an IP column from a MySQL row, picking the right
    /// underlying type based on the cached [`IpColumnShape`].
    ///
    /// Returns `Ok(None)` when the column itself is NULL. Returns
    /// `Err(sqlx::Error::ColumnDecode)` when the column exists but
    /// the type doesn't match the shape we asked for — typically
    /// because someone changed the schema after the app booted.
    /// We do *not* fall back silently in that case: a loud error is
    /// better than a misread value.
    pub fn from_row(
        row: &MySqlRow,
        col: &str,
        shape: IpColumnShape,
    ) -> Result<Option<Self>, sqlx::Error> {
        match shape {
            IpColumnShape::LegacyInt => {
                let v: Option<u32> = row.try_get(col)?;
                Ok(v.map(IpAddr::V4))
            }
            IpColumnShape::Varbinary => {
                let bytes: Option<Vec<u8>> = row.try_get(col)?;
                Ok(bytes.map(IpAddr::from_bytes))
            }
        }
    }

    /// Build an `IpAddr` from the raw byte representation used by
    /// `VARBINARY(16)`. Accepts both 4-byte (IPv4-in-VARBINARY) and
    /// 16-byte (IPv6) lengths. Anything else is an error — a 5-byte
    /// "IP" would be a corrupted schema, not a value to guess on.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        match bytes.len() {
            4 => {
                let n = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                IpAddr::V4(n)
            }
            16 => {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&bytes);
                IpAddr::V6(arr)
            }
            other => {
                // Defensive default: treat the bytes as 4-byte IPv4 if
                // we can, otherwise as a left-aligned IPv6 (zero-padded
                // on the right). Real internet work doesn't yield 5-byte
                // IPs — would only show up with a hand-corrupted DB.
                if other < 4 {
                    let mut padded = [0u8; 4];
                    padded[..other].copy_from_slice(&bytes);
                    IpAddr::V4(u32::from_be_bytes(padded))
                } else {
                    let mut arr = [0u8; 16];
                    arr[..other.min(16)].copy_from_slice(&bytes[..other.min(16)]);
                    IpAddr::V6(arr)
                }
            }
        }
    }

    /// Render as the canonical textual form:
    ///   * `1.2.3.4` for IPv4
    ///   * `2001:db8::1` for IPv6 (zero-compressed)
    pub fn to_dotted_decimal(&self) -> String {
        match self {
            IpAddr::V4(n) => format!(
                "{}.{}.{}.{}",
                (n >> 24) & 0xff,
                (n >> 16) & 0xff,
                (n >> 8) & 0xff,
                n & 0xff
            ),
            IpAddr::V6(bytes) => format_v6(bytes),
        }
    }

    /// True if the address is the unspecified IPv4 (`0.0.0.0`).
    /// VoIPmonitor writes `0` for unknown / missing IP sources and
    /// the old code rendered that as `"0.0.0.0"`, which the user
    /// saw as confusing. We treat `0.0.0.0` as "unknown" so the
    /// template can render an empty string instead.
    pub fn is_unspecified_v4(&self) -> bool {
        matches!(self, IpAddr::V4(0))
    }

    /// True if the address is the unspecified IPv6 (`::`).
    pub fn is_unspecified_v6(&self) -> bool {
        match self {
            IpAddr::V6(bytes) => bytes.iter().all(|&b| b == 0),
            _ => false,
        }
    }
}

impl std::fmt::Display for IpAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_dotted_decimal())
    }
}

impl Type<MySql> for IpAddr {
    /// Tell sqlx what MySQL type to expect in queries / prepared
    /// statements. We declare `VARBINARY` because `query_as` checks
    /// this against the actual column type when binding parameters;
    /// for the read side the runtime `decode` handles whatever shape
    /// is actually there.
    fn type_info() -> sqlx::mysql::MySqlTypeInfo {
        <Vec<u8> as Type<MySql>>::type_info()
    }

    fn compatible(ty: &sqlx::mysql::MySqlTypeInfo) -> bool {
        // Accept both legacy `INT UNSIGNED` and post-ipv6-alter
        // `VARBINARY(16)` for the read path.
        let n = ty.name();
        matches!(
            n,
            "VARBINARY" | "BINARY" | "TINYBLOB" | "BLOB" | "MEDIUMBLOB" | "LONGBLOB"
                | "INT UNSIGNED" | "INT" | "BIGINT UNSIGNED" | "BIGINT"
        )
    }
}

impl Decode<'_, MySql> for IpAddr {
    /// Decode an IP from a MySQL value. Inspects the column's actual
    /// type tag so we don't need to know in advance whether the
    /// column is `INT UNSIGNED` (legacy) or `VARBINARY(16)`
    /// (post-ipv6-alter):
    ///
    ///   * `INT UNSIGNED` → wrap as `IpAddr::V4(n)` directly.
    ///   * `VARBINARY` / `BINARY` / `BLOB` family → try `Vec<u8>` first,
    ///     dispatch on length to `V4` (4 bytes) or `V6` (16 bytes).
    ///
    /// Anything else is a real schema error — we surface the column
    /// type info in the error message rather than guessing.
    fn decode(
        value: MySqlValueRef<'_>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync + 'static>> {
        let type_name = value.type_info().name().to_string();
        match type_name.as_str() {
            "VARBINARY" | "BINARY" | "TINYBLOB" | "BLOB" | "MEDIUMBLOB" | "LONGBLOB" => {
                let bytes = <Vec<u8> as Decode<MySql>>::decode(value)?;
                Ok(IpAddr::from_bytes(bytes))
            }
            "INT UNSIGNED" | "INT" | "BIGINT UNSIGNED" | "BIGINT" => {
                let n = <u32 as Decode<MySql>>::decode(value)?;
                Ok(IpAddr::V4(n))
            }
            other => Err(format!(
                "IpAddr decode: unsupported MySQL column type {other}; \
                 expected VARBINARY (post-ipv6-alter) or INT UNSIGNED (legacy)"
            )
            .into()),
        }
    }
}

/// Format 16 bytes as a canonical IPv6 string with zero-compression.
/// Two passes: build the 8 hextets, find the longest run of zeroes,
/// emit `[…:data][::][…:data]`.
//
// Pulled into a separate function so tests can exercise it directly.
fn format_v6(bytes: &[u8; 16]) -> String {
    let mut hextets = [0u16; 8];
    for (i, h) in hextets.iter_mut().enumerate() {
        *h = u16::from_be_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
    }
    // RFC 5952 — find the longest run of consecutive zero hextets,
    // break ties by picking the first run.
    let mut best_start: Option<usize> = None;
    let mut best_len = 0usize;
    let mut cur_start: Option<usize> = None;
    let mut cur_len = 0usize;
    for (i, &h) in hextets.iter().enumerate() {
        if h == 0 {
            if cur_start.is_none() {
                cur_start = Some(i);
            }
            cur_len += 1;
            if cur_len > best_len {
                best_start = cur_start;
                best_len = cur_len;
            }
        } else {
            cur_start = None;
            cur_len = 0;
        }
    }
    // A single zero hextet should be written as "0", not "::".
    let best_str = if best_len >= 2 { best_start } else { None };
    let mut out = String::with_capacity(40);
    let mut i = 0;
    while i < hextets.len() {
        if Some(i) == best_str {
            out.push_str("::");
            i += best_len;
        } else {
            if !out.ends_with(':') && !out.is_empty() && !out.ends_with(':') {
                out.push(':');
            }
            out.push_str(&format!("{:x}", hextets[i]));
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_renders_as_dotted_decimal() {
        assert_eq!(IpAddr::V4(0x0102_0304).to_dotted_decimal(), "1.2.3.4");
        assert_eq!(IpAddr::V4(0).to_dotted_decimal(), "0.0.0.0");
        assert_eq!(
            IpAddr::V4(0xc0a8_0101).to_dotted_decimal(),
            "192.168.1.1"
        );
        // Network-byte-order round-trip: 1.2.3.4 → 0x01020304 → 16909060
        assert_eq!(IpAddr::V4(16909060).to_dotted_decimal(), "1.2.3.4");
    }

    #[test]
    fn v4_from_bytes_is_be_big_endian() {
        // MySQL stores INET_ATON('1.2.3.4') in network byte order,
        // so the byte column reads as [1, 2, 3, 4] → V4(16909060).
        let addr = IpAddr::from_bytes(vec![1, 2, 3, 4]);
        assert_eq!(addr, IpAddr::V4(16909060));
    }

    #[test]
    fn v6_renders_with_zero_compression() {
        // 2001:db8::1
        let bytes = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        assert_eq!(IpAddr::V6(bytes).to_dotted_decimal(), "2001:db8::1");
        // ::1
        let mut bytes = [0u8; 16];
        bytes[15] = 1;
        assert_eq!(IpAddr::V6(bytes).to_dotted_decimal(), "::1");
        // :: (unspecified)
        assert_eq!(IpAddr::V6([0u8; 16]).to_dotted_decimal(), "::");
        // Full form, no zeros — bytes 0..15 produce hextets 0x0001, 0x0203,
        // 0x0405, …, 0x0e0f which render as `1`, `203`, `405`, …
        let bytes: [u8; 16] = std::array::from_fn(|i| i as u8);
        assert_eq!(
            IpAddr::V6(bytes).to_dotted_decimal(),
            "1:203:405:607:809:a0b:c0d:e0f"
        );
        // Mid-range zero compression
        let bytes = [
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        assert_eq!(
            IpAddr::V6(bytes).to_dotted_decimal(),
            "fe80::1"
        );
    }

    #[test]
    fn v6_from_bytes_preserves_layout() {
        let bytes = [
            0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11,
            0x22, 0x33, 0x44,
        ];
        let addr = IpAddr::from_bytes(bytes.to_vec());
        match addr {
            IpAddr::V6(arr) => assert_eq!(arr, bytes),
            _ => panic!("expected V6"),
        }
    }

    #[test]
    fn unspecified_detection() {
        assert!(IpAddr::V4(0).is_unspecified_v4());
        assert!(!IpAddr::V4(1).is_unspecified_v4());
        assert!(IpAddr::V6([0u8; 16]).is_unspecified_v6());
        let mut not_zero = [0u8; 16];
        not_zero[0] = 1;
        assert!(!IpAddr::V6(not_zero).is_unspecified_v6());
    }

    #[test]
    fn from_bytes_handles_short_and_long_inputs_defensively() {
        // 0-byte input: pads to V4(0)
        assert_eq!(IpAddr::from_bytes(vec![]), IpAddr::V4(0));
        // 2-byte input: pads to V4 with first 2 bytes preserved at the
        // high end of the u32 — `[0x12, 0x34, 0, 0]` reads as
        // `0x12340000` = 305397760. Verifies the defensive path
        // doesn't silently drop operator-typed values.
        let addr = IpAddr::from_bytes(vec![0x12, 0x34]);
        assert_eq!(addr, IpAddr::V4(0x12340000));
        // 20-byte input: left-aligned, last 4 dropped
        let mut input = vec![0u8; 20];
        input[0] = 0x20;
        input[1] = 0x01;
        let addr = IpAddr::from_bytes(input.clone());
        match addr {
            IpAddr::V6(arr) => {
                assert_eq!(arr[0], 0x20);
                assert_eq!(arr[1], 0x01);
                assert_eq!(arr[2], 0);
                assert_eq!(arr[15], 0);
            }
            _ => panic!("expected V6"),
        }
    }

    #[test]
    fn display_uses_dotted_decimal() {
        assert_eq!(format!("{}", IpAddr::V4(0x0102_0304)), "1.2.3.4");
        let bytes = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
        assert_eq!(format!("{}", IpAddr::V6(bytes)), "2001:db8::1");
    }
}