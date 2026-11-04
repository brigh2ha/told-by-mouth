//! The Bluetooth advertisement name (spec section 4): 8 characters holding a
//! random 4-byte token and the low 2 bytes of catalog_version. iPhones allow
//! only a service id and a name while advertising, so the version rides in
//! the name.

pub type Token = [u8; 4];

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encodes 6 bytes (token, version low 16 bits) as 8 URL-safe base64 chars.
pub fn encode_name(token: Token, catalog_version: u32) -> String {
    let v = (catalog_version & 0xffff) as u16;
    let mut bytes = [0u8; 6];
    bytes[..4].copy_from_slice(&token);
    bytes[4..].copy_from_slice(&v.to_be_bytes());
    let mut out = String::with_capacity(8);
    for group in bytes.chunks(3) {
        let n = (group[0] as u32) << 16 | (group[1] as u32) << 8 | group[2] as u32;
        for shift in [18, 12, 6, 0] {
            out.push(ALPHABET[((n >> shift) & 63) as usize] as char);
        }
    }
    out
}

/// Reads a name back. `None` if it is not one of ours.
pub fn decode_name(name: &str) -> Option<(Token, u16)> {
    let raw = name.as_bytes();
    if raw.len() != 8 {
        return None;
    }
    let mut bytes = [0u8; 6];
    for (i, group) in raw.chunks(4).enumerate() {
        let mut n = 0u32;
        for &c in group {
            n = n << 6 | ALPHABET.iter().position(|&a| a == c)? as u32;
        }
        bytes[i * 3] = (n >> 16) as u8;
        bytes[i * 3 + 1] = (n >> 8) as u8;
        bytes[i * 3 + 2] = n as u8;
    }
    Some((
        bytes[..4].try_into().unwrap(),
        u16::from_be_bytes([bytes[4], bytes[5]]),
    ))
}

/// Of two phones, the one with the smaller token connects, so each pair
/// has one link.
pub fn i_connect(my_token: Token, their_token: Token) -> bool {
    my_token < their_token
}

/// Whether a seen version (low 16 bits) differs from the catalog I hold.
pub fn version_changed(seen_low16: u16, held: u32) -> bool {
    seen_low16 != (held & 0xffff) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_round_trip() {
        for (t, v) in [
            ([0, 0, 0, 0], 0),
            ([255, 1, 2, 3], 70_000),
            ([9, 8, 7, 6], 65_535),
        ] {
            let name = encode_name(t, v);
            assert_eq!(name.len(), 8);
            assert_eq!(decode_name(&name), Some((t, (v & 0xffff) as u16)));
        }
        assert_eq!(decode_name("short"), None);
        assert_eq!(decode_name("!!!!!!!!"), None);
        assert!(i_connect([1, 0, 0, 0], [2, 0, 0, 0]));
        assert!(version_changed(4, 3));
        assert!(!version_changed(4, 65_540));
    }
}
