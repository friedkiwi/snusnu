//! Stable local proxy addresses for automatic LLC routing.
//!
//! The concentrator owns 02:53:4e:xx:xx:xx. Locally selected addresses use
//! 06:53:4e:xx:xx:xx so a guest can address a target behind this router
//! without confusing it with a concentrator-managed destination.

use std::{collections::BTreeMap, collections::HashMap, io};

pub(crate) const LOCAL_PROXY_PREFIX: [u8; 3] = [0x06, 0x53, 0x4e];
const HASH_DOMAIN: &[u8] = b"snusnu-local-proxy-mac-v1\0";

#[derive(Clone, Debug, Default)]
pub(crate) struct AutoProxyMacs {
    by_id: BTreeMap<String, [u8; 6]>,
}

impl AutoProxyMacs {
    pub(crate) fn from_ids<I, S>(ids: I) -> io::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut by_id = BTreeMap::new();
        let mut by_mac = HashMap::<[u8; 6], String>::new();
        for id in ids {
            let id = id.as_ref();
            if id.is_empty() {
                return Err(invalid("local proxy target has an empty attachment ID"));
            }
            if by_id.contains_key(id) {
                return Err(invalid(format!("duplicate local proxy target {id}")));
            }
            let mac = mac_for_id(id);
            if let Some(previous) = by_mac.insert(mac, id.to_owned()) {
                return Err(invalid(format!(
                    "local proxy MAC collision between {previous} and {id} at {}",
                    format_mac(mac)
                )));
            }
            by_id.insert(id.to_owned(), mac);
        }
        Ok(Self { by_id })
    }

    pub(crate) fn get(&self, id: &str) -> Option<[u8; 6]> {
        self.by_id.get(id).copied()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&str, [u8; 6])> + '_ {
        self.by_id.iter().map(|(id, mac)| (id.as_str(), *mac))
    }
}

fn mac_for_id(id: &str) -> [u8; 6] {
    // FNV-1a is specified here rather than using DefaultHasher, whose output
    // is not guaranteed to stay stable across Rust releases.
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in HASH_DOMAIN.iter().chain(id.as_bytes()) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    [
        LOCAL_PROXY_PREFIX[0],
        LOCAL_PROXY_PREFIX[1],
        LOCAL_PROXY_PREFIX[2],
        (hash >> 16) as u8,
        (hash >> 8) as u8,
        hash as u8,
    ]
}

fn format_mac(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_proxy_macs_are_stable_unique_and_separate_from_managed_macs() {
        let first = AutoProxyMacs::from_ids(["v4", "v5"]).unwrap();
        let second = AutoProxyMacs::from_ids(["v5", "v4"]).unwrap();
        assert_eq!(first.get("v4"), second.get("v4"));
        assert_eq!(first.get("v5"), second.get("v5"));
        assert_ne!(first.get("v4"), first.get("v5"));
        for (_, mac) in first.iter() {
            assert_eq!(mac[..3], LOCAL_PROXY_PREFIX);
            assert_eq!(mac[0] & 1, 0);
        }
        assert_eq!(
            first.iter().map(|(id, _)| id).collect::<Vec<_>>(),
            vec!["v4", "v5"]
        );
    }

    #[test]
    fn collision_is_reported_instead_of_reusing_a_proxy_address() {
        let mut seen = HashMap::new();
        let mut colliding = None;
        for index in 0..100_000 {
            let id = format!("peer-{index}");
            let mac = mac_for_id(&id);
            if let Some(previous) = seen.insert(mac, id.clone()) {
                colliding = Some((previous, id));
                break;
            }
        }
        let (first, second) = colliding.expect("24-bit local proxy space should collide in search");
        let error = AutoProxyMacs::from_ids([first, second]).unwrap_err();
        assert!(error.to_string().contains("collision"));
    }
}
