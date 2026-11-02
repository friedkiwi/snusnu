//! Identity helpers for session-selected TCP62/native gateway circuits.
//!
//! A TCP62 Connect names LUs, not APPN control points. The router therefore
//! gives its virtual APPN link a stable, distinct CP name in the source LU's
//! network. The target CP must come from an actual route's `hosting_cp` (or an
//! explicit operator hint); it cannot be guessed from the target LU name.

use crate::config;
use std::io;
use transport_ws::wire;

const BASE36: &[u8; 36] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Build the router-owned CP for one TCP62 attachment. `seed` should contain
/// a stable router identity and attachment ID, so reconnects retain the name.
/// An explicit CP may override the generated name, but must be in the LU's
/// NETID because the concentrator can only publish this router's NETID.
pub(crate) fn virtual_cp_for_source(
    source_lu: &wire::SnaName,
    seed: &[u8],
    configured_cp: Option<&str>,
) -> io::Result<wire::SnaName> {
    let source = config::parse_cp(&format!("{}.{}", source_lu.netid, source_lu.name))?;
    if let Some(configured_cp) = configured_cp.filter(|value| !value.is_empty()) {
        let cp = config::parse_cp(configured_cp)?;
        if cp.netid != source.netid {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "configured virtual CP is outside the source LU NETID",
            ));
        }
        return Ok(cp);
    }
    // FNV-1a has defined, repeatable output across runs and Rust versions.
    // The seven base-36 digits give a stable router-specific SNA name.
    let mut hash = 0xcbf29ce484222325u64;
    for byte in seed
        .iter()
        .copied()
        .chain([0xff])
        .chain(source.netid.bytes())
        .chain([0xff])
        .chain(source.name.bytes())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let mut name = [b'R'; 8];
    for position in (1..8).rev() {
        name[position] = BASE36[(hash % 36) as usize];
        hash /= 36;
    }
    Ok(wire::SnaName {
        netid: source.netid,
        name: String::from_utf8(name.to_vec()).expect("base36 is ASCII"),
    })
}

/// An LU route needs a proven hosting CP before native APPN conversion.
pub(crate) fn require_hosting_cp(
    target_lu: &wire::SnaName,
    hosting_cp: Option<wire::SnaName>,
    configured_cp: Option<&str>,
) -> io::Result<wire::SnaName> {
    let hint = configured_cp
        .filter(|value| !value.is_empty())
        .map(config::parse_cp)
        .transpose()?;
    let cp = match hosting_cp {
        Some(cp) => cp,
        None => hint.clone().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "target LU has no hosting CP")
        })?,
    };
    if cp.netid != target_lu.netid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "target LU hosting CP is in another NETID",
        ));
    }
    let cp = config::parse_cp(&format!("{}.{}", cp.netid, cp.name))?;
    if hint.is_some_and(|hint| hint != cp) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "configured target CP disagrees with advertised LU hosting CP",
        ));
    }
    Ok(cp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(netid: &str, name: &str) -> wire::SnaName {
        wire::SnaName {
            netid: netid.into(),
            name: name.into(),
        }
    }

    #[test]
    fn generated_cp_is_stable_valid_and_source_scoped() {
        let lu = name("QABOB", "PAYROLL");
        let a = virtual_cp_for_source(&lu, b"router-one/mptn", None).unwrap();
        assert_eq!(a, virtual_cp_for_source(&lu, b"router-one/mptn", None).unwrap());
        assert_eq!(a.netid, "QABOB");
        assert_eq!(a.name.len(), 8);
        assert!(a.name.starts_with('R'));
        assert_ne!(a, virtual_cp_for_source(&lu, b"router-two/mptn", None).unwrap());
        assert_ne!(a.name, lu.name);
        config::parse_cp(&format!("{}.{}", a.netid, a.name)).unwrap();
    }

    #[test]
    fn configured_cp_and_hosting_cp_require_matching_netids() {
        let lu = name("QABOB", "SNAB");
        assert_eq!(
            virtual_cp_for_source(&lu, b"seed", Some("QABOB.GATEWAY"))
                .unwrap()
                .name,
            "GATEWAY"
        );
        assert!(virtual_cp_for_source(&lu, b"seed", Some("QAALICE.GATEWAY")).is_err());
        assert!(require_hosting_cp(&lu, None, None).is_err());
        assert_eq!(
            require_hosting_cp(&lu, Some(name("QABOB", "HOST")), None)
                .unwrap()
                .name,
            "HOST"
        );
        assert!(require_hosting_cp(&lu, Some(name("QAALICE", "HOST")), None).is_err());
        assert!(require_hosting_cp(&lu, Some(name("QABOB", "HOST")), Some("QABOB.OTHER")).is_err());
    }
}
