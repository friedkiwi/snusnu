//! One qualified outbound CPSVCMG RTP setup for the reciprocal CP-CP session.
//!
//! Identifiers and ANR labels come from the active, validated EE XID3 pair.
//! The caller owns UDP peer/SAP validation, TCID allocation, retransmission,
//! STATUS+CIE processing, and the CP-CP BIND transaction.

use crate::{
    fid2_bind::BindClass,
    hpr_control_bootstrap::{encode_network_name_component, HprControlBootstrap},
    hpr_fid5::Fid5WholeBiu,
};

const ASSIGNOR: u64 = 1 << 63;
const RESERVED: u64 = 1 << 62;
const CPSVCMG: [u8; 7] = [0xc3, 0xd7, 0xe2, 0xe5, 0xc3, 0xd4, 0xc7];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundSetupError {
    InvalidTg,
    InvalidTcid,
    InvalidIdentity,
    InvalidBind,
    TooLarge,
}

/// Encode the first RTP NLP, beginning at NHDR, with BSN zero and the whole
/// FID5 CPSVCMG BIND as its first complete message. `origin_tcid` is locally
/// allocated and has the assignor bit set. No EE UI header is included.
pub fn encode_cp_setup(
    bootstrap: &HprControlBootstrap,
    tg_number: u8,
    origin_tcid: u64,
    bind: &[u8],
) -> Result<Vec<u8>, OutboundSetupError> {
    if tg_number == 0 {
        return Err(OutboundSetupError::InvalidTg);
    }
    if origin_tcid & (ASSIGNOR | RESERVED) != ASSIGNOR || origin_tcid & !(ASSIGNOR | RESERVED) == 0
    {
        return Err(OutboundSetupError::InvalidTcid);
    }
    let fid5 = Fid5WholeBiu::parse_complete(bind).map_err(|_| OutboundSetupError::InvalidBind)?;
    let identity = fid5
        .classify_bind()
        .map_err(|_| OutboundSetupError::InvalidBind)?
        .ok_or(OutboundSetupError::InvalidBind)?;
    if identity.class
        != (BindClass::Management {
            mode: "CPSVCMG".into(),
        })
        || identity.plu != bootstrap.local.cp.to_string()
        || identity.slu != bootstrap.peer.cp.to_string()
    {
        return Err(OutboundSetupError::InvalidBind);
    }
    let local_netid = component(&bootstrap.local.cp.netid)?;
    let local_cp = component(&bootstrap.local.cp.name)?;
    let peer_netid = component(&bootstrap.peer.cp.netid)?;
    let peer_cp = component(&bootstrap.peer.cp.name)?;

    let mut qualifier = vec![0, 0x05, 0x80, 0];
    append_cv(&mut qualifier, 0x03, &local_netid)?;
    append_cv(&mut qualifier, 0x00, &local_cp)?;
    append_cv(&mut qualifier, 0x26, &bootstrap.local.tower.cp_nce_label)?;
    append_cv(&mut qualifier, 0x39, &bootstrap.local.tower.cp_nce_instance)?;
    // The final nested CV39's word padding belongs to parent CV05.
    qualifier[0] = u8::try_from(qualifier.len()).map_err(|_| OutboundSetupError::TooLarge)?;
    align4(&mut qualifier);

    let mut cs = vec![0, 0x0d, 1, 1, 0x98, 0, 0, 0];
    let mut topic = vec![0];
    topic.extend_from_slice(&CPSVCMG);
    append_cv(&mut cs, 0x28, &topic)?;
    append_cv(&mut cs, 0x03, &peer_netid)?;
    append_cv(&mut cs, 0x00, &peer_cp)?;
    append_cv(&mut cs, 0x39, &bootstrap.peer.tower.cp_nce_instance)?;
    finish_segment(&mut cs)?;

    let mut si = vec![0, 0x14, 0, 0];
    let mut cv83 = vec![0xa8, 0];
    cv83.extend_from_slice(&u32::from(bootstrap.max_packet_size).to_be_bytes());
    cv83.extend_from_slice(&bootstrap.local.tower.path_switch_time_ms.to_be_bytes());
    cv83.extend_from_slice(&180u32.to_be_bytes());
    cv83.extend_from_slice(&[
        u8::try_from(4 + bootstrap.peer.link_label.len())
            .map_err(|_| OutboundSetupError::TooLarge)?,
        0x67,
        u8::try_from(2 + bootstrap.peer.link_label.len())
            .map_err(|_| OutboundSetupError::TooLarge)?,
        0,
    ]);
    cv83.extend_from_slice(&bootstrap.peer.link_label);
    append_cv(&mut si, 0x83, &cv83)?;

    let mut fq_local = local_netid;
    fq_local.push(0x4b);
    fq_local.extend_from_slice(&local_cp);
    let mut descriptor = vec![
        0,
        0x80,
        tg_number,
        u8::try_from(fq_local.len()).map_err(|_| OutboundSetupError::TooLarge)?,
    ];
    descriptor.extend_from_slice(&fq_local);
    descriptor.push(0x21);
    descriptor.extend_from_slice(&[0; 4]);
    descriptor[0] = u8::try_from(descriptor.len()).map_err(|_| OutboundSetupError::TooLarge)?;
    let mut cv85 = vec![0, 1, 0, 0x46];
    cv85.extend_from_slice(&descriptor);
    cv85[2] = u8::try_from(cv85.len() - 2).map_err(|_| OutboundSetupError::TooLarge)?;
    append_cv(&mut si, 0x85, &cv85)?;
    finish_segment(&mut si)?;

    // Captured Base ARB initial operating range: 4 ms nominal, 40 ms upper,
    // conservative 4.3 Mbps reverse capacity, 276 us transmission time.
    let arb: [u8; 20] = [
        5, 0x22, 0, 0, 0, 0, 0x0f, 0xa0, 0, 0, 0x9c, 0x40, 0, 0, 0x10, 0xcc, 0, 0, 1, 0x14,
    ];
    let mut thdr = Vec::new();
    thdr.extend_from_slice(&origin_tcid.to_be_bytes());
    thdr.extend_from_slice(&[0x7c, 0x0c, 0, 0]); // SOM/EOM, qualifier and optional segments.
    thdr.extend_from_slice(&(bind.len() as u32).to_be_bytes());
    thdr.extend_from_slice(&0u32.to_be_bytes()); // Initial byte sequence number.
    thdr.extend_from_slice(&qualifier);
    thdr.extend_from_slice(&cs);
    thdr.extend_from_slice(&si);
    thdr.extend_from_slice(&arb);
    if !thdr.len().is_multiple_of(4) || thdr.len() / 4 > u16::MAX as usize {
        return Err(OutboundSetupError::TooLarge);
    }
    let data_offset_words = (thdr.len() / 4) as u16;
    thdr[10..12].copy_from_slice(&data_offset_words.to_be_bytes());
    let mut nlp = vec![0xc6, 8]; // Network priority NHDR, optional segment present.
    nlp.extend_from_slice(&bootstrap.peer.tower.cp_nce_label);
    nlp.extend_from_slice(&[0xff, 0]);
    nlp.extend_from_slice(&thdr);
    nlp.extend_from_slice(bind);
    if nlp.len() > usize::from(bootstrap.max_packet_size) {
        return Err(OutboundSetupError::TooLarge);
    }
    Ok(nlp)
}

fn component(value: &str) -> Result<Vec<u8>, OutboundSetupError> {
    encode_network_name_component(value).map_err(|_| OutboundSetupError::InvalidIdentity)
}

fn append_cv(parent: &mut Vec<u8>, key: u8, value: &[u8]) -> Result<(), OutboundSetupError> {
    parent.push(u8::try_from(value.len() + 2).map_err(|_| OutboundSetupError::TooLarge)?);
    parent.push(key);
    parent.extend_from_slice(value);
    align4(parent);
    Ok(())
}

fn align4(value: &mut Vec<u8>) {
    while !value.len().is_multiple_of(4) {
        value.push(0);
    }
}

fn finish_segment(segment: &mut Vec<u8>) -> Result<(), OutboundSetupError> {
    align4(segment);
    segment[0] = u8::try_from(segment.len() / 4).map_err(|_| OutboundSetupError::TooLarge)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        hpr_control_bootstrap::ControlAdvertisement,
        hpr_cp_initiator::ReciprocalCpSession,
        hpr_cv61::{ArbMode, ControlFlowsTower},
        hpr_rtp::RtpPacket,
        hpr_rtp_setup::RtpSetupTopic,
        hpr_switching_path::validate_inbound_switching_path,
        session::QualifiedName,
        ConnectionGeneration,
    };

    fn advertisement(
        cp: &str,
        node_id: u8,
        link: &[u8],
        label: &[u8],
        instance: [u8; 4],
    ) -> ControlAdvertisement {
        ControlAdvertisement {
            cp: cp.parse::<QualifiedName>().unwrap(),
            node_id: [0, 0, 0, node_id],
            hpr_sap: 4,
            link_label: link.to_vec(),
            tower: ControlFlowsTower {
                max_send_packet_size: 1461,
                path_switch_time_ms: 60_000,
                mobile: false,
                multilink_tg: false,
                arb_mode: ArbMode::Base,
                cp_nce_instance: instance,
                route_setup_nce_instance: instance,
                cp_nce_label: label.to_vec(),
                route_setup_nce_label: label.to_vec(),
            },
        }
    }

    #[test]
    fn reciprocal_cp_setup_is_valid_from_live_guest_perspective() {
        let local = advertisement(
            "SNUSNU.SVC",
            2,
            &[0x80, 0x80],
            &[0xa4, 0x80],
            [0xff, 0xf2, 0xc4, 0x80],
        );
        let guest = advertisement("SOLNET.SNAB", 1, &[0x80, 2], &[0xa4, 0], [0, 0, 0, 7]);
        let generation = ConnectionGeneration::new(1).unwrap();
        let bootstrap = HprControlBootstrap::new(generation, local.clone(), guest.clone()).unwrap();
        let bind = ReciprocalCpSession::new(bootstrap.clone(), 0x0102_0304_0506_0708).unwrap();
        let wire = encode_cp_setup(
            &bootstrap,
            1,
            ASSIGNOR | 0x1234,
            bind.prepare_bind().unwrap(),
        )
        .unwrap();
        let packet = RtpPacket::parse(&wire).unwrap();
        assert_eq!(packet.data, bind.prepare_bind().unwrap());
        assert_eq!(packet.byte_sequence_number, 0);
        assert!(packet.start_of_message && packet.end_of_message);
        assert_eq!(packet.tcid, ASSIGNOR | 0x1234);
        let guest_view = HprControlBootstrap::new(generation, guest, local).unwrap();
        let path =
            validate_inbound_switching_path(packet, &guest_view, 1, &RtpSetupTopic::CpSvcMg, None)
                .unwrap();
        assert_eq!(path.peer_nce_label, [0xa4, 0x80]);
        assert_eq!(path.priority, 3);
        let segments = packet.optional_segments().unwrap();
        assert_eq!(
            segments
                .iter()
                .map(|segment| segment.key)
                .collect::<Vec<_>>(),
            [0x0d, 0x14, 0x22]
        );
    }
}
