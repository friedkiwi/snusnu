//! Route-scoped SNASVCMG sessions on an EE user RTP connection.

use std::io;

use router_core::{
    hpr_external_management::{ExternalCpManagementResponder, ExternalManagementPhase},
    hpr_session_address::{RtpAssociationScope, RtpObservation},
    session::QualifiedName,
};

const MAX_LEGS: usize = 64;

pub(crate) struct VerifiedExternalRoute {
    pub(crate) scope: RtpAssociationScope,
    pub(crate) peer_cp: QualifiedName,
    pub(crate) target_lu: QualifiedName,
    pub(crate) target_cp: QualifiedName,
    pub(crate) attachment_id: String,
    pub(crate) assigned_sa: u64,
}

struct Leg {
    target_lu: QualifiedName,
    target_cp: QualifiedName,
    attachment_id: String,
    responder: ExternalCpManagementResponder,
}

struct Pending {
    index: usize,
    candidate: ExternalCpManagementResponder,
    replies: Vec<Vec<u8>>,
    next_reply: usize,
    first_bind: bool,
}

#[derive(Default)]
pub(crate) struct ExternalManagementRoutes {
    legs: Vec<Leg>,
    pending: Option<Pending>,
}

impl ExternalManagementRoutes {
    /// Returns true when this BIU belongs to an external management leg.
    /// A preview remains uncommitted until every response is accepted by RTP.
    pub(crate) fn receive(
        &mut self,
        observation: RtpObservation,
        bytes: &[u8],
        start: Option<VerifiedExternalRoute>,
    ) -> io::Result<bool> {
        if self.pending.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "external CP management response pending",
            ));
        }
        let index = self
            .legs
            .iter()
            .position(|leg| leg.responder.owns(observation, bytes));
        let (index, created) = match index {
            Some(index) => (index, false),
            None => {
                let Some(route) = start else {
                    return Ok(false);
                };
                if self.legs.len() >= MAX_LEGS {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "external CP management session limit reached",
                    ));
                }
                if self
                    .legs
                    .iter()
                    .any(|leg| leg.responder.scope() == route.scope)
                {
                    return Err(invalid("conflicting external CP BIND on user RTP scope"));
                }
                let responder = ExternalCpManagementResponder::new(
                    route.scope,
                    route.peer_cp,
                    route.target_cp.clone(),
                    route.assigned_sa,
                )
                .map_err(|error| invalid(format!("external CP route: {error:?}")))?;
                self.legs.push(Leg {
                    target_lu: route.target_lu,
                    target_cp: route.target_cp,
                    attachment_id: route.attachment_id,
                    responder,
                });
                (self.legs.len() - 1, true)
            }
        };
        let leg = &self.legs[index];
        let (candidate, replies) = match leg.responder.preview_ingress(observation, bytes) {
            Ok(preview) => preview,
            Err(error) => {
                if created {
                    self.legs.pop();
                }
                return Err(invalid(format!("external CP management BIU: {error:?}")));
            }
        };
        if replies.is_empty() {
            self.legs[index].responder = candidate;
        } else {
            self.pending = Some(Pending {
                index,
                first_bind: leg.responder.phase() == ExternalManagementPhase::AwaitBind,
                candidate,
                replies,
                next_reply: 0,
            });
        }
        Ok(true)
    }

    /// Send as many queued replies as RTP accepts. Returns a scope once the
    /// first positive management BIND response is fully committed.
    pub(crate) fn pump(
        &mut self,
        mut send: impl FnMut(RtpAssociationScope, &[u8]) -> io::Result<bool>,
    ) -> io::Result<Option<RtpAssociationScope>> {
        let Some(pending) = self.pending.as_mut() else {
            return Ok(None);
        };
        while let Some(reply) = pending.replies.get(pending.next_reply) {
            if !send(pending.candidate.scope(), reply)? {
                return Ok(None);
            }
            pending.next_reply += 1;
        }
        let pending = self.pending.take().unwrap();
        let scope = pending.first_bind.then_some(pending.candidate.scope());
        self.legs[pending.index].responder = pending.candidate;
        Ok(scope)
    }

    pub(crate) fn retain(
        &mut self,
        mut valid: impl FnMut(&QualifiedName, &QualifiedName, &str, RtpAssociationScope) -> bool,
    ) {
        // The pending response is tied to a vector index. Finish it or drop
        // it before compacting the vector.
        if let Some(pending) = self.pending.as_ref() {
            let leg = &self.legs[pending.index];
            if valid(
                &leg.target_lu,
                &leg.target_cp,
                &leg.attachment_id,
                leg.responder.scope(),
            ) {
                return;
            }
            self.pending = None;
        }
        self.legs.retain(|leg| {
            valid(
                &leg.target_lu,
                &leg.target_cp,
                &leg.attachment_id,
                leg.responder.scope(),
            )
        });
    }
}

fn invalid(reason: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason.into())
}
