// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{Failure, FailureClass, Format, common, records};
use crate::images::{
    Descriptor, Kept, StageError, VerifiedOutput, analysis, builders, graph, outputs, publish,
    solve, supervise,
};
use serde_json::{Value, json};
use std::fmt::Write as _;

pub(super) fn encode(value: Value, format: Format) -> common::Result<Vec<u8>> {
    match format {
        Format::Json => {
            fn sorted(value: Value) -> Value {
                match value {
                    Value::Object(map) => Value::Object(
                        map.into_iter()
                            .collect::<std::collections::BTreeMap<_, _>>()
                            .into_iter()
                            .map(|(k, v)| (k, sorted(v)))
                            .collect(),
                    ),
                    Value::Array(items) => Value::Array(items.into_iter().map(sorted).collect()),
                    value => value,
                }
            }
            let mut bytes = serde_json::to_vec(&sorted(value)).map_err(|_| Failure::Protocol)?;
            bytes.push(b'\n');
            Ok(bytes)
        }
        Format::Table => {
            fn lines(value: &Value, indent: usize, text: &mut String) {
                match value {
                    Value::Object(map) => {
                        for (key, value) in map {
                            let pad = " ".repeat(indent);
                            if value.is_object() || value.is_array() {
                                let _ = writeln!(text, "{pad}{key}:");
                                lines(value, indent + 2, text);
                            } else {
                                let _ = writeln!(text, "{pad}{key}: {value}");
                            }
                        }
                    }
                    Value::Array(items) => {
                        for item in items {
                            let _ = writeln!(text, "{}-", " ".repeat(indent));
                            lines(item, indent + 2, text);
                        }
                    }
                    value => {
                        let _ = writeln!(text, "{}{value}", " ".repeat(indent));
                    }
                }
            }
            let mut text = String::new();
            lines(&value, 0, &mut text);
            Ok(text.into_bytes())
        }
    }
}

fn failure(f: Failure) -> &'static str {
    FailureClass::of(f).name()
}
fn dispatch(d: supervise::Dispatch) -> &'static str {
    match d {
        supervise::Dispatch::None => "none",
        supervise::Dispatch::Possible => "possible",
        supervise::Dispatch::Observed => "observed",
    }
}

pub(super) fn observation(o: &supervise::Observation) -> String {
    format!(
        "dispatch={}; exit={}; signal={}; cancellation_requested={}; completion_uncertain={}; cleanup_uncertain={}",
        dispatch(o.dispatch),
        o.exit_code
            .map_or_else(|| "unavailable".into(), |v| v.to_string()),
        o.signal
            .map_or_else(|| "unavailable".into(), |v| v.to_string()),
        o.cancellation_requested,
        o.completion_uncertain,
        o.cleanup_uncertain
    )
}
fn observed(o: &supervise::Observation) -> Value {
    json!({"failure":o.failure.map(failure),"dispatch":dispatch(o.dispatch),"exit_code":o.exit_code,"signal":o.signal,
        "cancellation_requested":o.cancellation_requested,"completion_uncertain":o.completion_uncertain,"cleanup_uncertain":o.cleanup_uncertain,
        "started_ns":o.started_ns,"finished_ns":o.finished_ns,"stdout_bytes":o.stdout_bytes,"stderr_bytes":o.stderr_bytes})
}
fn stage(e: &StageError) -> Value {
    json!({"failure":failure(e.failure),"observation":observed(&e.observation)})
}
fn cleanup(c: &std::result::Result<supervise::Observation, StageError>) -> Value {
    match c {
        Ok(o) => json!({"state":"observed","observation":observed(o)}),
        Err(e) => json!({"state":"failed","error":stage(e)}),
    }
}
fn session(s: &solve::SessionObservation) -> Value {
    json!({"operation_id":s.operation_id,"cleanup":cleanup(&s.cleanup),"residue":s.residue,"unresolved_owner":s.unresolved_owner})
}
fn verified(o: &VerifiedOutput) -> Value {
    let (files, bytes) = o.verified_counts();
    json!({"entry":o.entry().wire(),"root":o.root().wire(),"complete":o.closure_complete(),"verified_files":files,"verified_bytes":bytes,"stage":o.stage()})
}
pub(super) fn kept(k: &Kept) -> Value {
    json!({"operation_id":k.token.operation_id(),"entries":k.entries.iter().map(|e| e.wire()).collect::<Vec<_>>()})
}

fn ranges(ranges: &[analysis::Range]) -> Value {
    json!(ranges.iter().map(|r| json!({"start_line":r.start_line,"end_line":r.end_line,"start_column":r.start_column,"end_column":r.end_column})).collect::<Vec<_>>())
}
fn location(l: &analysis::Location) -> Value {
    match l {
        analysis::Location::Dockerfile(r) => json!({"kind":"dockerfile","ranges":ranges(r)}),
        analysis::Location::Inherited {
            parent_reference,
            parent_root,
            parent_platform,
            trigger_index,
            consuming_from,
        } => {
            json!({"kind":"inherited","parent_reference":parent_reference,"parent_root":parent_root,"parent_platform":parent_platform,"trigger_index":trigger_index,"consuming_from":ranges(consuming_from)})
        }
        analysis::Location::Unavailable => json!({"kind":"unavailable"}),
    }
}
fn role(r: analysis::Role) -> &'static str {
    match r {
        analysis::Role::Inheritance => "inheritance",
        analysis::Role::FileSource => "file-source",
    }
}
fn instruction(i: analysis::Instruction) -> &'static str {
    match i {
        analysis::Instruction::From => "from",
        analysis::Instruction::Copy => "copy",
        analysis::Instruction::RunMount => "run-mount",
    }
}
fn tag_origin(t: analysis::TagOrigin) -> &'static str {
    match t {
        analysis::TagOrigin::Declared => "declared",
        analysis::TagOrigin::Default => "default",
        analysis::TagOrigin::Absent => "absent",
    }
}
fn diagnostic(d: &graph::Diagnostic) -> Value {
    let subject = match d.subject {
        graph::Subject::Node(ordinal) => json!({"kind":"node","ordinal":ordinal}),
        graph::Subject::Source(ordinal) => json!({"kind":"source","ordinal":ordinal}),
        graph::Subject::Catalogs => json!({"kind":"catalogs"}),
    };
    json!({"subject":subject,"reason":d.reason,"location":location(&d.location),"cycle":d.cycle})
}

pub(super) fn graph(r: &graph::Resolution) -> Value {
    let nodes: Vec<_> = r.nodes.iter().map(|n| {
        let mut v = json!({"producer":n.producer,"platform":n.platform,"path":n.path,"snapshot_size":n.snapshot_size,"snapshot_digest":n.snapshot_digest,"resolution_id":n.resolution_id,"state":n.state.name()});
        if let graph::State::Pending(pending) = &n.state { v["pending"] = json!(pending); }
        v
    }).collect();
    let edges: Vec<_> = r.edges.iter().map(|e| {
        let target = match e.target { graph::Target::Node(ordinal) => json!({"kind":"node","ordinal":ordinal}), graph::Target::Source(ordinal) => json!({"kind":"source","ordinal":ordinal}) };
        json!({"source":e.source,"target":target,"role":role(e.role),"instruction":instruction(e.instruction),"tag_origin":tag_origin(e.tag_origin),"location":location(&e.location)})
    }).collect();
    json!({"request":{"environment":r.request.environment,"targets":r.request.targets,"platforms":r.request.platforms,"build_platform":r.request.build_platform,"staging":r.request.staging.name()},
        "catalog_id":r.catalog_id,"nodes":nodes,"edges":edges,
        "external_sources":r.external_sources.iter().map(|s| json!({"reference":s.reference,"platform":s.platform,"root":s.root.wire(),"registry":s.registry,"staging":s.staging.name()})).collect::<Vec<_>>(),
        "diagnostics":r.diagnostics.iter().map(diagnostic).collect::<Vec<_>>(),"complete":r.complete,"graph_id":r.graph_id})
}

fn ignore(i: &solve::IgnoreEntry) -> Value {
    match i {
        solve::IgnoreEntry::Absent => json!({"state":"absent"}),
        solve::IgnoreEntry::File { mode, size, digest } => {
            json!({"state":"file","mode":mode,"size":size,"digest":digest})
        }
    }
}
fn derived(d: &solve::DerivedInputProvenance) -> Value {
    let history = d.history_completion.as_ref().map(|h| json!({"protocol_version":h.protocol_version,"source_sha256":h.source_sha256,"convention":h.convention,"original_form":h.original_form,"original_entries":h.original_entries,"original_nonempty":h.original_nonempty,"layer_count":h.layer_count,"missing_history":h.missing_history,
        "added":h.added.iter().map(|a| json!({"history_ordinal":a.history_ordinal,"layer_ordinal":a.layer_ordinal,"layer":a.layer.wire(),"diff_id":a.diff_id,"entry_sha256":a.entry_sha256})).collect::<Vec<_>>()}));
    json!({"ordinal":d.ordinal,"original_reference":d.original_reference,"original_platform":d.original_platform,"original_root":d.original_root,"original_manifest":d.original_manifest.wire(),"original_config":d.original_config.wire(),"role":d.role,
        "uses":d.uses.iter().map(|u| json!({"role":role(u.role),"instruction":instruction(u.instruction),"tag_origin":tag_origin(u.tag_origin),"location":location(&u.location)})).collect::<Vec<_>>(),
        "derived_root":d.derived_root.wire(),"derived_manifest":d.derived_manifest.wire(),"derived_config":d.derived_config.wire(),"layers":d.layers.iter().map(Descriptor::wire).collect::<Vec<_>>(),"history_completion":history})
}
fn built(b: &solve::BuiltNode) -> Value {
    let builder = &b.builder;
    json!({"state":"built","context_id":b.context_id,"ignore":{"record":ignore(&b.ignore.record),"default_ignore":ignore(&b.ignore.default_ignore),"named_ignore":b.ignore.named_ignore.iter().map(|(k, v)| (k.clone(), ignore(v))).collect::<serde_json::Map<_, _>>()},
        "dockerfile_digest":b.dockerfile_digest,"bake_digest":b.bake_digest,"build_platform":b.build_platform,"generated_inputs_id":b.generated_inputs_id,"output":verified(&b.output),
        "frontend":b.frontend.as_ref().map(|f| json!({"reference":f.reference,"content":f.content,"reason":f.reason})),
        "derived_entries":b.derived_entries,"derived_bytes":b.derived_bytes,"derived_inputs":b.derived_inputs.iter().map(derived).collect::<Vec<_>>(),
        "builder":{"name":builder.name,"kind":builder.kind,"endpoint":builder.endpoint,"server_name":builder.server_name,"version":builder.version,"oci_worker":builder.oci_worker,"platforms":builder.platforms,"build_platform":builder.build_platform}})
}
fn node_outcome(o: &solve::NodeOutcome) -> Value {
    match o {
        solve::NodeOutcome::Built(b) => built(b),
        solve::NodeOutcome::Failed { class, check } => {
            json!({"state":"failed","class":failure(*class),"check":check.map(|c| c.name())})
        }
        solve::NodeOutcome::NotDispatched(reason) => {
            json!({"state":"not-dispatched","reason":reason.name()})
        }
    }
}
fn release(r: &solve::ReleaseOutcome) -> Value {
    match r {
        solve::ReleaseOutcome::None => json!({"state":"none"}),
        solve::ReleaseOutcome::Released => json!({"state":"released"}),
        solve::ReleaseOutcome::Unreleased(class) => {
            json!({"state":"unreleased","class":class.map(failure)})
        }
        solve::ReleaseOutcome::Failed(class) => json!({"state":"failed","class":failure(*class)}),
    }
}
fn write(o: solve::WriteOutcome) -> Value {
    json!({"state":o.name(),"class":records::Outcome::of_write(o).1.map(|c| c.name())})
}
fn cache(c: &solve::NodeCache) -> Value {
    json!({"no_cache":c.no_cache,"secret_freshness":c.secret_freshness.name(),
        "secrets":c.secrets.iter().map(|s| json!({"set":s.set,"key":s.key,"version":"unavailable"})).collect::<Vec<_>>(),
        "reads":c.reads.iter().map(|r| json!({"registry":r.registry,"reference":r.reference,"outcome":{"state":r.outcome.name(),"class":records::Outcome::of_read(r.outcome).1.map(|c| c.name())},"root":r.root.as_ref().map(Descriptor::wire),"imported":r.imported,"operation_id":r.operation_id,"session":r.session.as_ref().map(session),"release":release(&r.release)})).collect::<Vec<_>>(),
        "write":c.write.as_ref().map(|w| json!({"registry":w.registry,"mode":w.mode.name(),"export_root":w.export_root.as_ref().map(Descriptor::wire),"writer_reference":w.writer_reference,"outcome":write(w.outcome),"namespace_reference":w.namespace_reference,"promotion":w.promotion.map(write),"writer_session":w.writer_session.as_ref().map(session),"promotion_session":w.promotion_session.as_ref().map(session)}))})
}
fn target_outcome(o: &outputs::TargetOutcome) -> Value {
    match o {
        outputs::TargetOutcome::Retained(r) => {
            json!({"state":"retained","owner":r.owner,"location":r.location,"kind":r.kind,"root":r.root.wire(),"manifests":r.manifests.iter().map(|(p, d)| json!({"platform":p,"descriptor":d.wire()})).collect::<Vec<_>>(),"verified_files":r.verified_files,"verified_bytes":r.verified_bytes,"archive":r.archive.as_ref().map(|(d, s)| json!({"digest":d,"size":s})),"verification":r.verification,"verified_ns":r.verified_ns,"verified_at":r.verified_at,"cleanup":r.cleanup})
        }
        outputs::TargetOutcome::Loaded(l) => {
            json!({"state":"loaded","socket":l.socket,"store":l.store,"image_id":l.image_id,"reference":l.reference,"platform":l.platform})
        }
        outputs::TargetOutcome::CacheOnly => json!({"state":"cache-only"}),
        outputs::TargetOutcome::Unpublished(h) => match h {
            outputs::Handoff::Nodes(nodes) => {
                json!({"state":"unpublished","handoff":"nodes","nodes":nodes.iter().map(|n| json!({"platform":n.platform,"entry":n.entry.wire(),"root":n.root.wire()})).collect::<Vec<_>>()})
            }
            outputs::Handoff::Consumed { nodes } => {
                json!({"state":"unpublished","handoff":"consumed","nodes":nodes,"replacement":"publication-residue"})
            }
        },
        outputs::TargetOutcome::Failed {
            class,
            check,
            published,
        } => {
            json!({"state":"failed","class":failure(*class),"check":check.map(|c| c.name()),"published":published})
        }
        outputs::TargetOutcome::NotExported(reason) => {
            json!({"state":"not-exported","reason":reason.name()})
        }
    }
}
fn stop(s: &solve::Stop) -> Value {
    use solve::Stop;
    let name = match s {
        Stop::Success => "success",
        Stop::Quiescent => "quiescent",
        Stop::Stale(_) => "stale",
        Stop::BuilderAgreement => "builder-agreement",
        Stop::CacheAgreement => "cache-agreement",
        Stop::CacheWrite => "cache-write",
        Stop::NodeFailed => "node-failed",
        Stop::Cancelled => "cancelled",
        Stop::GraphRefused(_) => "graph-refused",
        Stop::ProbeFailed(_) => "probe-failed",
        Stop::Bound => "bound",
    };
    let mut result = json!({"state":name});
    match s {
        Stop::Stale(d) => {
            result["diagnostics"] = json!(d.iter().map(diagnostic).collect::<Vec<_>>())
        }
        Stop::GraphRefused(e) | Stop::ProbeFailed(e) => result["error"] = stage(e),
        _ => {}
    }
    result
}
pub(super) fn build(r: &solve::SolveReport) -> Value {
    json!({"build_platform":r.build_platform,"probe":r.probe.as_ref().map(session),"graph_sessions":r.graph_sessions.iter().map(session).collect::<Vec<_>>(),"resolution":r.resolution.as_ref().map(graph),
        "nodes":r.nodes.iter().map(|n| json!({"producer":n.producer,"platform":n.platform,"outcome":node_outcome(&n.outcome),"session":n.session.as_ref().map(session),"cache":n.cache.as_ref().map(cache)})).collect::<Vec<_>>(),
        "closures":r.closures.iter().map(verified).collect::<Vec<_>>(),"stop":stop(&r.stop),"node_sessions":r.node_sessions,"re_entries":r.re_entries,
        "targets":r.targets.iter().map(|t| json!({"target":t.target,"kind":t.kind,"outcome":target_outcome(&t.outcome),"session":t.session.as_ref().map(session),"residue":t.residue,"provenance":t.provenance,"provenance_reason":t.provenance_reason})).collect::<Vec<_>>(),
        "publications":r.publications.iter().map(publication).collect::<Vec<_>>(),"retained":r.retained.iter().map(kept).collect::<Vec<_>>(),"cache_complete":r.cache_complete})
}

fn server(s: &publish::ServerIdentity) -> Value {
    json!({"authority":s.authority,"transport":s.transport,"authentication":s.authentication})
}
fn tag(t: &publish::TagAssociation) -> Value {
    json!({"tag":t.tag,"root":t.root.wire()})
}
fn publication_outcome(o: &publish::PublicationOutcome) -> Value {
    use publish::PublicationOutcome;
    match o {
        PublicationOutcome::Published(p) => {
            json!({"state":"published","artifact_id":p.artifact_id,"predicate":p.predicate,"root":p.root.wire(),"endpoint":p.endpoint,"server":server(&p.server),"repository":p.repository,"association":p.association.wire(),
            "closure":p.closure.iter().map(|c| json!({"descriptor":c.descriptor.wire(),"role":c.role,"local":c.local,"endpoint":c.endpoint})).collect::<Vec<_>>(),"tag":p.tag.as_ref().map(tag),"observed_ns":p.observed_ns,"observed_at":p.observed_at,"method":p.method,"operation_id":p.operation_id,"auxiliary":p.auxiliary.iter().map(Descriptor::wire).collect::<Vec<_>>()})
        }
        PublicationOutcome::Failed { check, .. } => {
            json!({"state":"failed","class":super::publish::class(o).map(|c| c.name()),"check":check.map(|c| c.name())})
        }
        PublicationOutcome::Unknown(u) => {
            let class = super::publish::class(&PublicationOutcome::Failed {
                class: u.class,
                check: u.check,
            });
            json!({"state":"unknown","class":class.map(|c| c.name()),"check":u.check.map(|c| c.name()),"endpoint":u.endpoint,"server":server(&u.server),"repository":u.repository,"expected_root":u.expected_root.wire(),"tag":u.tag,"completion_uncertain":u.completion_uncertain,"cleanup_uncertain":u.cleanup_uncertain,"recovery":u.recovery,"local_content":u.local_content})
        }
        PublicationOutcome::Cancelled => json!({"state":"cancelled"}),
        PublicationOutcome::NotPublished(reason) => {
            json!({"state":"not-published","reason":reason.name()})
        }
    }
}
fn publication_release(r: &publish::PublicationRelease) -> Value {
    let class = match r {
        publish::PublicationRelease::Refused { class, .. }
        | publish::PublicationRelease::Failed { class, .. } => Some(failure(*class)),
        _ => None,
    };
    json!({"state":r.name(),"class":class,"residue":r.residue().map(|r| json!({"entry":r.entry.wire(),"root":r.root.wire(),"reason":r.reason}))})
}
pub(super) fn publication(p: &publish::PublicationReport) -> Value {
    json!({"target":p.target,"outcome":publication_outcome(&p.outcome),"release":publication_release(&p.release),"layout":p.layout.as_ref().map(|(e, d)| json!({"entry":e.wire(),"root":d.wire()})),"tag":p.tag.as_ref().map(tag),
        "staging":p.staging.iter().map(|s| json!({"operation":s.operation,"operation_id":s.operation_id,"counted_bytes":s.counted_bytes,"allowance_bytes":s.allowance_bytes})).collect::<Vec<_>>(),"sessions":p.sessions.iter().map(session).collect::<Vec<_>>(),
        "source":p.source.as_ref().map(|s| json!({"location":s.location,"kind":s.kind,"root":s.root.wire(),"verification":s.verification,"verified_files":s.verified_files,"verified_bytes":s.verified_bytes,"alternative":s.alternative})),"recovery":p.recovery})
}

fn projection(p: &records::Projection) -> Value {
    let commits: Vec<_> = p
        .commits
        .iter()
        .map(|c| {
            let (id, state) = match c {
                records::Commit::Unproved { artifact_id } => (artifact_id, "unproved"),
                records::Commit::Committed { artifact_id } => (artifact_id, "committed"),
                records::Commit::Abandoned { artifact_id, .. } => (artifact_id, "abandoned"),
            };
            let mut v = json!({"artifact_id":id,"state":state});
            if let records::Commit::Abandoned {
                failure_class: Some(class),
                ..
            } = c
            {
                v["failure_class"] = json!(class.name());
            }
            v
        })
        .collect();
    let publications: Vec<_> = p
        .publications
        .iter()
        .map(|(seq, d)| {
            let mut v = json!({"publication_seq":seq});
            match d {
                records::PublicationDisposition::Bound { artifact_id } => {
                    v["binding"] = json!("bound");
                    v["artifact_id"] = json!(artifact_id);
                }
                records::PublicationDisposition::Unbound { reason } => {
                    v["binding"] = json!("unbound");
                    v["reason"] = json!(reason.disposition.name());
                }
                records::PublicationDisposition::DispositionUnproved => {
                    v["binding"] = json!("disposition-unproved")
                }
                records::PublicationDisposition::Ambiguous {
                    ambiguous_seq,
                    settled,
                } => {
                    v["binding"] = json!("ambiguous");
                    v["ambiguous_seq"] = json!(ambiguous_seq);
                    let (state, id) = match settled {
                        records::Settled::Unsettled => ("unsettled", None),
                        records::Settled::AppendUnproved { artifact_id } => {
                            ("settled-append-unproved", Some(artifact_id))
                        }
                        records::Settled::Resolved { artifact_id } => {
                            ("settled", Some(artifact_id))
                        }
                    };
                    v["settlement"] = json!(state);
                    if let Some(id) = id {
                        v["artifact_id"] = json!(id);
                    }
                }
            }
            v
        })
        .collect();
    let targets: Vec<_> = p
        .targets
        .iter()
        .map(|t| {
            let mut v =
                json!({"logical_target":t.logical_target,"phase":t.phase,"outcome":t.outcome});
            if let Some(class) = &t.failure_class {
                v["failure_class"] = json!(class);
            }
            v
        })
        .collect();
    json!({"operation_id":p.operation_id,"commits":commits,"publications":publications,"targets":targets})
}
pub(super) fn index(i: &records::Index) -> Value {
    json!({"format_version":1,"operations":i.operations.iter().map(projection).collect::<Vec<_>>()})
}
pub(super) fn resumed(r: &records::Resumed, decision: bool) -> Value {
    let windows: Vec<_> = r
        .windows
        .iter()
        .map(|w| {
            let (id, state) = match w {
                records::WindowOutcome::Committed { artifact_id } => (artifact_id, "committed"),
                records::WindowOutcome::Abandoned { artifact_id } => (artifact_id, "abandoned"),
                records::WindowOutcome::Corrupt { artifact_id } => (artifact_id, "corrupt"),
                records::WindowOutcome::AlreadyTerminal { artifact_id } => {
                    (artifact_id, "already-terminal")
                }
            };
            json!({"artifact_id":id,"state":state})
        })
        .collect();
    json!({"operation_id":r.operation_id,"windows":windows,"completed":r.completed.iter().map(|s| json!({"format_version":1,"ambiguous_seq":s.ambiguous_seq,"artifact_id":s.artifact_id,"retention_operation_id":s.retention_operation_id,"retention_seq":s.retention_seq})).collect::<Vec<_>>(),"left_open":r.left_open,"projection":projection(&r.projection),"tool_identities_changed":r.tool_identities_changed,"requires_explicit_decision":decision})
}
pub(super) fn settled(s: &records::SettleOutcome) -> Value {
    let (id, state) = match s {
        records::SettleOutcome::Settled { artifact_id } => (artifact_id, "settled"),
        records::SettleOutcome::Completed { artifact_id } => (artifact_id, "completed"),
        records::SettleOutcome::Refused { artifact_id } => (artifact_id, "refused"),
    };
    json!({"state":state,"artifact_id":id})
}
pub(super) fn record_table(r: &records::Record) -> Vec<u8> {
    format!(
        "artifact_id: {}\ncreated_at: {}\nbuild_operation_id: {}\ntarget: {}\nroot: {}\n",
        r.artifact_id, r.created_at, r.build_operation_id, r.target.logical_target, r.root.digest
    )
    .into_bytes()
}

pub(super) fn builder(o: &builders::Outcome) -> Value {
    let steps: Vec<_> = o.steps.iter().map(|s| {
        let t = &s.transport;
        let transport = json!({"failure":t.failure.map(|f| f.as_str()),"dispatched":t.dispatched,"remote_status":t.remote_status,"remote_signal":t.remote_signal.as_ref().map(|s| &s.name),"possible_staging_residue":t.possible_staging_residue,"unresolved_input":t.unresolved_input});
        let upload = s.upload.as_ref().map(|u| json!({"failure":u.failure.map(|f| f.as_str()),"launcher_dispatched":u.launcher_dispatched,"mutation_dispatched":u.mutation_dispatched,"transfer_complete":u.transfer_complete,"remote_status":u.remote_status,"possible_staging_residue":u.possible_staging_residue,"unresolved_session":u.unresolved_session,"temporary":u.temporary,"destination":u.destination}));
        json!({"action":s.action,"step":s.step,"transport":transport,"receipt":s.receipt.as_ref().map(|r| r.wire()),"upload":upload,"local_failure":s.local_failure.map(failure)})
    }).collect();
    let endpoint = o.endpoint.as_ref().map(|e| {
        let result = match &e.result {
            Ok(b) => json!({"state":"succeeded","discovery":observed(&b.discovery),"capabilities":{"version":b.capabilities.version,"oci_worker":b.capabilities.oci_worker,"platforms":b.capabilities.platforms,"build_platform":b.capabilities.build_platform},"output":b.output.as_ref().map(verified)}),
            Err(error) => json!({"state":"failed","error":stage(error)}),
        };
        json!({"result":result,"cleanup":cleanup(&e.cleanup),"protected":{"session":e.protected.session,"residue":e.protected.residue,"unresolved_owner":e.protected.unresolved_owner},"release":e.release.as_ref().map(kept)})
    });
    json!({"result":o.result.map_or_else(failure, |()| "succeeded"),"record":o.record,"steps":steps,"endpoint":endpoint,"ownership_uncertain":o.ownership_uncertain})
}
