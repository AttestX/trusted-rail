//! An OpenShell supervisor middleware. OpenShell hands it every HTTP request a
//! sandbox makes to the selected hosts; it asks the ledger, which decides
//! against the sandbox's mandate and records the decision. Only an allow
//! passes: a sandbox without a mandate, a body that cannot be read and any
//! error are all refusals.
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use openshell_core::extension_protocol::{
    ExtensionFamily, http_hooks_middleware_metadata, validate_gateway_metadata,
};
use openshell_core::middleware::{
    HttpRequestHookResultStream, HttpResponseHookResultStream, WebSocketResponseStream,
};
use openshell_core::proto::middleware::v1::http_hooks_server::{HttpHooks, HttpHooksServer};
use openshell_core::proto::middleware::v1::supervisor_middleware_server::{
    SupervisorMiddleware, SupervisorMiddlewareServer,
};
use openshell_core::proto::{
    HttpBodyMode, HttpBodyUnavailableReason, HttpContinue, HttpDenial, HttpInspect,
    HttpPreflightResult, HttpRequestEvaluation, HttpRequestHookEvent, HttpRequestHookPreflight,
    HttpRequestHookResult, HttpRequestResult, HttpResponseHookEvent, HttpUnchanged,
    HttpWholeBodyMode, HttpWholeBodyResult, MiddlewareBinding, MiddlewareDescribeRequest,
    MiddlewareDiagnostics, MiddlewareManifest, SupervisorMiddlewareOperation,
    SupervisorMiddlewarePhase, ValidateConfigRequest, ValidateConfigResponse,
    WebSocketSessionEvent, http_inspect, http_preflight_result, http_request_hook_event,
    http_request_hook_result, http_whole_body_result,
};
use serde_json::json;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{Stream, StreamExt};
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use trusted_contracts::ExecutionIdentity;
use trusted_rail::action::{self, HttpRequest};
use trusted_rail::rego::{
    decode_batch_public_values, engine_profile, evaluate_witness, policy_digest,
};
use trusted_rail::{Decision, DecisionRecord, PolicyBundle};
use trusted_rail_ledger::{Attempt, Ledger, ProofVerifier};

const NAME: &str = "attestx/trusted-rail";
/// How long a decision stays valid for whoever acts on its record.
const VALIDITY_SECONDS: u64 = 60;
const MAX_PAYLOAD_BYTES: u64 = 256 * 1024;
const MAX_GRPC_MESSAGE_BYTES: usize = 4 * 1024 * 1024 + 512 * 1024;

#[derive(Debug, Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Serve the middleware.
    Serve {
        #[arg(long, default_value = "127.0.0.1:50061")]
        bind: SocketAddr,
        #[command(flatten)]
        store: Store,
        /// One `<sandbox name>.json` per sandbox: `{"modules": {name: rego},
        /// "data": {...}, "state": {...}}`. `state` is where a new chain
        /// starts; leave it out for a mandate that keeps none.
        #[arg(long)]
        mandates: PathBuf,
    },
    /// Show where a sandbox's chain stands and check its unproven decisions
    /// by running them as the proof guest would.
    Chain {
        #[command(flatten)]
        store: Store,
        #[arg(long)]
        sandbox: String,
    },
}

#[derive(Debug, clap::Args)]
struct Store {
    /// The ledger file. Its directory must be private to this user.
    #[arg(long)]
    ledger: PathBuf,
    /// The OpenShell workspace the sandboxes belong to.
    #[arg(long, default_value = "default")]
    workspace: String,
    /// This node's name in the execution identity.
    #[arg(long, default_value = "local")]
    node: String,
}

/// No proof system is wired in yet, so no receipt is ever accepted.
struct NoVerifier;
impl ProofVerifier for NoVerifier {
    fn verify(&self, _public_values: &[u8], _receipt: &[u8]) -> trusted_rail::Result<()> {
        Err(trusted_rail::Error::Unsupported)
    }
}

impl Store {
    fn open(&self) -> Result<Ledger, String> {
        Ledger::open(&self.ledger, Arc::new(NoVerifier))
            .map_err(|error| format!("{}: {error}", self.ledger.display()))
    }

    /// A mandate belongs to a sandbox name, which the operator assigns, so a
    /// sandbox that is recreated under its name keeps what it has spent. The
    /// instance id goes into each request's context instead.
    fn execution(&self, workspace: &str, sandbox: &str) -> Result<ExecutionIdentity, String> {
        serde_json::from_value(json!({
            "namespace": workspace, "workload": sandbox, "allocation_id": sandbox,
            "lease_id": "openshell", "generation": 1, "node_id": self.node,
        }))
        .map_err(|error| error.to_string())
    }
}

fn mandate(path: &Path) -> Result<(PolicyBundle, Option<serde_json::Value>), String> {
    let fail = |error: &dyn std::fmt::Display| format!("{}: {error}", path.display());
    let file: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).map_err(|e| fail(&e))?)
            .map_err(|e| fail(&e))?;
    let mut policy = PolicyBundle {
        policy: serde_json::from_value(
            json!({"issuer": "operator", "policy_id": "mandate", "version": 1, "sha256": ""}),
        )
        .map_err(|e| fail(&e))?,
        engine: engine_profile(),
        modules: serde_json::from_value(file["modules"].clone()).map_err(|e| fail(&e))?,
        data: file["data"].clone(),
    };
    policy.policy.sha256 = policy_digest(&policy).map_err(|e| fail(&e))?;
    Ok((policy, file.get("state").cloned()))
}

/// Gives every sandbox named in `directory` its mandate: a new one starts its
/// chain, a known one keeps its state and takes the mandate as it now reads.
fn load_mandates(ledger: &Ledger, store: &Store, directory: &Path) -> Result<Vec<String>, String> {
    let mut sandboxes = Vec::new();
    for entry in
        std::fs::read_dir(directory).map_err(|e| format!("{}: {e}", directory.display()))?
    {
        let path = entry.map_err(|e| e.to_string())?.path();
        let Some(name) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(".json"))
        else {
            continue;
        };
        let (policy, state) = mandate(&path)?;
        let execution = store.execution(&store.workspace, name)?;
        let result = match ledger.head(&execution) {
            Ok(_) => ledger.set_policy(&execution, &policy),
            Err(_) => ledger.activate(&execution, &policy, state.as_ref()),
        };
        result.map_err(|error| format!("{}: {error}", path.display()))?;
        sandboxes.push(format!("{name}={}", policy.policy.sha256));
    }
    sandboxes.sort();
    Ok(sandboxes)
}

#[derive(Clone)]
struct Rail {
    ledger: Arc<Ledger>,
    store: Arc<Store>,
}

/// The request head OpenShell observed, kept until the body arrives.
struct Head {
    preflight: HttpRequestHookPreflight,
}

impl Rail {
    fn decide(&self, head: &Head, body: &[u8]) -> Result<(), MiddlewareDiagnostics> {
        let started = Instant::now();
        // The ledger write is a short blocking call.
        let outcome = tokio::task::block_in_place(|| self.evaluate(head, body));
        let target = head
            .preflight
            .request
            .as_ref()
            .and_then(|r| r.target.as_ref());
        let (method, host, path) = target.map_or(("", "", ""), |t| (&t.method, &t.host, &t.path));
        let sandbox = head
            .preflight
            .context
            .as_ref()
            .map_or("", |c| c.sandbox.as_str());
        let (verdict, reasons, root) = match &outcome {
            Ok(record) if record.decision == Decision::Allow => (
                "allow",
                record.reason_codes.join(","),
                record.next_state_root.as_str(),
            ),
            Ok(record) => (
                "deny",
                record.reason_codes.join(","),
                record.next_state_root.as_str(),
            ),
            Err(code) => ("deny", code.clone(), ""),
        };
        println!(
            "decision={verdict} reasons={reasons} sandbox={sandbox} {method} {host}{path} body_bytes={} state_root={:.12} micros={}",
            body.len(),
            root,
            started.elapsed().as_micros()
        );
        let refused = |code: &str| MiddlewareDiagnostics {
            reason: format!("refused by the mandate: {code}"),
            reason_code: code.into(),
            ..Default::default()
        };
        match outcome {
            Ok(record) if record.decision == Decision::Allow => Ok(()),
            Ok(record) => Err(refused(
                record.reason_codes.first().map_or("denied", String::as_str),
            )),
            Err(code) => Err(refused(&code)),
        }
    }

    /// The recorded decision, or the reason no decision could be made.
    fn evaluate(&self, head: &Head, body: &[u8]) -> Result<DecisionRecord, String> {
        let preflight = &head.preflight;
        let target = preflight
            .request
            .as_ref()
            .and_then(|request| request.target.as_ref())
            .ok_or("no_target")?;
        let context = preflight.context.as_ref().ok_or("no_context")?;
        if context.workspace != self.store.workspace || context.request_id.is_empty() {
            return Err("unknown_sandbox".into());
        }
        let binary = context
            .originating_process
            .as_ref()
            .map_or("", |process| process.binary.as_str());
        let action = action::http_request(&HttpRequest {
            method: &target.method,
            scheme: &target.scheme,
            host: &target.host,
            port: u16::try_from(target.port).map_err(|_| "bad_port")?,
            path: &target.path,
            query: &target.query,
            binary: if binary.is_empty() { "unknown" } else { binary },
            body,
        })
        .map_err(|_| "malformed_request")?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "clock")?
            .as_secs();
        let attempt = Attempt {
            execution: self
                .store
                .execution(&context.workspace, &context.sandbox)
                .map_err(|_| "bad_identity")?,
            principal: context.sandbox.clone(),
            action_id: context.request_id.clone(),
            context: json!({"sandbox_id": context.sandbox_id}),
            evaluated_at_unix: now,
            validity: serde_json::from_value(
                json!({"not_before": now, "expires_at": now + VALIDITY_SECONDS}),
            )
            .map_err(|_| "bad_validity")?,
        };
        self.ledger
            .decide(action, attempt)
            .map_err(|error| match error {
                trusted_rail::Error::Rejected => "no_mandate".into(),
                trusted_rail::Error::Conflict => "repeated_request".into(),
                other => format!("not_decided: {other}"),
            })
    }

    fn preflight(&self, preflight: HttpRequestHookPreflight) -> (Option<Head>, Reply) {
        let bodyless = preflight.declared_body_bytes == Some(0)
            || preflight
                .unavailable_body_modes
                .iter()
                .any(|mode| mode.reason == HttpBodyUnavailableReason::Bodyless as i32);
        let whole = preflight
            .permitted_body_modes
            .contains(&(HttpBodyMode::WholeBody as i32));
        let limit = preflight
            .limits
            .map_or(0, |limits| limits.max_whole_body_bytes)
            .min(MAX_PAYLOAD_BYTES);
        let head = Head { preflight };
        if bodyless {
            let reply = match self.decide(&head, b"") {
                Ok(()) => Reply::Continue,
                Err(diagnostics) => Reply::Deny(diagnostics),
            };
            return (None, reply);
        }
        if !whole || limit == 0 {
            // Never pass a body that could not be read.
            return (
                None,
                Reply::Deny(MiddlewareDiagnostics {
                    reason: "the mandate check cannot read this body".into(),
                    reason_code: "cannot_inspect".into(),
                    ..Default::default()
                }),
            );
        }
        (Some(head), Reply::Inspect(limit))
    }
}

enum Reply {
    Continue,
    Inspect(u64),
    Unchanged,
    Deny(MiddlewareDiagnostics),
}

impl From<Reply> for HttpRequestHookResult {
    fn from(reply: Reply) -> Self {
        use http_request_hook_result::Result as Wire;
        let preflight = |decision| {
            Wire::PreflightResult(HttpPreflightResult {
                decision: Some(decision),
                ..Default::default()
            })
        };
        let result = match reply {
            Reply::Continue => preflight(http_preflight_result::Decision::ContinueWithoutBody(
                HttpContinue {},
            )),
            Reply::Inspect(max_body_bytes) => {
                preflight(http_preflight_result::Decision::Inspect(HttpInspect {
                    mode: Some(http_inspect::Mode::WholeBody(HttpWholeBodyMode {
                        max_body_bytes,
                    })),
                }))
            }
            Reply::Unchanged => Wire::WholeBodyResult(HttpWholeBodyResult {
                body: Some(http_whole_body_result::Body::Unchanged(HttpUnchanged {})),
                ..Default::default()
            }),
            Reply::Deny(diagnostics) => Wire::Deny(HttpDenial {
                diagnostics: Some(diagnostics),
            }),
        };
        Self {
            result: Some(result),
        }
    }
}

fn request_stream<S>(rail: Rail, mut events: S) -> HttpRequestHookResultStream
where
    S: Stream<Item = Result<HttpRequestHookEvent, Status>> + Send + Unpin + 'static,
{
    let (sender, receiver) = mpsc::channel(4);
    tokio::spawn(async move {
        use http_request_hook_event::Event;
        let mut head = None;
        while let Some(next) = events.next().await {
            let reply = match next.map(|event| event.event) {
                Ok(Some(Event::Preflight(preflight))) => {
                    let (kept, reply) = rail.preflight(preflight);
                    head = kept;
                    Some(Ok(reply))
                }
                Ok(Some(Event::Begin(_))) => None,
                Ok(Some(Event::WholeBody(body))) => Some(match head.take() {
                    Some(head) => Ok(match rail.decide(&head, &body.data) {
                        Ok(()) => Reply::Unchanged,
                        Err(diagnostics) => Reply::Deny(diagnostics),
                    }),
                    None => Err(Status::invalid_argument("body without a preflight")),
                }),
                Ok(Some(Event::SessionEnd(_))) => break,
                Ok(_) => Some(Err(Status::invalid_argument("unexpected HTTP event"))),
                Err(error) => Some(Err(error)),
            };
            if let Some(reply) = reply {
                let failed = reply.is_err();
                if sender.send(reply.map(Into::into)).await.is_err() || failed {
                    return;
                }
            }
        }
    });
    Box::pin(ReceiverStream::new(receiver)) as Pin<Box<_>>
}

#[tonic::async_trait]
impl SupervisorMiddleware for Rail {
    type EvaluateWebSocketSessionStream = WebSocketResponseStream;

    async fn describe(
        &self,
        request: Request<MiddlewareDescribeRequest>,
    ) -> Result<Response<MiddlewareManifest>, Status> {
        let manifest = MiddlewareManifest {
            name: NAME.into(),
            service_version: env!("CARGO_PKG_VERSION").into(),
            bindings: vec![MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                max_payload_bytes: MAX_PAYLOAD_BYTES,
                ..Default::default()
            }],
            expected_audience: String::new(),
            extension: Some(http_hooks_middleware_metadata(
                NAME,
                openshell_core::VERSION,
            )),
        };
        validate_gateway_metadata(
            ExtensionFamily::SupervisorMiddleware,
            NAME,
            manifest.extension.as_ref(),
            request.into_inner().gateway,
        )
        .map_err(|error| Status::failed_precondition(error.to_string()))?;
        Ok(Response::new(manifest))
    }

    async fn validate_config(
        &self,
        _request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        Ok(Response::new(ValidateConfigResponse {
            valid: true,
            reason: String::new(),
        }))
    }

    async fn evaluate_http_request(
        &self,
        _request: Request<HttpRequestEvaluation>,
    ) -> Result<Response<HttpRequestResult>, Status> {
        Err(Status::unimplemented("HTTP hooks only"))
    }

    async fn evaluate_web_socket_session(
        &self,
        _request: Request<tonic::Streaming<WebSocketSessionEvent>>,
    ) -> Result<Response<Self::EvaluateWebSocketSessionStream>, Status> {
        Err(Status::unimplemented("HTTP requests only"))
    }
}

#[tonic::async_trait]
impl HttpHooks for Rail {
    type EvaluateHttpRequestHookStream = HttpRequestHookResultStream;
    type EvaluateHttpResponseHookStream = HttpResponseHookResultStream;

    async fn evaluate_http_request_hook(
        &self,
        request: Request<tonic::Streaming<HttpRequestHookEvent>>,
    ) -> Result<Response<Self::EvaluateHttpRequestHookStream>, Status> {
        Ok(Response::new(request_stream(
            self.clone(),
            request.into_inner(),
        )))
    }

    async fn evaluate_http_response_hook(
        &self,
        _request: Request<tonic::Streaming<HttpResponseHookEvent>>,
    ) -> Result<Response<Self::EvaluateHttpResponseHookStream>, Status> {
        Err(Status::unimplemented("HTTP requests only"))
    }
}

/// Prints the chain's position, then runs the unproven decisions through the
/// guest's entry point to check they reproduce what the ledger recorded.
fn chain(store: &Store, sandbox: &str) -> Result<(), String> {
    let ledger = store.open()?;
    let execution = store.execution(&store.workspace, sandbox)?;
    let head = ledger
        .head(&execution)
        .map_err(|error| format!("{sandbox}: {error}"))?;
    println!(
        "sandbox={sandbox} decisions={} proven={} state_root={} state={}",
        head.decisions,
        head.proven,
        head.state_root,
        head.state
            .map_or_else(|| "none".into(), |state| state.to_string())
    );
    let Some(batch) = ledger
        .next_batch(&execution, usize::MAX)
        .map_err(|e| e.to_string())?
    else {
        println!("nothing left to prove");
        return Ok(());
    };
    let allowed = batch
        .records
        .iter()
        .filter(|r| r.decision == Decision::Allow)
        .count();
    let public = evaluate_witness(&batch.witness).map_err(|e| format!("witness refused: {e}"))?;
    if decode_batch_public_values(&public).map_err(|e| e.to_string())? != batch.summary {
        return Err("the witness does not reproduce the recorded decisions".into());
    }
    println!(
        "next batch: decisions={} allowed={} witness_bytes={} from={} to={} records_sha256={}",
        batch.summary.count,
        allowed,
        batch.witness.len(),
        batch.summary.previous_state_root,
        batch.summary.next_state_root,
        batch.summary.records_sha256
    );
    println!("re-evaluated as the proof guest would: matches the ledger (no proof was generated)");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (bind, store, mandates) = match Cli::parse().command {
        Command::Chain { store, sandbox } => return Ok(chain(&store, &sandbox)?),
        Command::Serve {
            bind,
            store,
            mandates,
        } => (bind, store, mandates),
    };
    let ledger = store.open()?;
    let loaded = load_mandates(&ledger, &store, &mandates)?;
    println!(
        "serving {NAME} on http://{bind} mandates: {}",
        loaded.join(" ")
    );
    let rail = Rail {
        ledger: Arc::new(ledger),
        store: Arc::new(store),
    };
    Server::builder()
        .add_service(
            SupervisorMiddlewareServer::new(rail.clone())
                .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES),
        )
        .add_service(
            HttpHooksServer::new(rail)
                .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES),
        )
        .serve(bind)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use trusted_rail::action::Action;

    fn order(size: &str, price: &str, asset: u64) -> Action {
        let body =
            json!({"action": {"type": "order", "orders": [{"a": asset, "s": size, "p": price}]}});
        action::http_request(&HttpRequest {
            method: "POST",
            scheme: "https",
            host: "api.hyperliquid-testnet.xyz",
            port: 443,
            path: "/exchange",
            query: "",
            binary: "/usr/bin/curl",
            body: body.to_string().as_bytes(),
        })
        .unwrap()
    }

    #[test]
    fn the_sample_mandate_holds_a_daily_limit() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mandates = dir.path().join("mandates");
        std::fs::create_dir(&mandates).unwrap();
        std::fs::copy(
            "examples/hyperliquid-mandate.json",
            mandates.join("trader.json"),
        )
        .unwrap();
        let store = Store {
            ledger: dir.path().join("ledger.db"),
            workspace: "default".into(),
            node: "test".into(),
        };
        let ledger = store.open().unwrap();
        assert_eq!(load_mandates(&ledger, &store, &mandates).unwrap().len(), 1);
        // Loading again, as a restart does, keeps the chain.
        load_mandates(&ledger, &store, &mandates).unwrap();
        let mut id = 0;
        let mut decide = |action: Action, at: u64| {
            id += 1;
            let record = ledger
                .decide(
                    action,
                    Attempt {
                        execution: store.execution("default", "trader").unwrap(),
                        principal: "trader".into(),
                        action_id: id.to_string(),
                        context: json!({}),
                        evaluated_at_unix: at,
                        validity: serde_json::from_value(
                            json!({"not_before": at, "expires_at": at + 60}),
                        )
                        .unwrap(),
                    },
                )
                .unwrap();
            (record.decision, record.reason_codes.join(","))
        };
        let day = 20_000 * 86_400;
        // 0.04 x 1891.4 = 75.66 per order; the limits are 100 per order, 200 per day.
        assert_eq!(
            decide(order("0.04", "1891.4", 4), day),
            (Decision::Allow, "within_mandate".into())
        );
        assert_eq!(
            decide(order("0.04", "1891.4", 4), day + 1),
            (Decision::Allow, "within_mandate".into())
        );
        assert_eq!(
            decide(order("0.04", "1891.4", 4), day + 2),
            (Decision::Deny, "over_daily_limit".into())
        );
        assert_eq!(
            decide(order("0.1", "1891.4", 4), day + 3),
            (Decision::Deny, "outside_mandate".into())
        );
        assert_eq!(
            decide(order("0.01", "1891.4", 7), day + 4),
            (Decision::Deny, "outside_mandate".into())
        );
        let head = ledger
            .head(&store.execution("default", "trader").unwrap())
            .unwrap();
        assert_eq!(head.state, Some(json!({"day": day, "spent": 15132})));
        // The next day starts a new budget.
        assert_eq!(
            decide(order("0.04", "1891.4", 4), day + 86_400),
            (Decision::Allow, "within_mandate".into())
        );
        // The whole run re-evaluates to what was recorded.
        drop(decide);
        drop(ledger);
        chain(&store, "trader").unwrap();
        // A sandbox without a mandate has no chain.
        assert!(chain(&store, "stranger").is_err());
    }
}
