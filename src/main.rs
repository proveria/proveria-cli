use std::{
    collections::BTreeMap,
    collections::HashSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use regex::Regex;
use reqwest::{
    Client, StatusCode,
    header::{COOKIE, SET_COOKIE},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

const DEFAULT_API_URL: &str = "http://127.0.0.1:3001";
const SESSION_COOKIE_NAME: &str = "proveria_session";
const CONTENT_PROOF_METHODS: [&str; 3] = ["plain-text/v1", "pdf-text-layer/v1", "ocr-tesseract/v1"];
const CONTENT_PROOF_PRESETS: [(&str, usize, usize); 3] =
    [("standard", 7, 1), ("broad", 12, 3), ("sensitive", 4, 1)];

#[derive(Parser)]
#[command(name = "proveria")]
#[command(about = "Proveria CLI for API-first provenance workflows")]
#[command(version)]
struct Cli {
    #[arg(long, global = true, env = "PROVERIA_API_URL")]
    api_url: Option<String>,

    #[arg(long, global = true, env = "PROVERIA_API_KEY")]
    api_key: Option<String>,

    #[arg(long, global = true, env = "PROVERIA_WORKSPACE")]
    workspace: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Grant or revoke verifier access to an attestation.
    Access(AccessCommand),
    /// Manage admin login for session-scoped commands.
    Auth(AuthCommand),
    /// Create, list, and revoke workspace API keys.
    ApiKeys(ApiKeysCommand),
    /// List attestation records.
    Attestations(AttestationsCommand),
    /// Generate shell completions.
    Completions(CompletionsCommand),
    /// Manage local CLI configuration.
    Config(ConfigCommand),
    /// List workspace events.
    Events(EventsCommand),
    /// Export evidence, receipts, and verification artifacts.
    Export(ExportCommand),
    /// Compute a local SHA-256 hash.
    Hash(HashCommand),
    /// Manage projects.
    Projects(ProjectsCommand),
    /// Create a proof record from a file or SHA-256 hash.
    Prove(ProveCommand),
    /// Read attestation records.
    Records(RecordsCommand),
    /// Download attestation receipt artifacts.
    Receipt(ReceiptCommand),
    /// Download verification result artifacts.
    Result(ResultCommand),
    /// Verify a file, SHA-256 hash, or text passage.
    Verify(VerifyCommand),
    /// Manage webhook endpoints and deliveries.
    Webhooks(WebhooksCommand),
}

#[derive(Args)]
struct AccessCommand {
    #[command(subcommand)]
    command: AccessSubcommand,
}

#[derive(Subcommand)]
enum AccessSubcommand {
    /// Grant a verifier access to one attestation.
    Grant(AccessGrant),
    /// Revoke an existing verifier access grant.
    Revoke(AccessRevoke),
}

#[derive(Args)]
struct AccessGrant {
    #[arg(value_name = "ATTESTATION")]
    attestation: String,

    #[arg(long)]
    email: String,

    #[arg(long)]
    message: Option<String>,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

#[derive(Args)]
struct AccessRevoke {
    #[arg(value_name = "ATTESTATION")]
    attestation: String,

    #[arg(long)]
    grant: String,
}

#[derive(Args)]
struct AuthCommand {
    #[command(subcommand)]
    command: AuthSubcommand,
}

#[derive(Subcommand)]
enum AuthSubcommand {
    /// Sign in with a Proveria admin account and save the session locally.
    Login(AuthLogin),
    /// Remove the saved admin session from local CLI config.
    Logout,
}

#[derive(Args)]
struct AuthLogin {
    #[arg(long)]
    email: String,

    #[arg(long)]
    password: String,
}

#[derive(Args)]
struct ApiKeysCommand {
    #[command(subcommand)]
    command: ApiKeysSubcommand,
}

#[derive(Subcommand)]
enum ApiKeysSubcommand {
    /// Create a workspace API key. The token is shown once.
    Create(ApiKeyCreate),
    /// List workspace API keys.
    List(ApiKeyList),
    /// Revoke a workspace API key.
    Revoke(ApiKeyRevoke),
}

#[derive(Args)]
struct ApiKeyCreate {
    #[arg(long)]
    name: String,

    #[arg(long = "scope")]
    scopes: Vec<String>,

    #[arg(long, help = "Save the returned token as the active CLI API key.")]
    use_key: bool,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

#[derive(Args)]
struct ApiKeyList {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

#[derive(Args)]
struct ApiKeyRevoke {
    #[arg(value_name = "API_KEY_ID")]
    id: String,
}

#[derive(Args)]
struct CompletionsCommand {
    #[arg(value_enum)]
    shell: Shell,
}

#[derive(Args)]
struct AttestationsCommand {
    #[arg(long)]
    project: Option<String>,

    #[arg(long)]
    status: Option<String>,

    #[arg(long)]
    limit: Option<u32>,

    #[arg(long)]
    offset: Option<u32>,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

#[derive(Args)]
struct ConfigCommand {
    #[command(subcommand)]
    command: ConfigSubcommand,
}

#[derive(Subcommand)]
enum ConfigSubcommand {
    Set(ConfigSet),
    Show,
}

#[derive(Args)]
struct ConfigSet {
    #[arg(long)]
    api_url: Option<String>,

    #[arg(long)]
    api_key: Option<String>,

    #[arg(long)]
    workspace: Option<String>,
}

#[derive(Args)]
struct EventsCommand {
    #[arg(long)]
    category: Option<String>,

    #[arg(long)]
    action: Option<String>,

    #[arg(long)]
    target_type: Option<String>,

    #[arg(long)]
    target_id: Option<String>,

    #[arg(long)]
    limit: Option<u32>,

    #[arg(long)]
    offset: Option<u32>,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

#[derive(Args)]
struct ExportCommand {
    #[arg(long)]
    project_id: Option<String>,

    #[arg(long)]
    actor_user_id: Option<String>,

    #[arg(long)]
    no_events: bool,

    #[arg(long)]
    limit: Option<u32>,

    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<ExportSubcommand>,
}

#[derive(Subcommand)]
enum ExportSubcommand {
    Jobs(ExportJobs),
    Create(ExportCreate),
}

#[derive(Args)]
struct ExportJobs {
    #[arg(long)]
    limit: Option<u32>,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

#[derive(Args)]
struct ExportCreate {
    #[arg(long)]
    project_id: Option<String>,

    #[arg(long)]
    actor_user_id: Option<String>,

    #[arg(long)]
    no_events: bool,

    #[arg(long)]
    limit: Option<u32>,

    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(Args)]
struct HashCommand {
    #[arg(value_name = "FILE")]
    file: PathBuf,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

#[derive(Args)]
struct ProjectsCommand {
    #[command(subcommand)]
    command: ProjectsSubcommand,
}

#[derive(Subcommand)]
enum ProjectsSubcommand {
    Create(ProjectCreate),
    List,
}

#[derive(Args)]
struct ProjectCreate {
    #[arg(value_name = "SLUG")]
    slug: String,

    #[arg(long)]
    name: String,

    #[arg(long)]
    description: Option<String>,

    #[arg(long)]
    classification: Option<String>,

    #[arg(long = "tag")]
    tags: Vec<String>,

    #[arg(long, value_enum)]
    visibility: Option<ProjectVisibility>,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

#[derive(Args)]
struct RecordsCommand {
    #[command(subcommand)]
    command: RecordsSubcommand,
}

#[derive(Subcommand)]
enum RecordsSubcommand {
    Get(RecordsGet),
}

#[derive(Args)]
struct RecordsGet {
    #[arg(value_name = "ATTESTATION")]
    attestation: String,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

#[derive(Args)]
struct ProveCommand {
    #[arg(value_name = "INPUT")]
    input: Option<String>,

    #[arg(long)]
    project: Option<String>,

    #[arg(long, alias = "label")]
    name: Option<String>,

    #[arg(long, value_name = "FILE")]
    compliance_json: Option<PathBuf>,

    #[arg(long)]
    file_name: Option<String>,

    #[arg(long)]
    byte_size: Option<u64>,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,

    #[command(subcommand)]
    command: Option<ProveSubcommand>,
}

#[derive(Subcommand)]
enum ProveSubcommand {
    Hash(ProveHash),
    File(ProveFile),
}

#[derive(Args)]
struct ProveHash {
    #[arg(value_name = "SHA256")]
    sha256: String,

    #[arg(long)]
    project: String,

    #[arg(long, alias = "label")]
    name: String,

    #[arg(long)]
    file_name: Option<String>,

    #[arg(long)]
    byte_size: Option<u64>,

    #[arg(long, value_name = "FILE")]
    compliance_json: Option<PathBuf>,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

#[derive(Args)]
struct ProveFile {
    #[arg(value_name = "FILE")]
    file: PathBuf,

    #[arg(long)]
    project: String,

    #[arg(long, alias = "label")]
    name: Option<String>,

    #[arg(long, value_name = "FILE")]
    compliance_json: Option<PathBuf>,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

#[derive(Args)]
struct ReceiptCommand {
    #[arg(value_name = "ATTESTATION")]
    attestation: String,

    #[arg(long, help = "Download the signed receipt JSON artifact.")]
    json: bool,

    #[arg(long, help = "Download the human-readable receipt PDF artifact.")]
    pdf: bool,

    #[arg(
        long,
        value_name = "DIR",
        help = "Directory for downloaded artifacts. Use with --json or --pdf."
    )]
    output: Option<PathBuf>,
}

#[derive(Args)]
struct ResultCommand {
    #[arg(value_name = "LINK_ID")]
    link_id: String,

    #[arg(long, help = "Download the verification result JSON artifact.")]
    json: bool,

    #[arg(long, help = "Download the verification result PDF artifact.")]
    pdf: bool,

    #[arg(
        long,
        value_name = "DIR",
        help = "Directory for downloaded artifacts. Use with --json or --pdf."
    )]
    output: Option<PathBuf>,
}

#[derive(Args)]
struct VerifyCommand {
    #[arg(value_name = "INPUT")]
    input: Option<String>,

    #[arg(long)]
    attestation: Option<String>,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,

    #[command(subcommand)]
    command: Option<VerifySubcommand>,
}

#[derive(Subcommand)]
enum VerifySubcommand {
    Hash(VerifyHash),
    File(VerifyFile),
    Passage(VerifyPassage),
}

#[derive(Args)]
struct VerifyHash {
    #[arg(value_name = "SHA256")]
    sha256: String,

    #[arg(long)]
    attestation: String,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

#[derive(Args)]
struct VerifyFile {
    #[arg(value_name = "FILE")]
    file: PathBuf,

    #[arg(long)]
    attestation: String,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

#[derive(Args)]
struct VerifyPassage {
    #[arg(value_name = "TEXT")]
    text: String,

    #[arg(long)]
    attestation: String,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

#[derive(Args)]
struct WebhooksCommand {
    #[command(subcommand)]
    command: WebhooksSubcommand,
}

#[derive(Subcommand)]
enum WebhooksSubcommand {
    /// Create a webhook endpoint subscription.
    Create(WebhookCreate),
    /// List webhook delivery attempts.
    Deliveries(WebhookDeliveries),
    /// Disable a webhook endpoint.
    Disable(WebhookDisable),
    /// List webhook endpoints.
    List(WebhookList),
    /// Send a test event to a webhook endpoint.
    Test(WebhookTest),
}

#[derive(Args)]
struct WebhookCreate {
    #[arg(long)]
    url: String,

    #[arg(long = "event")]
    events: Vec<String>,

    #[arg(long)]
    description: Option<String>,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

#[derive(Args)]
struct WebhookList {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

#[derive(Args)]
struct WebhookDisable {
    #[arg(value_name = "ENDPOINT")]
    endpoint: String,
}

#[derive(Args)]
struct WebhookTest {
    #[arg(value_name = "ENDPOINT")]
    endpoint: String,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

#[derive(Args)]
struct WebhookDeliveries {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

#[derive(Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Clone, Copy, ValueEnum)]
enum ProjectVisibility {
    Public,
    Private,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct ConfigFile {
    api_url: Option<String>,
    api_key: Option<String>,
    workspace: Option<String>,
    session_cookie: Option<String>,
    session_email: Option<String>,
}

#[derive(Clone)]
struct AppContext {
    api_url: String,
    api_key: Option<String>,
    workspace: Option<String>,
    session_cookie: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProjectsResponse {
    data: Vec<Project>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ProjectResponse {
    data: Project,
}

#[derive(Debug, Deserialize, Serialize)]
struct Project {
    id: String,
    slug: String,
    name: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiKeysResponse {
    api_keys: Vec<ApiKeyRecord>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiKeyCreateResponse {
    api_key: ApiKeyRecord,
    token: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiKeyRecord {
    id: String,
    name: String,
    key_prefix: String,
    scopes: Vec<String>,
    created_by_user_id: Option<String>,
    created_at: String,
    last_used_at: Option<String>,
    revoked_at: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AttestationsResponse {
    data: Vec<Attestation>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AttestationResponse {
    data: Attestation,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Attestation {
    id: String,
    label: String,
    state: String,
    project: Option<AttestationProject>,
    merkle_root: Option<String>,
    package_id: Option<String>,
    receipt_available: bool,
    created_at: String,
    confirmed_at: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct AttestationProject {
    id: String,
    slug: String,
    name: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct EventsResponse {
    data: Vec<Event>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Event {
    id: String,
    category: String,
    action: String,
    target_type: Option<String>,
    target_id: Option<String>,
    payload: serde_json::Value,
    created_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportResponse {
    data: serde_json::Value,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportJobsResponse {
    data: Vec<ExportJob>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportJobResponse {
    data: ExportJobData,
}

#[derive(Debug, Deserialize, Serialize)]
struct ExportJobData {
    job: ExportJob,
    manifest: serde_json::Value,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportJob {
    id: String,
    kind: String,
    status: String,
    filters: serde_json::Value,
    artifact_count: i64,
    row_count: i64,
    result_object_key: Option<String>,
    error: Option<String>,
    created_at: String,
    started_at: Option<String>,
    completed_at: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateAttestationResponse {
    data: serde_json::Value,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct LookupResponse {
    data: LookupData,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct LookupData {
    package_id: String,
    link_id: String,
    signed: bool,
    retrieve_url: String,
    verification_url: String,
    package: LookupPackage,
}

#[derive(Debug, Deserialize, Serialize)]
struct LookupPackage {
    result_type: String,
    submitted_hash: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptResponse {
    data: ReceiptData,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptData {
    attestation_id: String,
    attestation_label: String,
    state: String,
    package_id: Option<String>,
    merkle_root: Option<String>,
    receipt_available: bool,
    receipt_pdf_available: bool,
    confirmed_at: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccessGrantResponse {
    data: AccessGrantData,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccessGrantData {
    id: String,
    attestation_id: String,
    granted_to_email: String,
    status: String,
    created_at: String,
    claimed_at: Option<String>,
    revoked_at: Option<String>,
    claim_token: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct WebhookEndpointsResponse {
    data: Vec<WebhookEndpoint>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct WebhookEndpointResponse {
    data: WebhookEndpoint,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct WebhookEndpoint {
    id: String,
    url: String,
    description: Option<String>,
    events: Vec<String>,
    created_at: String,
    disabled_at: Option<String>,
    signing_secret: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct WebhookDeliveriesResponse {
    data: Vec<WebhookDelivery>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct WebhookDeliveryResponse {
    data: WebhookDelivery,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct WebhookDelivery {
    id: String,
    endpoint_id: String,
    event_type: String,
    status: String,
    attempts: i64,
    response_status: Option<i64>,
    created_at: String,
    last_attempt_at: Option<String>,
    next_attempt_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PublicApiErrorEnvelope {
    error: PublicApiErrorBody,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicApiErrorBody {
    code: String,
    message: String,
    retryable: bool,
    request_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicResolvedLink {
    link: PublicLinkMeta,
    target_type: String,
    payload: serde_json::Value,
    signed: bool,
    signature_valid: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicLinkMeta {
    id: String,
    created_at: String,
    expires_at: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = std::env::args()
        .enumerate()
        .filter_map(|(index, arg)| {
            if index > 0 && arg == "--" {
                None
            } else {
                Some(arg)
            }
        })
        .collect::<Vec<_>>();
    let cli = Cli::parse_from(args);
    let config = load_config()?;
    let ctx = AppContext {
        api_url: cli
            .api_url
            .or_else(|| config.api_url.clone())
            .unwrap_or_else(|| DEFAULT_API_URL.to_string())
            .trim_end_matches('/')
            .to_string(),
        api_key: cli.api_key.or_else(|| config.api_key.clone()),
        workspace: cli.workspace.or_else(|| config.workspace.clone()),
        session_cookie: config.session_cookie.clone(),
    };

    match cli.command {
        Command::Access(command) => run_access(ctx, command).await,
        Command::Auth(command) => run_auth(ctx, command).await,
        Command::ApiKeys(command) => run_api_keys(ctx, command).await,
        Command::Attestations(command) => run_attestations(ctx, command).await,
        Command::Completions(command) => run_completions(command),
        Command::Config(command) => run_config(command).await,
        Command::Events(command) => run_events(ctx, command).await,
        Command::Export(command) => run_export(ctx, command).await,
        Command::Hash(command) => run_hash(command),
        Command::Projects(command) => run_projects(ctx, command).await,
        Command::Prove(command) => run_prove(ctx, command).await,
        Command::Records(command) => run_records(ctx, command).await,
        Command::Receipt(command) => run_receipt(ctx, command).await,
        Command::Result(command) => run_result(ctx, command).await,
        Command::Verify(command) => run_verify(ctx, command).await,
        Command::Webhooks(command) => run_webhooks(ctx, command).await,
    }
}

fn run_completions(command: CompletionsCommand) -> Result<()> {
    let mut cli = Cli::command();
    generate(command.shell, &mut cli, "proveria", &mut std::io::stdout());
    Ok(())
}

async fn run_access(ctx: AppContext, command: AccessCommand) -> Result<()> {
    match command.command {
        AccessSubcommand::Grant(input) => {
            let workspace = require_workspace(&ctx)?;
            let email = input.email.trim().to_lowercase();
            if email.is_empty() {
                bail!("verifier email is required");
            }
            let mut body = serde_json::Map::new();
            body.insert("email".to_string(), json!(email));
            if let Some(message) = input.message {
                body.insert("message".to_string(), json!(message));
            }
            let idempotency_key =
                access_grant_idempotency_key(workspace, &input.attestation, &input.email);
            let response = api_post::<AccessGrantResponse>(
                &ctx,
                &format!(
                    "/v1/tenants/{workspace}/attestations/{}/verifier-access",
                    input.attestation
                ),
                serde_json::Value::Object(body),
                Some(idempotency_key),
            )
            .await?;
            match input.output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&response)?),
                OutputFormat::Text => print_access_grant(&response.data),
            }
            Ok(())
        }
        AccessSubcommand::Revoke(input) => {
            let workspace = require_workspace(&ctx)?;
            api_delete(
                &ctx,
                &format!(
                    "/v1/tenants/{workspace}/attestations/{}/verifier-access/{}",
                    input.attestation, input.grant
                ),
            )
            .await?;
            println!("Revoked verifier access grant {}", input.grant);
            Ok(())
        }
    }
}

fn print_access_grant(grant: &AccessGrantData) {
    println!("Verifier access: {}", grant.status);
    println!("grant_id: {}", grant.id);
    println!("attestation_id: {}", grant.attestation_id);
    println!("email: {}", grant.granted_to_email);
    println!("created_at: {}", grant.created_at);
    if let Some(claimed_at) = &grant.claimed_at {
        println!("claimed_at: {claimed_at}");
    }
    if let Some(revoked_at) = &grant.revoked_at {
        println!("revoked_at: {revoked_at}");
    }
    if let Some(claim_token) = &grant.claim_token {
        println!("claim_token: {claim_token}");
    }
}

async fn run_attestations(ctx: AppContext, command: AttestationsCommand) -> Result<()> {
    let workspace = require_workspace(&ctx)?;
    let mut query = Vec::new();
    if let Some(project_slug) = command.project {
        query.push(("project", project_slug));
    }
    if let Some(status) = command.status {
        query.push(("status", status));
    }
    if let Some(limit) = command.limit {
        query.push(("limit", limit.to_string()));
    }
    if let Some(offset) = command.offset {
        query.push(("offset", offset.to_string()));
    }
    let mut path = format!("/v1/tenants/{workspace}/attestations");
    append_query(&mut path, query);
    let response = api_get::<AttestationsResponse>(&ctx, &path).await?;
    match command.output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&response)?),
        OutputFormat::Text => {
            if response.data.is_empty() {
                println!("No attestations found.");
                return Ok(());
            }
            println!("STATE\tRECEIPT\tPROJECT\tLABEL\tID");
            for attestation in response.data {
                let project = attestation
                    .project
                    .as_ref()
                    .map(|project| project.slug.as_str())
                    .unwrap_or("-");
                let receipt = if attestation.receipt_available {
                    "yes"
                } else {
                    "no"
                };
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    attestation.state, receipt, project, attestation.label, attestation.id
                );
            }
        }
    }
    Ok(())
}

async fn run_events(ctx: AppContext, command: EventsCommand) -> Result<()> {
    let workspace = require_workspace(&ctx)?;
    let mut query = Vec::new();
    if let Some(category) = command.category {
        query.push(("category", category));
    }
    if let Some(action) = command.action {
        query.push(("action", action));
    }
    if let Some(target_type) = command.target_type {
        query.push(("targetType", target_type));
    }
    if let Some(target_id) = command.target_id {
        query.push(("targetId", target_id));
    }
    if let Some(limit) = command.limit {
        query.push(("limit", limit.to_string()));
    }
    if let Some(offset) = command.offset {
        query.push(("offset", offset.to_string()));
    }
    let mut path = format!("/v1/tenants/{workspace}/events");
    append_query(&mut path, query);
    let response = api_get::<EventsResponse>(&ctx, &path).await?;
    match command.output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&response)?),
        OutputFormat::Text => {
            if response.data.is_empty() {
                println!("No events found.");
                return Ok(());
            }
            println!("CREATED\tCATEGORY\tACTION\tTARGET\tID");
            for event in response.data {
                let target_type = event.target_type.as_deref().unwrap_or("-");
                let target_id = event.target_id.as_deref().unwrap_or("-");
                println!(
                    "{}\t{}\t{}\t{}:{}\t{}",
                    event.created_at,
                    event.category,
                    event.action,
                    target_type,
                    target_id,
                    event.id
                );
            }
        }
    }
    Ok(())
}

async fn run_export(ctx: AppContext, command: ExportCommand) -> Result<()> {
    if command.command.is_some() {
        ensure_no_legacy_export_flags(&command)?;
    }
    match command.command {
        Some(ExportSubcommand::Jobs(input)) => return run_export_jobs(ctx, input).await,
        Some(ExportSubcommand::Create(input)) => return run_export_create(ctx, input).await,
        None => {}
    }
    let workspace = require_workspace(&ctx)?;
    let mut query = Vec::new();
    if let Some(project_id) = command.project_id {
        query.push(("projectId", project_id));
    }
    if let Some(actor_user_id) = command.actor_user_id {
        query.push(("actorUserId", actor_user_id));
    }
    query.push(("includeEvents", (!command.no_events).to_string()));
    if let Some(limit) = command.limit {
        query.push(("limit", limit.to_string()));
    }
    let mut path = format!("/v1/tenants/{workspace}/evidence-export/manifest");
    append_query(&mut path, query);
    let response = api_get::<ExportResponse>(&ctx, &path).await?;
    let json = serde_json::to_string_pretty(&response.data)?;
    if let Some(output) = command.output {
        fs::write(&output, json)
            .with_context(|| format!("could not write {}", output.display()))?;
        println!("Wrote {}", output.display());
    } else {
        println!("{json}");
    }
    Ok(())
}

fn ensure_no_legacy_export_flags(command: &ExportCommand) -> Result<()> {
    if command.project_id.is_some()
        || command.actor_user_id.is_some()
        || command.no_events
        || command.limit.is_some()
        || command.output.is_some()
    {
        bail!(
            "put export filters after the export subcommand, for example `proveria export create --limit 100`"
        );
    }
    Ok(())
}

async fn run_export_jobs(ctx: AppContext, input: ExportJobs) -> Result<()> {
    let workspace = require_workspace(&ctx)?;
    let mut query = Vec::new();
    if let Some(limit) = input.limit {
        query.push(("limit", limit.to_string()));
    }
    let mut path = format!("/v1/tenants/{workspace}/evidence-export/jobs");
    append_query(&mut path, query);
    let response = api_get::<ExportJobsResponse>(&ctx, &path).await?;
    match input.output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&response)?),
        OutputFormat::Text => {
            if response.data.is_empty() {
                println!("No evidence export jobs found.");
                return Ok(());
            }
            println!("CREATED\tSTATUS\tARTIFACTS\tROWS\tID");
            for job in response.data {
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    job.created_at, job.status, job.artifact_count, job.row_count, job.id
                );
            }
        }
    }
    Ok(())
}

async fn run_export_create(ctx: AppContext, input: ExportCreate) -> Result<()> {
    let workspace = require_workspace(&ctx)?;
    let mut body = serde_json::Map::new();
    if let Some(project_id) = input.project_id {
        body.insert("projectId".to_string(), json!(project_id));
    }
    if let Some(actor_user_id) = input.actor_user_id {
        body.insert("actorUserId".to_string(), json!(actor_user_id));
    }
    body.insert("includeEvents".to_string(), json!(!input.no_events));
    if let Some(limit) = input.limit {
        body.insert("limit".to_string(), json!(limit));
    }
    let response = api_post::<ExportJobResponse>(
        &ctx,
        &format!("/v1/tenants/{workspace}/evidence-export/jobs"),
        serde_json::Value::Object(body),
        None,
    )
    .await?;
    if let Some(output) = input.output {
        let json = serde_json::to_string_pretty(&response.data.manifest)?;
        fs::write(&output, json)
            .with_context(|| format!("could not write {}", output.display()))?;
        println!("Wrote {}", output.display());
    }
    match input.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&response)?),
        OutputFormat::Text => {
            println!("Created evidence export job {}", response.data.job.id);
            println!("status: {}", response.data.job.status);
            println!("artifact_count: {}", response.data.job.artifact_count);
            println!("row_count: {}", response.data.job.row_count);
            if let Some(completed_at) = response.data.job.completed_at {
                println!("completed_at: {completed_at}");
            }
        }
    }
    Ok(())
}

async fn run_webhooks(ctx: AppContext, command: WebhooksCommand) -> Result<()> {
    match command.command {
        WebhooksSubcommand::Create(input) => {
            let workspace = require_workspace(&ctx)?;
            let url = input.url.trim().to_string();
            let events: Vec<String> = input
                .events
                .into_iter()
                .map(|event| event.trim().to_string())
                .filter(|event| !event.is_empty())
                .collect();
            if url.is_empty() {
                bail!("webhook URL is required");
            }
            if events.is_empty() {
                bail!("at least one webhook event is required. Pass `--event receipt.issued`");
            }
            let mut body = serde_json::Map::new();
            body.insert("url".to_string(), json!(url));
            body.insert("events".to_string(), json!(events));
            if let Some(description) = input.description {
                body.insert("description".to_string(), json!(description));
            }
            let idempotency_key = webhook_idempotency_key(workspace, &body);
            let response = api_post::<WebhookEndpointResponse>(
                &ctx,
                &format!("/v1/tenants/{workspace}/webhook-endpoints"),
                serde_json::Value::Object(body),
                Some(idempotency_key),
            )
            .await?;
            match input.output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&response)?),
                OutputFormat::Text => print_webhook_endpoint(&response.data),
            }
            Ok(())
        }
        WebhooksSubcommand::Deliveries(input) => {
            let workspace = require_workspace(&ctx)?;
            let response = api_get::<WebhookDeliveriesResponse>(
                &ctx,
                &format!("/v1/tenants/{workspace}/webhook-deliveries"),
            )
            .await?;
            match input.output {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&response)?);
                    Ok(())
                }
                OutputFormat::Text => {
                    if response.data.is_empty() {
                        println!("No webhook deliveries found.");
                        return Ok(());
                    }
                    println!("CREATED\tSTATUS\tEVENT\tATTEMPTS\tENDPOINT\tID");
                    for delivery in response.data {
                        println!(
                            "{}\t{}\t{}\t{}\t{}\t{}",
                            delivery.created_at,
                            delivery.status,
                            delivery.event_type,
                            delivery.attempts,
                            delivery.endpoint_id,
                            delivery.id
                        );
                    }
                    Ok(())
                }
            }
        }
        WebhooksSubcommand::Disable(input) => {
            let workspace = require_workspace(&ctx)?;
            api_delete(
                &ctx,
                &format!(
                    "/v1/tenants/{workspace}/webhook-endpoints/{}",
                    input.endpoint
                ),
            )
            .await?;
            println!("Disabled webhook endpoint {}", input.endpoint);
            Ok(())
        }
        WebhooksSubcommand::List(input) => {
            let workspace = require_workspace(&ctx)?;
            let response = api_get::<WebhookEndpointsResponse>(
                &ctx,
                &format!("/v1/tenants/{workspace}/webhook-endpoints"),
            )
            .await?;
            match input.output {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&response)?);
                    Ok(())
                }
                OutputFormat::Text => {
                    if response.data.is_empty() {
                        println!("No webhook endpoints found.");
                        return Ok(());
                    }
                    println!("CREATED\tSTATUS\tEVENTS\tURL\tID");
                    for endpoint in response.data {
                        let status = if endpoint.disabled_at.is_some() {
                            "disabled"
                        } else {
                            "active"
                        };
                        println!(
                            "{}\t{}\t{}\t{}\t{}",
                            endpoint.created_at,
                            status,
                            endpoint.events.join(","),
                            endpoint.url,
                            endpoint.id
                        );
                    }
                    Ok(())
                }
            }
        }
        WebhooksSubcommand::Test(input) => {
            let workspace = require_workspace(&ctx)?;
            let idempotency_key = webhook_test_idempotency_key(workspace, &input.endpoint);
            let response = api_post::<WebhookDeliveryResponse>(
                &ctx,
                &format!(
                    "/v1/tenants/{workspace}/webhook-endpoints/{}/test",
                    input.endpoint
                ),
                json!({}),
                Some(idempotency_key),
            )
            .await?;
            match input.output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&response)?),
                OutputFormat::Text => {
                    println!("Queued webhook test delivery {}", response.data.id);
                    println!("status: {}", response.data.status);
                    println!("endpoint_id: {}", response.data.endpoint_id);
                }
            }
            Ok(())
        }
    }
}

async fn run_auth(ctx: AppContext, command: AuthCommand) -> Result<()> {
    match command.command {
        AuthSubcommand::Login(input) => {
            let email = input.email.trim().to_lowercase();
            if email.is_empty() {
                bail!("email is required");
            }
            if input.password.is_empty() {
                bail!("password is required");
            }
            let client = Client::new();
            let response = client
                .post(format!("{}/auth/login", ctx.api_url))
                .json(&json!({
                    "email": email,
                    "password": input.password,
                }))
                .send()
                .await
                .context("POST /auth/login failed")?;
            let status = response.status();
            let set_cookies = response
                .headers()
                .get_all(SET_COOKIE)
                .iter()
                .filter_map(|header| header.to_str().ok())
                .map(str::to_string)
                .collect::<Vec<_>>();
            let text = response
                .text()
                .await
                .context("could not read login response")?;
            if !status.is_success() {
                bail!("{}", format_api_error(status, &text));
            }
            let cookie = set_cookies
                .iter()
                .map(String::as_str)
                .find_map(extract_session_cookie)
                .ok_or_else(|| anyhow!("login succeeded without a session cookie"))?;

            let mut config = load_config()?;
            config.api_url = Some(ctx.api_url);
            config.session_cookie = Some(cookie);
            config.session_email = Some(email.clone());
            save_config(&config)?;
            println!("Signed in as {email}");
            println!("Saved admin session at {}", config_path()?.display());
            Ok(())
        }
        AuthSubcommand::Logout => {
            let mut config = load_config()?;
            config.session_cookie = None;
            config.session_email = None;
            save_config(&config)?;
            println!(
                "Removed saved admin session from {}",
                config_path()?.display()
            );
            Ok(())
        }
    }
}

async fn run_api_keys(ctx: AppContext, command: ApiKeysCommand) -> Result<()> {
    match command.command {
        ApiKeysSubcommand::Create(input) => {
            let workspace = require_workspace(&ctx)?;
            let name = input.name.trim();
            if name.is_empty() {
                bail!("API key name is required");
            }
            let scopes = normalize_api_key_scopes(input.scopes)?;
            let response = session_post::<ApiKeyCreateResponse>(
                &ctx,
                &format!("/tenants/{workspace}/api-keys"),
                json!({
                    "name": name,
                    "scopes": scopes,
                }),
            )
            .await?;

            if input.use_key {
                let mut config = load_config()?;
                config.api_url = Some(ctx.api_url.clone());
                config.workspace = Some(workspace.to_string());
                config.api_key = Some(response.token.clone());
                save_config(&config)?;
            }

            match input.output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&response)?),
                OutputFormat::Text => {
                    println!("Created API key {}", response.api_key.id);
                    println!("name: {}", response.api_key.name);
                    println!("prefix: {}", response.api_key.key_prefix);
                    println!("scopes: {}", response.api_key.scopes.join(","));
                    println!("token: {}", response.token);
                    if input.use_key {
                        println!("Saved token as the active CLI API key.");
                    } else {
                        println!("Token is shown once. Store it now or rerun with --use-key.");
                    }
                }
            }
            Ok(())
        }
        ApiKeysSubcommand::List(input) => {
            let workspace = require_workspace(&ctx)?;
            let response =
                session_get::<ApiKeysResponse>(&ctx, &format!("/tenants/{workspace}/api-keys"))
                    .await?;
            match input.output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&response)?),
                OutputFormat::Text => {
                    if response.api_keys.is_empty() {
                        println!("No API keys found.");
                        return Ok(());
                    }
                    println!("CREATED\tSTATUS\tSCOPES\tPREFIX\tNAME\tID");
                    for key in response.api_keys {
                        let status = if key.revoked_at.is_some() {
                            "revoked"
                        } else {
                            "active"
                        };
                        println!(
                            "{}\t{}\t{}\t{}\t{}\t{}",
                            key.created_at,
                            status,
                            key.scopes.join(","),
                            key.key_prefix,
                            key.name,
                            key.id
                        );
                    }
                }
            }
            Ok(())
        }
        ApiKeysSubcommand::Revoke(input) => {
            let workspace = require_workspace(&ctx)?;
            session_delete(&ctx, &format!("/tenants/{workspace}/api-keys/{}", input.id)).await?;
            println!("Revoked API key {}", input.id);
            Ok(())
        }
    }
}

fn print_webhook_endpoint(endpoint: &WebhookEndpoint) {
    println!("Webhook endpoint: {}", endpoint.id);
    println!("url: {}", endpoint.url);
    println!("events: {}", endpoint.events.join(","));
    println!("created_at: {}", endpoint.created_at);
    if let Some(description) = &endpoint.description {
        println!("description: {description}");
    }
    if let Some(disabled_at) = &endpoint.disabled_at {
        println!("disabled_at: {disabled_at}");
    }
    if let Some(secret) = &endpoint.signing_secret {
        println!("signing_secret: {secret}");
    }
}

async fn run_config(command: ConfigCommand) -> Result<()> {
    match command.command {
        ConfigSubcommand::Set(input) => {
            let mut config = load_config()?;
            if input.api_url.is_some() {
                config.api_url = input.api_url;
            }
            if input.api_key.is_some() {
                config.api_key = input.api_key;
            }
            if input.workspace.is_some() {
                config.workspace = input.workspace;
            }
            save_config(&config)?;
            println!("Saved Proveria CLI config at {}", config_path()?.display());
            Ok(())
        }
        ConfigSubcommand::Show => {
            let config = load_config()?;
            println!("{}", serde_json::to_string_pretty(&config)?);
            Ok(())
        }
    }
}

fn run_hash(command: HashCommand) -> Result<()> {
    let hash = sha256_file(&command.file)?;
    match command.output {
        OutputFormat::Text => println!("{hash}  {}", command.file.display()),
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "file": command.file,
                    "sha256": hash,
                }))?
            );
        }
    }
    Ok(())
}

async fn run_projects(ctx: AppContext, command: ProjectsCommand) -> Result<()> {
    match command.command {
        ProjectsSubcommand::Create(input) => {
            let workspace = require_workspace(&ctx)?;
            let slug = input.slug.trim().to_string();
            let name = input.name.trim().to_string();
            if slug.is_empty() {
                bail!("project slug is required");
            }
            if name.is_empty() {
                bail!("project name is required");
            }
            let mut body = serde_json::Map::new();
            body.insert("slug".to_string(), json!(slug));
            body.insert("name".to_string(), json!(name));
            if let Some(description) = input.description {
                body.insert("description".to_string(), json!(description));
            }
            if let Some(classification) = input.classification {
                body.insert("classification".to_string(), json!(classification));
            }
            if !input.tags.is_empty() {
                body.insert("tags".to_string(), json!(input.tags));
            }
            if let Some(visibility) = input.visibility {
                body.insert(
                    "visibility".to_string(),
                    json!(match visibility {
                        ProjectVisibility::Public => "public",
                        ProjectVisibility::Private => "private",
                    }),
                );
            }
            let body = serde_json::Value::Object(body);
            let idempotency_key = project_idempotency_key(workspace, &input.slug, &input.name);
            let response = api_post::<ProjectResponse>(
                &ctx,
                &format!("/v1/tenants/{workspace}/projects"),
                body,
                Some(idempotency_key),
            )
            .await?;
            match input.output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&response)?),
                OutputFormat::Text => {
                    println!("Created project {}", response.data.slug);
                    println!("name: {}", response.data.name);
                    println!("id: {}", response.data.id);
                }
            }
            Ok(())
        }
        ProjectsSubcommand::List => {
            let workspace = require_workspace(&ctx)?;
            let response =
                api_get::<ProjectsResponse>(&ctx, &format!("/v1/tenants/{workspace}/projects"))
                    .await?;
            if response.data.is_empty() {
                println!("No projects found.");
                return Ok(());
            }
            for project in response.data {
                println!("{}\t{}\t{}", project.slug, project.name, project.id);
            }
            Ok(())
        }
    }
}

async fn run_records(ctx: AppContext, command: RecordsCommand) -> Result<()> {
    match command.command {
        RecordsSubcommand::Get(input) => {
            let workspace = require_workspace(&ctx)?;
            let response = api_get::<AttestationResponse>(
                &ctx,
                &format!("/v1/tenants/{workspace}/attestations/{}", input.attestation),
            )
            .await?;
            match input.output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&response)?),
                OutputFormat::Text => print_attestation_record(&response.data),
            }
            Ok(())
        }
    }
}

fn print_attestation_record(attestation: &Attestation) {
    println!("Record: {}", attestation.label);
    println!("id: {}", attestation.id);
    println!("state: {}", attestation.state);
    if let Some(project) = &attestation.project {
        println!("project: {} ({})", project.name, project.slug);
    }
    if let Some(package_id) = &attestation.package_id {
        println!("package_id: {package_id}");
    }
    if let Some(merkle_root) = &attestation.merkle_root {
        println!("merkle_root: {merkle_root}");
    }
    println!(
        "receipt: {}",
        if attestation.receipt_available {
            "available"
        } else {
            "not available"
        }
    );
    println!("created_at: {}", attestation.created_at);
    if let Some(confirmed_at) = &attestation.confirmed_at {
        println!("confirmed_at: {confirmed_at}");
    }
}

async fn run_prove(ctx: AppContext, command: ProveCommand) -> Result<()> {
    match command.command {
        Some(ProveSubcommand::Hash(input)) => {
            if command.input.is_some() || command.project.is_some() || command.name.is_some() {
                bail!(
                    "use either `proveria prove <input> --project <slug>` or `proveria prove hash <sha256> --project <slug> --name <name>`, not both"
                );
            }
            ensure_hex_sha256(&input.sha256)?;
            prove_hash(
                &ctx,
                ProveHashInput {
                    project: input.project,
                    label: input.name,
                    sha256: input.sha256.to_lowercase(),
                    file_name: input.file_name,
                    byte_size: input.byte_size,
                    compliance_json: input.compliance_json,
                    output: input.output,
                    source_label: "hash".to_string(),
                },
            )
            .await
        }
        Some(ProveSubcommand::File(input)) => {
            if command.input.is_some() || command.project.is_some() || command.name.is_some() {
                bail!(
                    "use either `proveria prove <input> --project <slug>` or `proveria prove file <file> --project <slug> --name <name>`, not both"
                );
            }
            let hash = sha256_file(&input.file)?;
            let label = input
                .name
                .unwrap_or_else(|| default_label_from_path(&input.file));
            let file_name = input
                .file
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| anyhow!("file name is not valid UTF-8"))?;
            let file_size = fs::metadata(&input.file)
                .with_context(|| format!("could not stat {}", input.file.display()))?
                .len();
            prove_hash(
                &ctx,
                ProveHashInput {
                    project: input.project,
                    label,
                    sha256: hash,
                    file_name: Some(file_name.to_string()),
                    byte_size: Some(file_size),
                    compliance_json: input.compliance_json,
                    output: input.output,
                    source_label: format!("file {file_name}"),
                },
            )
            .await
        }
        None => {
            let input = command.input.ok_or_else(|| {
                anyhow!("missing input. Use `proveria prove <sha256-or-file> --project <slug>`")
            })?;
            let project = command
                .project
                .ok_or_else(|| anyhow!("missing project slug. Pass `--project <slug>`"))?;
            if let Ok(sha256) = normalized_sha256(&input) {
                let label = command
                    .name
                    .ok_or_else(|| anyhow!("proving a raw hash needs `--name <name>`"))?;
                return prove_hash(
                    &ctx,
                    ProveHashInput {
                        project,
                        label,
                        sha256,
                        file_name: command.file_name,
                        byte_size: command.byte_size,
                        compliance_json: command.compliance_json,
                        output: command.output,
                        source_label: "hash".to_string(),
                    },
                )
                .await;
            }
            let file = PathBuf::from(&input);
            if command.file_name.is_some() || command.byte_size.is_some() {
                bail!("--file-name and --byte-size are only valid when proving a raw SHA-256 hash");
            }
            let hash = sha256_file(&file)?;
            let label = command
                .name
                .unwrap_or_else(|| default_label_from_path(&file));
            let file_name = file
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| anyhow!("file name is not valid UTF-8"))?;
            let file_size = fs::metadata(&file)
                .with_context(|| format!("could not stat {}", file.display()))?
                .len();
            prove_hash(
                &ctx,
                ProveHashInput {
                    project,
                    label,
                    sha256: hash,
                    file_name: Some(file_name.to_string()),
                    byte_size: Some(file_size),
                    compliance_json: command.compliance_json,
                    output: command.output,
                    source_label: format!("file {file_name}"),
                },
            )
            .await
        }
    }
}

struct ProveHashInput {
    project: String,
    label: String,
    sha256: String,
    file_name: Option<String>,
    byte_size: Option<u64>,
    compliance_json: Option<PathBuf>,
    output: OutputFormat,
    source_label: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ComplianceJsonMetadata {
    sha256: String,
    file_name: String,
    byte_size: u64,
    media_type: &'static str,
    canonicalization: &'static str,
}

async fn prove_hash(ctx: &AppContext, input: ProveHashInput) -> Result<()> {
    let workspace = require_workspace(ctx)?;
    let compliance = input
        .compliance_json
        .as_deref()
        .map(compliance_json_metadata)
        .transpose()?;
    let mut body = serde_json::Map::new();
    body.insert("label".to_string(), json!(input.label));
    body.insert("sha256".to_string(), json!(input.sha256));
    if let Some(file_name) = &input.file_name {
        body.insert("fileName".to_string(), json!(file_name));
    }
    if let Some(byte_size) = input.byte_size {
        body.insert("byteSize".to_string(), json!(byte_size));
    }
    if let Some(compliance) = &compliance {
        body.insert("compliance".to_string(), serde_json::to_value(compliance)?);
    }
    let file_name_for_key = input.file_name.as_deref().unwrap_or("external-sha256");
    let idempotency_key = attestation_idempotency_key(
        workspace,
        &input.project,
        &input.label,
        file_name_for_key,
        &input.sha256,
        compliance.as_ref().map(|metadata| metadata.sha256.as_str()),
    );
    let response = api_post::<CreateAttestationResponse>(
        ctx,
        &format!(
            "/v1/tenants/{workspace}/projects/{}/attestations",
            input.project
        ),
        serde_json::Value::Object(body),
        Some(idempotency_key),
    )
    .await?;
    match input.output {
        OutputFormat::Text => {
            println!("Proved {}", input.source_label);
            println!("{}", serde_json::to_string_pretty(&response.data)?);
        }
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&response)?),
    }
    Ok(())
}

async fn run_receipt(ctx: AppContext, command: ReceiptCommand) -> Result<()> {
    let workspace = require_workspace(&ctx)?;
    if command.output.is_some() && !command.json && !command.pdf {
        bail!("`--output` is only used with `--json` or `--pdf`");
    }
    if command.json || command.pdf {
        return download_receipt_artifacts(&ctx, workspace, command).await;
    }
    let response = api_get::<ReceiptResponse>(
        &ctx,
        &format!(
            "/v1/tenants/{workspace}/attestations/{}/receipt",
            command.attestation
        ),
    )
    .await?;
    println!("Receipt: {}", response.data.attestation_label);
    println!("attestation_id: {}", response.data.attestation_id);
    println!("state: {}", response.data.state);
    if let Some(package_id) = response.data.package_id {
        println!("package_id: {package_id}");
    }
    if let Some(merkle_root) = response.data.merkle_root {
        println!("merkle_root: {merkle_root}");
    }
    println!(
        "receipt_json: {}",
        if response.data.receipt_available {
            "available"
        } else {
            "not available"
        }
    );
    println!(
        "receipt_pdf: {}",
        if response.data.receipt_pdf_available {
            "available"
        } else {
            "not available"
        }
    );
    if let Some(confirmed_at) = response.data.confirmed_at {
        println!("confirmed_at: {confirmed_at}");
    }
    Ok(())
}

async fn download_receipt_artifacts(
    ctx: &AppContext,
    workspace: &str,
    command: ReceiptCommand,
) -> Result<()> {
    let output_dir = command.output.unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(&output_dir)
        .with_context(|| format!("could not create {}", output_dir.display()))?;
    if command.json {
        let path = output_dir.join(format!("{}.receipt.json", command.attestation));
        let bytes = api_get_bytes(
            ctx,
            &format!(
                "/v1/tenants/{workspace}/attestations/{}/receipt.json",
                command.attestation
            ),
        )
        .await?;
        fs::write(&path, bytes).with_context(|| format!("could not write {}", path.display()))?;
        println!("Wrote {}", path.display());
    }
    if command.pdf {
        let path = output_dir.join(format!("{}.receipt.pdf", command.attestation));
        let bytes = api_get_bytes(
            ctx,
            &format!(
                "/v1/tenants/{workspace}/attestations/{}/receipt.pdf",
                command.attestation
            ),
        )
        .await?;
        fs::write(&path, bytes).with_context(|| format!("could not write {}", path.display()))?;
        println!("Wrote {}", path.display());
    }
    Ok(())
}

async fn run_result(ctx: AppContext, command: ResultCommand) -> Result<()> {
    if command.output.is_some() && !command.json && !command.pdf {
        bail!("`--output` is only used with `--json` or `--pdf`");
    }
    let resolved =
        public_get::<PublicResolvedLink>(&ctx, &format!("/v/{}", command.link_id)).await?;
    if resolved.target_type != "lookup_result" {
        bail!(
            "link {} is a {}, not a verification result",
            command.link_id,
            resolved.target_type
        );
    }

    if command.json || command.pdf {
        return download_result_artifacts(&ctx, command, resolved).await;
    }

    println!("Verification result: {}", resolved.link.id);
    if let Some(package_id) = resolved
        .payload
        .get("package_id")
        .and_then(|value| value.as_str())
    {
        println!("package_id: {package_id}");
    }
    if let Some(result_type) = resolved
        .payload
        .get("result_type")
        .and_then(|value| value.as_str())
    {
        println!("result_type: {result_type}");
    }
    if let Some(hash) = resolved
        .payload
        .get("submitted_hash")
        .and_then(|value| value.as_str())
    {
        println!("submitted_hash: {hash}");
    }
    println!("signed: {}", if resolved.signed { "yes" } else { "no" });
    println!("created_at: {}", resolved.link.created_at);
    println!(
        "expires_at: {}",
        resolved.link.expires_at.as_deref().unwrap_or("never")
    );
    println!("json: {}/v/{}", ctx.api_url, resolved.link.id);
    println!("pdf: {}/v/{}.pdf", ctx.api_url, resolved.link.id);
    Ok(())
}

async fn download_result_artifacts(
    ctx: &AppContext,
    command: ResultCommand,
    resolved: PublicResolvedLink,
) -> Result<()> {
    let output_dir = command.output.unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(&output_dir)
        .with_context(|| format!("could not create {}", output_dir.display()))?;
    if command.json {
        let path = output_dir.join(format!("{}.result.json", command.link_id));
        let mut json = serde_json::to_string_pretty(&resolved.payload)?;
        json.push('\n');
        fs::write(&path, json).with_context(|| format!("could not write {}", path.display()))?;
        println!("Wrote {}", path.display());
    }
    if command.pdf {
        let path = output_dir.join(format!("{}.result.pdf", command.link_id));
        let bytes = public_get_bytes(ctx, &format!("/v/{}.pdf", command.link_id)).await?;
        fs::write(&path, bytes).with_context(|| format!("could not write {}", path.display()))?;
        println!("Wrote {}", path.display());
    }
    Ok(())
}

async fn run_verify(ctx: AppContext, command: VerifyCommand) -> Result<()> {
    match command.command {
        Some(VerifySubcommand::Hash(input)) => {
            if command.input.is_some() || command.attestation.is_some() {
                bail!(
                    "use either `proveria verify <input> --attestation <id>` or `proveria verify hash <sha256> --attestation <id>`, not both"
                );
            }
            let sha256 = normalized_sha256(&input.sha256)?;
            verify_hash(
                &ctx,
                VerifyHashInput {
                    attestation: input.attestation,
                    sha256,
                    output: input.output,
                    source_label: "hash".to_string(),
                },
            )
            .await
        }
        Some(VerifySubcommand::File(input)) => {
            if command.input.is_some() || command.attestation.is_some() {
                bail!(
                    "use either `proveria verify <input> --attestation <id>` or `proveria verify file <file> --attestation <id>`, not both"
                );
            }
            let sha256 = sha256_file(&input.file)?;
            let source_label = format!("file {}", input.file.display());
            verify_hash(
                &ctx,
                VerifyHashInput {
                    attestation: input.attestation,
                    sha256,
                    output: input.output,
                    source_label,
                },
            )
            .await
        }
        Some(VerifySubcommand::Passage(input)) => {
            if command.input.is_some() || command.attestation.is_some() {
                bail!(
                    "use `proveria verify passage <text> --attestation <id>` for passage verification"
                );
            }
            let candidate_hashes = passage_candidate_hashes(&input.text)?;
            verify_content_hashes(
                &ctx,
                VerifyContentInput {
                    attestation: input.attestation,
                    candidate_hashes,
                    output: input.output,
                    source_label: "passage".to_string(),
                },
            )
            .await
        }
        None => {
            let input = command.input.ok_or_else(|| {
                anyhow!("missing input. Use `proveria verify <sha256-or-file> --attestation <id>`")
            })?;
            let attestation = command
                .attestation
                .ok_or_else(|| anyhow!("missing attestation id. Pass `--attestation <id>`"))?;
            if let Ok(sha256) = normalized_sha256(&input) {
                return verify_hash(
                    &ctx,
                    VerifyHashInput {
                        attestation,
                        sha256,
                        output: command.output,
                        source_label: "hash".to_string(),
                    },
                )
                .await;
            }
            let file = PathBuf::from(&input);
            let sha256 = sha256_file(&file)?;
            verify_hash(
                &ctx,
                VerifyHashInput {
                    attestation,
                    sha256,
                    output: command.output,
                    source_label: format!("file {}", file.display()),
                },
            )
            .await
        }
    }
}

struct VerifyHashInput {
    attestation: String,
    sha256: String,
    output: OutputFormat,
    source_label: String,
}

struct VerifyContentInput {
    attestation: String,
    candidate_hashes: Vec<String>,
    output: OutputFormat,
    source_label: String,
}

async fn verify_hash(ctx: &AppContext, input: VerifyHashInput) -> Result<()> {
    let workspace = require_workspace(ctx)?;
    let body = json!({
        "submittedHash": input.sha256,
        "lookupKind": "whole_file",
    });
    let response = api_post::<LookupResponse>(
        ctx,
        &format!(
            "/v1/tenants/{workspace}/attestations/{}/lookup",
            input.attestation
        ),
        body,
        None,
    )
    .await?;
    match input.output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&response)?),
        OutputFormat::Text => {
            let result = response.data.package.result_type.as_str();
            let verdict = if result == "match" {
                "MATCH"
            } else {
                "NO MATCH"
            };
            println!("{verdict}: verified {}", input.source_label);
            println!("submitted_hash: {}", response.data.package.submitted_hash);
            println!("package_id: {}", response.data.package_id);
            println!(
                "verification_url: {}{}",
                ctx.api_url, response.data.verification_url
            );
        }
    }
    Ok(())
}

async fn verify_content_hashes(ctx: &AppContext, input: VerifyContentInput) -> Result<()> {
    let workspace = require_workspace(ctx)?;
    let submitted_hash = input
        .candidate_hashes
        .first()
        .ok_or_else(|| anyhow!("passage verification needs at least 7 normalized words"))?;
    let candidate_count = input.candidate_hashes.len();
    let body = json!({
        "submittedHash": submitted_hash,
        "candidateHashes": input.candidate_hashes,
        "lookupKind": "content",
    });
    let response = api_post::<LookupResponse>(
        ctx,
        &format!(
            "/v1/tenants/{workspace}/attestations/{}/lookup",
            input.attestation
        ),
        body,
        None,
    )
    .await?;
    match input.output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&response)?),
        OutputFormat::Text => {
            let result = response.data.package.result_type.as_str();
            let verdict = if result == "match" {
                "MATCH"
            } else {
                "NO MATCH"
            };
            println!("{verdict}: verified {}", input.source_label);
            println!("candidate_hashes: {candidate_count}");
            println!("submitted_hash: {}", response.data.package.submitted_hash);
            println!("package_id: {}", response.data.package_id);
            println!(
                "verification_url: {}{}",
                ctx.api_url, response.data.verification_url
            );
        }
    }
    Ok(())
}

async fn api_get<T: for<'de> Deserialize<'de>>(ctx: &AppContext, path: &str) -> Result<T> {
    let client = Client::new();
    let response = client
        .get(format!("{}{}", ctx.api_url, path))
        .bearer_auth(require_api_key(ctx)?)
        .send()
        .await
        .with_context(|| format!("GET {path} failed"))?;
    decode_response(response).await
}

async fn api_get_bytes(ctx: &AppContext, path: &str) -> Result<Vec<u8>> {
    let client = Client::new();
    let response = client
        .get(format!("{}{}", ctx.api_url, path))
        .bearer_auth(require_api_key(ctx)?)
        .send()
        .await
        .with_context(|| format!("GET {path} failed"))?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .with_context(|| format!("could not read GET {path} response"))?;
    if !status.is_success() {
        let text = String::from_utf8_lossy(&bytes);
        bail!("{}", format_api_error(status, &text));
    }
    Ok(bytes.to_vec())
}

async fn public_get<T: for<'de> Deserialize<'de>>(ctx: &AppContext, path: &str) -> Result<T> {
    let client = Client::new();
    let response = client
        .get(format!("{}{}", ctx.api_url, path))
        .send()
        .await
        .with_context(|| format!("GET {path} failed"))?;
    decode_response(response).await
}

async fn public_get_bytes(ctx: &AppContext, path: &str) -> Result<Vec<u8>> {
    let client = Client::new();
    let response = client
        .get(format!("{}{}", ctx.api_url, path))
        .send()
        .await
        .with_context(|| format!("GET {path} failed"))?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .with_context(|| format!("could not read GET {path} response"))?;
    if status == StatusCode::ACCEPTED {
        bail!("PDF is still rendering. Try again in a moment.");
    }
    if !status.is_success() {
        let text = String::from_utf8_lossy(&bytes);
        bail!("{}", format_api_error(status, &text));
    }
    Ok(bytes.to_vec())
}

async fn session_get<T: for<'de> Deserialize<'de>>(ctx: &AppContext, path: &str) -> Result<T> {
    let client = Client::new();
    let response = client
        .get(format!("{}{}", ctx.api_url, path))
        .header(COOKIE, require_session_cookie(ctx)?)
        .send()
        .await
        .with_context(|| format!("GET {path} failed"))?;
    decode_response(response).await
}

async fn session_post<T: for<'de> Deserialize<'de>>(
    ctx: &AppContext,
    path: &str,
    body: serde_json::Value,
) -> Result<T> {
    let client = Client::new();
    let response = client
        .post(format!("{}{}", ctx.api_url, path))
        .header(COOKIE, require_session_cookie(ctx)?)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {path} failed"))?;
    decode_response(response).await
}

async fn session_delete(ctx: &AppContext, path: &str) -> Result<()> {
    let client = Client::new();
    let response = client
        .delete(format!("{}{}", ctx.api_url, path))
        .header(COOKIE, require_session_cookie(ctx)?)
        .send()
        .await
        .with_context(|| format!("DELETE {path} failed"))?;
    let status = response.status();
    if status == StatusCode::NO_CONTENT {
        return Ok(());
    }
    let text = response
        .text()
        .await
        .with_context(|| format!("could not read DELETE {path} response"))?;
    if !status.is_success() {
        bail!("{}", format_api_error(status, &text));
    }
    Ok(())
}

async fn api_post<T: for<'de> Deserialize<'de>>(
    ctx: &AppContext,
    path: &str,
    body: serde_json::Value,
    idempotency_key: Option<String>,
) -> Result<T> {
    let client = Client::new();
    let mut request = client
        .post(format!("{}{}", ctx.api_url, path))
        .bearer_auth(require_api_key(ctx)?)
        .json(&body);
    if let Some(key) = idempotency_key {
        request = request.header("Idempotency-Key", key);
    }
    let response = request
        .send()
        .await
        .with_context(|| format!("POST {path} failed"))?;
    decode_response(response).await
}

async fn api_delete(ctx: &AppContext, path: &str) -> Result<()> {
    let client = Client::new();
    let response = client
        .delete(format!("{}{}", ctx.api_url, path))
        .bearer_auth(require_api_key(ctx)?)
        .send()
        .await
        .with_context(|| format!("DELETE {path} failed"))?;
    let status = response.status();
    if status == StatusCode::NO_CONTENT {
        return Ok(());
    }
    let text = response
        .text()
        .await
        .with_context(|| format!("could not read DELETE {path} response"))?;
    if !status.is_success() {
        bail!("{}", format_api_error(status, &text));
    }
    Ok(())
}

fn access_grant_idempotency_key(workspace: &str, attestation: &str, email: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(workspace.as_bytes());
    hasher.update(b"\0");
    hasher.update(attestation.as_bytes());
    hasher.update(b"\0");
    hasher.update(email.trim().to_lowercase().as_bytes());
    format!("cli-access-{}", hex::encode(hasher.finalize()))
}

fn attestation_idempotency_key(
    workspace: &str,
    project: &str,
    label: &str,
    file_name: &str,
    sha256: &str,
    compliance_sha256: Option<&str>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(workspace.as_bytes());
    hasher.update(b"\0");
    hasher.update(project.as_bytes());
    hasher.update(b"\0");
    hasher.update(label.as_bytes());
    hasher.update(b"\0");
    hasher.update(file_name.as_bytes());
    hasher.update(b"\0");
    hasher.update(sha256.as_bytes());
    if let Some(compliance_sha256) = compliance_sha256 {
        hasher.update(b"\0");
        hasher.update(compliance_sha256.as_bytes());
    }
    format!("cli-attest-{}", hex::encode(hasher.finalize()))
}

fn project_idempotency_key(workspace: &str, slug: &str, name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(workspace.as_bytes());
    hasher.update(b"\0");
    hasher.update(slug.as_bytes());
    hasher.update(b"\0");
    hasher.update(name.as_bytes());
    format!("cli-project-{}", hex::encode(hasher.finalize()))
}

fn webhook_idempotency_key(
    workspace: &str,
    body: &serde_json::Map<String, serde_json::Value>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(workspace.as_bytes());
    hasher.update(b"\0");
    hasher.update(serde_json::to_string(body).unwrap_or_default().as_bytes());
    format!("cli-webhook-{}", hex::encode(hasher.finalize()))
}

fn webhook_test_idempotency_key(workspace: &str, endpoint: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(workspace.as_bytes());
    hasher.update(b"\0");
    hasher.update(endpoint.as_bytes());
    format!("cli-webhook-test-{}", hex::encode(hasher.finalize()))
}

async fn decode_response<T: for<'de> Deserialize<'de>>(response: reqwest::Response) -> Result<T> {
    let status = response.status();
    if status == StatusCode::NO_CONTENT {
        bail!("API returned no content");
    }
    let text = response
        .text()
        .await
        .context("could not read API response")?;
    if !status.is_success() {
        bail!("{}", format_api_error(status, &text));
    }
    serde_json::from_str(&text).with_context(|| format!("could not decode API response: {text}"))
}

fn format_api_error(status: StatusCode, body: &str) -> String {
    if let Ok(envelope) = serde_json::from_str::<PublicApiErrorEnvelope>(body) {
        let retry = if envelope.error.retryable {
            "retryable"
        } else {
            "not retryable"
        };
        return format!(
            "API request failed with HTTP {} ({}): {} [{}; request id: {}]",
            status.as_u16(),
            envelope.error.code,
            envelope.error.message,
            retry,
            envelope.error.request_id,
        );
    }

    let trimmed = body.trim();
    if trimmed.is_empty() {
        format!("API request failed with HTTP {}", status.as_u16())
    } else {
        format!(
            "API request failed with HTTP {}: {trimmed}",
            status.as_u16()
        )
    }
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        fs::File::open(path).with_context(|| format!("could not open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 64];
    loop {
        let bytes = file
            .read(&mut buffer)
            .with_context(|| format!("could not read {}", path.display()))?;
        if bytes == 0 {
            break;
        }
        hasher.update(&buffer[..bytes]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn compliance_json_metadata(path: &Path) -> Result<ComplianceJsonMetadata> {
    let text =
        fs::read_to_string(path).with_context(|| format!("could not read {}", path.display()))?;
    let parsed: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("could not parse {}", path.display()))?;
    if !parsed.is_object() {
        bail!("compliance JSON must be a JSON object");
    }
    let canonical = canonical_json(&parsed);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("compliance JSON file name is not valid UTF-8"))?
        .to_string();
    Ok(ComplianceJsonMetadata {
        sha256: hex::encode(Sha256::digest(canonical.as_bytes())),
        file_name,
        byte_size: canonical.len() as u64,
        media_type: "application/json",
        canonicalization: "json-stable-v1",
    })
}

fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::String(value) => serde_json::to_string(value).unwrap_or_default(),
        serde_json::Value::Array(values) => {
            let items = values.iter().map(canonical_json).collect::<Vec<_>>();
            format!("[{}]", items.join(","))
        }
        serde_json::Value::Object(values) => {
            let sorted = values
                .iter()
                .map(|(key, value)| (key, value))
                .collect::<BTreeMap<_, _>>();
            let items = sorted
                .into_iter()
                .map(|(key, value)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).unwrap_or_default(),
                        canonical_json(value)
                    )
                })
                .collect::<Vec<_>>();
            format!("{{{}}}", items.join(","))
        }
    }
}

fn ensure_hex_sha256(value: &str) -> Result<()> {
    let valid = value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit());
    if valid {
        Ok(())
    } else {
        bail!("expected a 64-character SHA-256 hex digest")
    }
}

fn normalized_sha256(value: &str) -> Result<String> {
    ensure_hex_sha256(value)?;
    Ok(value.to_lowercase())
}

fn passage_candidate_hashes(text: &str) -> Result<Vec<String>> {
    let normalized = normalize_for_shingling(text)?;
    let tokens = tokenize_normalized(&normalized);
    if tokens.iter().all(|paragraph| paragraph.len() < 7) {
        bail!("passage verification needs at least 7 normalized words from one continuous passage");
    }

    let mut seen = HashSet::new();
    let mut hashes = Vec::new();
    for (preset, window, stride) in CONTENT_PROOF_PRESETS {
        for method in CONTENT_PROOF_METHODS {
            for paragraph in &tokens {
                if paragraph.len() < window {
                    continue;
                }
                let mut index = 0;
                while index + window <= paragraph.len() {
                    let window_text = paragraph[index..index + window].join(" ");
                    let hash = shingle_payload_hash(preset, method, &window_text);
                    if seen.insert(hash.clone()) {
                        hashes.push(hash);
                    }
                    index += stride;
                }
            }
        }
    }

    if hashes.is_empty() {
        bail!(
            "passage verification needs more continuous text for the supported content proof presets"
        );
    }
    Ok(hashes)
}

fn normalize_for_shingling(text: &str) -> Result<String> {
    let mut normalized = text.nfc().collect::<String>().to_lowercase();
    normalized = normalized
        .replace(['\u{2018}', '\u{2019}'], "'")
        .replace(['\u{201c}', '\u{201d}'], "\"")
        .replace(['\u{2013}', '\u{2014}'], "-")
        .replace('\u{2026}', "...")
        .replace('\u{fb00}', "ff")
        .replace('\u{fb01}', "fi")
        .replace('\u{fb02}', "fl")
        .replace('\u{fb03}', "ffi")
        .replace('\u{fb04}', "ffl")
        .replace('\u{00ad}', "")
        .replace('\u{000c}', "\n\n");

    let hyphenated_line_break = Regex::new(r"-\n[ \t]*")?;
    normalized = hyphenated_line_break
        .replace_all(&normalized, "")
        .to_string();

    let paragraph_break = Regex::new(r"(?:[ \t\r\x0B\x0C]*\n[ \t\r\x0B\x0C]*){2,}")?;
    let punctuation = Regex::new(r##"[!"#$%&'()*+,./:;<=>?@\[\\\]^_`{|}~]"##)?;
    let paragraphs = paragraph_break
        .split(&normalized)
        .map(|paragraph| {
            let paragraph = paragraph.replace('\n', " ");
            let paragraph = punctuation.replace_all(&paragraph, " ");
            paragraph.split_whitespace().collect::<Vec<_>>().join(" ")
        })
        .filter(|paragraph| !paragraph.is_empty())
        .collect::<Vec<_>>();

    Ok(paragraphs.join("\n\n"))
}

fn tokenize_normalized(normalized: &str) -> Vec<Vec<&str>> {
    normalized
        .split("\n\n")
        .map(|paragraph| {
            paragraph
                .split(' ')
                .filter(|token| !token.is_empty())
                .collect()
        })
        .collect()
}

fn shingle_payload_hash(preset: &str, source_extraction_method: &str, window_text: &str) -> String {
    let mut payload = vec![0x02];
    append_length_prefixed(&mut payload, "1.0");
    append_length_prefixed(&mut payload, preset);
    append_length_prefixed(&mut payload, "1.0");
    append_length_prefixed(&mut payload, "1.0");
    append_length_prefixed(&mut payload, source_extraction_method);
    append_length_prefixed(&mut payload, window_text);
    hex::encode(Sha256::digest(&payload))
}

fn append_length_prefixed(payload: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    payload.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    payload.extend_from_slice(bytes);
}

fn append_query(path: &mut String, query: Vec<(&str, String)>) {
    if query.is_empty() {
        return;
    }
    let encoded = query
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&");
    path.push('?');
    path.push_str(&encoded);
}

fn require_api_key(ctx: &AppContext) -> Result<&str> {
    ctx.api_key
        .as_deref()
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .ok_or_else(|| {
            anyhow!(
                "missing API key. Set PROVERIA_API_KEY or run `proveria config set --api-key ...`"
            )
        })
}

fn require_session_cookie(ctx: &AppContext) -> Result<&str> {
    ctx.session_cookie.as_deref().ok_or_else(|| {
        anyhow!("missing admin session. Run `proveria auth login --email ... --password ...`")
    })
}

fn require_workspace(ctx: &AppContext) -> Result<&str> {
    ctx.workspace
        .as_deref()
        .ok_or_else(|| anyhow!("missing workspace slug. Set PROVERIA_WORKSPACE or run `proveria config set --workspace ...`"))
}

fn extract_session_cookie(set_cookie: &str) -> Option<String> {
    let cookie = set_cookie.split(';').next()?.trim();
    if cookie.starts_with(&format!("{SESSION_COOKIE_NAME}=")) {
        Some(cookie.to_string())
    } else {
        None
    }
}

fn normalize_api_key_scopes(scopes: Vec<String>) -> Result<Vec<String>> {
    let scopes = if scopes.is_empty() {
        vec!["read".to_string()]
    } else {
        scopes
    };
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();
    for scope in scopes {
        let scope = scope.trim().to_lowercase();
        if !matches!(scope.as_str(), "read" | "write") {
            bail!("invalid API key scope `{scope}`. Use read or write.");
        }
        if seen.insert(scope.clone()) {
            normalized.push(scope);
        }
    }
    Ok(normalized)
}

fn default_label_from_path(path: &Path) -> String {
    path.file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or("attestation")
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, ' ' | '.' | '_' | '-') {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim()
        .to_string()
}

fn load_config() -> Result<ConfigFile> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(ConfigFile::default());
    }
    let text =
        fs::read_to_string(&path).with_context(|| format!("could not read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("could not parse {}", path.display()))
}

fn save_config(config: &ConfigFile) -> Result<()> {
    let path = config_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("could not create {}", parent.display()))?;
    }
    let mut text = serde_json::to_string_pretty(config)?;
    text.push('\n');
    fs::write(&path, text).with_context(|| format!("could not write {}", path.display()))
}

fn config_path() -> Result<PathBuf> {
    let base =
        dirs::config_dir().ok_or_else(|| anyhow!("could not resolve user config directory"))?;
    Ok(base.join("proveria").join("config.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passage_hash_matches_browser_shingling_for_pdf_text() {
        let normalized = normalize_for_shingling(
            "A law firm may need to prove that a contract clause existed in the signed version of an agreement.",
        )
        .expect("normalizes");
        let tokens = tokenize_normalized(&normalized);
        let window_text = tokens[0][0..7].join(" ");
        let hash = shingle_payload_hash("standard", "pdf-text-layer/v1", &window_text);

        assert_eq!(
            hash,
            "76c18e4cee28d1ece2bf521aea85b32f6c365d02b8fd68fd4db5fa2c9bad2f3f"
        );
    }

    #[test]
    fn passage_candidates_require_a_continuous_seven_word_window() {
        let error = passage_candidate_hashes("one two three four five six")
            .expect_err("short passage should fail");

        assert!(
            error
                .to_string()
                .contains("at least 7 normalized words from one continuous passage")
        );
    }

    #[test]
    fn formats_public_api_error_envelope() {
        let body = r#"{
          "error": {
            "code": "idempotency_key_conflict",
            "message": "This Idempotency-Key was already used with a different request body.",
            "retryable": false,
            "requestId": "req_cli_1"
          }
        }"#;

        let formatted = format_api_error(StatusCode::CONFLICT, body);

        assert_eq!(
            formatted,
            "API request failed with HTTP 409 (idempotency_key_conflict): This Idempotency-Key was already used with a different request body. [not retryable; request id: req_cli_1]",
        );
    }

    #[test]
    fn formats_retryable_public_api_error_envelope() {
        let body = r#"{
          "error": {
            "code": "receipt_not_available",
            "message": "The receipt is not available yet.",
            "retryable": true,
            "requestId": "req_cli_2"
          }
        }"#;

        let formatted = format_api_error(StatusCode::ACCEPTED, body);

        assert_eq!(
            formatted,
            "API request failed with HTTP 202 (receipt_not_available): The receipt is not available yet. [retryable; request id: req_cli_2]",
        );
    }

    #[test]
    fn falls_back_for_non_json_error_body() {
        let formatted = format_api_error(StatusCode::BAD_GATEWAY, "upstream unavailable\n");

        assert_eq!(
            formatted,
            "API request failed with HTTP 502: upstream unavailable",
        );
    }

    #[test]
    fn project_idempotency_key_is_stable() {
        let first = project_idempotency_key("evaluation-workspace", "evidence", "Evidence");
        let second = project_idempotency_key("evaluation-workspace", "evidence", "Evidence");
        let different = project_idempotency_key("evaluation-workspace", "evidence-2", "Evidence");

        assert_eq!(first, second);
        assert_ne!(first, different);
        assert!(first.starts_with("cli-project-"));
    }

    #[test]
    fn access_grant_idempotency_key_normalizes_email() {
        let first =
            access_grant_idempotency_key("evaluation-workspace", "att_1", "Verifier@Example.com");
        let second =
            access_grant_idempotency_key("evaluation-workspace", "att_1", "verifier@example.com");

        assert_eq!(first, second);
        assert!(first.starts_with("cli-access-"));
    }

    #[test]
    fn canonical_json_sorts_object_keys_recursively() {
        let value = serde_json::json!({
            "b": 2,
            "a": {
                "z": false,
                "m": ["text", 1]
            }
        });

        assert_eq!(
            canonical_json(&value),
            r#"{"a":{"m":["text",1],"z":false},"b":2}"#
        );
    }

    #[test]
    fn compliance_json_metadata_hashes_canonical_object() {
        let path = std::env::temp_dir().join(format!(
            "proveria-compliance-{}-metadata.json",
            std::process::id()
        ));
        fs::write(&path, r#"{ "b": 2, "a": 1 }"#).expect("writes fixture");

        let metadata = compliance_json_metadata(&path).expect("builds metadata");

        assert_eq!(
            metadata.sha256,
            hex::encode(Sha256::digest(r#"{"a":1,"b":2}"#.as_bytes()))
        );
        assert_eq!(
            metadata.file_name,
            path.file_name().unwrap().to_str().unwrap()
        );
        assert_eq!(metadata.byte_size, 13);
        assert_eq!(metadata.media_type, "application/json");
        assert_eq!(metadata.canonicalization, "json-stable-v1");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn webhook_idempotency_keys_are_stable() {
        let mut body = serde_json::Map::new();
        body.insert(
            "url".to_string(),
            json!("https://example.com/proveria/webhooks"),
        );
        body.insert("events".to_string(), json!(["receipt.issued"]));

        let first = webhook_idempotency_key("evaluation-workspace", &body);
        let second = webhook_idempotency_key("evaluation-workspace", &body);
        let test = webhook_test_idempotency_key("evaluation-workspace", "endpoint_1");

        assert_eq!(first, second);
        assert!(first.starts_with("cli-webhook-"));
        assert!(test.starts_with("cli-webhook-test-"));
    }

    #[test]
    fn extracts_session_cookie_from_set_cookie_header() {
        let header = "proveria_session=s%3Aabc.def; Path=/; HttpOnly; SameSite=Lax";

        assert_eq!(
            extract_session_cookie(header),
            Some("proveria_session=s%3Aabc.def".to_string())
        );
    }

    #[test]
    fn ignores_unrelated_cookie_header() {
        let header = "other=value; Path=/; HttpOnly";

        assert_eq!(extract_session_cookie(header), None);
    }

    #[test]
    fn normalizes_api_key_scopes() {
        let scopes = normalize_api_key_scopes(vec![
            "READ".to_string(),
            "write".to_string(),
            "read".to_string(),
        ])
        .expect("valid scopes");

        assert_eq!(scopes, vec!["read".to_string(), "write".to_string()]);
    }
}
