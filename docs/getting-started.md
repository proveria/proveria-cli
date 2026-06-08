# Getting Started With Proveria CLI

This guide walks through the core Proveria CLI workflow:

- install the CLI
- configure API access
- create proof records
- attach compliance JSON
- inspect records and receipts
- verify files, hashes, and passages
- troubleshoot common errors

## Install

Install from the Proveria Homebrew tap:

```bash
brew tap proveria/tap
brew install proveria
```

Confirm the binary is available:

```bash
proveria --version
proveria --help
```

Build from source when working directly in this repository:

```bash
cargo install --path . --force
```

## Configure API Access

API-backed commands need three values:

- `api_url`: Proveria API base URL
- `workspace`: workspace slug
- `api_key`: workspace API key

If you have an admin session, create a short-lived workspace API key:

```bash
proveria auth login \
  --email admin-producer-eval@example.com \
  --password admin-producer-eval-password-123

proveria api-keys create \
  --name "CLI development" \
  --scope read \
  --scope write \
  --expires-in 90d \
  --use-key
```

`--expires-in` accepts minutes, hours, days, or weeks, such as `90m`, `12h`,
`90d`, or `4w`.
Use `proveria api-keys rotate <api-key-id> --expires-in 90d --use-key` to
create a replacement key, revoke the old key, and save the replacement locally.

Save them locally:

```bash
proveria config set \
  --api-url https://api.example.com \
  --workspace evaluation-workspace \
  --api-key prv_v1_...
```

For local development, the API URL is usually:

```bash
proveria config set \
  --api-url http://127.0.0.1:3001 \
  --workspace evaluation-workspace \
  --api-key prv_v1_...
```

Check your saved config:

```bash
proveria config show
```

Environment variables override saved config:

```bash
export PROVERIA_API_URL=http://127.0.0.1:3001
export PROVERIA_WORKSPACE=evaluation-workspace
export PROVERIA_API_KEY=prv_v1_...
```

## Create A Proof Record From A File

Use `prove` with a file path:

```bash
proveria prove ./example.pdf \
  --project evaluation-evidence \
  --name example-proof
```

The CLI hashes the file locally, then sends proof metadata to the API. The file
bytes are not uploaded by this command.

The command returns an attestation id. Save it:

```bash
ATTESTATION_ID=<attestation-id>
```

## Create A Proof Record From An External Hash

Use this when another system already produced the SHA-256 hash:

```bash
proveria prove bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --project evaluation-evidence \
  --name external-hash-proof \
  --file-name invoice.pdf \
  --byte-size 1234
```

For external hashes, `--file-name` and `--byte-size` describe the source object.
They do not upload the original file.

You can also use the explicit form:

```bash
proveria prove hash bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --project evaluation-evidence \
  --name external-hash-proof \
  --file-name invoice.pdf \
  --byte-size 1234
```

## Attach Compliance JSON

Use `--compliance-json` to attach compliance evidence to the proof record:

```bash
proveria prove ./example.pdf \
  --project evaluation-evidence \
  --name example-with-compliance \
  --compliance-json ./compliance-controls.json
```

The compliance JSON file must contain a JSON object:

```json
{
  "control_owner": "Security",
  "policy": "SOC2",
  "retention": "7 years"
}
```

The CLI:

- validates that the file is a JSON object
- canonicalizes it with stable sorted keys
- hashes the canonical JSON locally
- sends the compliance hash and metadata to the API
- does not upload the raw compliance JSON body

Receipts for these records include both the primary proof leaf and the
compliance JSON proof leaf.

## Read A Record

Use `records get` to inspect the attestation:

```bash
proveria records get "$ATTESTATION_ID"
```

Use JSON output when piping into tools:

```bash
proveria records get "$ATTESTATION_ID" --output json
```

Useful fields include:

- `id`: attestation id
- `state`: current lifecycle state
- `project`: project name and slug
- `merkle_root`: committed proof root
- `receipt`: whether receipt artifacts are available
- `confirmed_at`: confirmation timestamp

## Download Receipt Artifacts

Print receipt information:

```bash
proveria receipt "$ATTESTATION_ID"
```

Download JSON and PDF receipt artifacts:

```bash
proveria receipt "$ATTESTATION_ID" \
  --json \
  --pdf \
  --output ./receipts
```

If the receipt is not ready yet, retry after the worker has confirmed the
attestation.

## Verify A Hash Or File

Verify a SHA-256 hash against an attestation:

```bash
proveria verify bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --attestation "$ATTESTATION_ID"
```

Verify a local file:

```bash
proveria verify ./example.pdf \
  --attestation "$ATTESTATION_ID"
```

You can also use explicit forms:

```bash
proveria verify hash bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --attestation "$ATTESTATION_ID"

proveria verify file ./example.pdf \
  --attestation "$ATTESTATION_ID"
```

## Verify A Text Passage

Use passage verification for content-proof attestations:

```bash
proveria verify passage "Paste one continuous passage from the source document here." \
  --attestation "$ATTESTATION_ID"
```

Passages work best when they are one continuous sentence or paragraph. Very
short snippets may not have enough words to generate content proof hashes.

## Download Verification Result Artifacts

When verification creates a public result link, use the result id to download
artifacts:

```bash
proveria result <link-id> --json --pdf --output ./verification-result
```

The result id is the `vrf_...` identifier from the verification response or
public result URL.

## Manage Projects

List projects:

```bash
proveria projects list
```

Create a project:

```bash
proveria projects create evaluation-evidence \
  --name "Evaluation Evidence" \
  --description "Evidence used for evaluation workflows"
```

## Manage Verifier Access

Grant a verifier access to an attestation:

```bash
proveria access grant "$ATTESTATION_ID" \
  --email verifier@example.com \
  --message "Please verify this evidence package."
```

Revoke an access grant:

```bash
proveria access revoke "$ATTESTATION_ID" \
  --grant <grant-id>
```

## Manage API Keys

List workspace API keys:

```bash
proveria api-keys list
```

Create a workspace API key:

```bash
proveria api-keys create \
  --name "CLI automation" \
  --scope records:write \
  --scope records:read \
  --use-key
```

The token is shown once. Store it securely.

Revoke an API key:

```bash
proveria api-keys revoke <api-key-id>
```

## Export Evidence

Create an export:

```bash
proveria export create \
  --limit 100 \
  --output ./evidence-export.json
```

List export jobs:

```bash
proveria export jobs
```

## View Events

List recent events:

```bash
proveria events --limit 25
```

Filter by category:

```bash
proveria events --category verification_lookup --limit 25
```

## Webhooks

List webhook endpoints:

```bash
proveria webhooks list
```

Create a webhook:

```bash
proveria webhooks create \
  --url https://example.com/proveria/webhook \
  --event attestation.confirmed \
  --event verification.completed
```

Send a test event:

```bash
proveria webhooks test <endpoint-id>
```

Disable a webhook:

```bash
proveria webhooks disable <endpoint-id>
```

## Shell Completions

Generate shell completions:

```bash
proveria completions zsh > _proveria
proveria completions bash > proveria.bash
proveria completions fish > proveria.fish
```

## Common Errors

### Missing API Key

If a command says the API key is missing, configure one:

```bash
proveria config set --api-key prv_v1_...
```

Or set:

```bash
export PROVERIA_API_KEY=prv_v1_...
```

### Receipt Not Available

If `proveria receipt` says the receipt is not available, the attestation may not
be confirmed yet or the worker may still be processing it. Check the record:

```bash
proveria records get "$ATTESTATION_ID"
```

### Invalid Compliance JSON

`--compliance-json` must point to an existing file containing a JSON object.
Arrays, strings, invalid JSON, and missing files are rejected before the proof
request is sent.

### No Verification Match

A no-match result means the submitted hash or generated passage proof hash was
not found in the attestation's committed proof set. For passage verification,
try a longer continuous excerpt from the original source text.
