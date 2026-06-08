# Proveria CLI

Command line tools for creating and verifying Proveria proof records.

The Proveria CLI is built for local hashing, API-backed attestations, receipt
downloads, verification workflows, compliance metadata, and automation from
developer or data pipelines.

## Install

Install with Homebrew:

```bash
brew tap proveria/tap
brew install proveria
```

Confirm the install:

```bash
proveria --version
proveria --help
```

For a complete walkthrough, see [Getting Started With Proveria CLI](docs/getting-started.md).

Build from source:

```bash
cargo install --path . --force
```

## Configure

Most API-backed commands require a Proveria API URL, workspace slug, and
workspace API key.

Create a short-lived workspace API key from an admin session:

```bash
proveria api-keys create \
  --name "CLI automation" \
  --scope read \
  --scope write \
  --expires-in 90d \
  --use-key
```

`--expires-in` accepts minutes, hours, days, or weeks, such as `90m`, `12h`,
`90d`, or `4w`.

```bash
proveria config set \
  --api-url https://api.example.com \
  --workspace your-workspace \
  --api-key prv_v1_...
```

Environment variables can override saved config:

```bash
export PROVERIA_API_URL=https://api.example.com
export PROVERIA_WORKSPACE=your-workspace
export PROVERIA_API_KEY=prv_v1_...
```

## Common Commands

Hash a local file without uploading it:

```bash
proveria hash ./example.pdf
```

Create a proof record from a local file:

```bash
proveria prove ./example.pdf \
  --project evaluation-evidence
```

Create a proof record from an external SHA-256 hash:

```bash
proveria prove <sha256> \
  --project evaluation-evidence \
  --name external-proof \
  --file-name invoice.pdf \
  --byte-size 1234
```

Attach compliance JSON metadata to a proof:

```bash
proveria prove ./example.pdf \
  --project evaluation-evidence \
  --compliance-json ./compliance-controls.json
```

Read a record and download receipt artifacts:

```bash
proveria records get <attestation-id>
proveria receipt <attestation-id>
proveria receipt <attestation-id> --json --pdf --output ./receipts
```

Verify a hash or file against an attestation:

```bash
proveria verify <sha256> --attestation <attestation-id>
proveria verify ./example.pdf --attestation <attestation-id>
proveria verify passage "paste a source passage here" --attestation <attestation-id>
```

Manage projects, access grants, exports, events, webhooks, and API keys:

```bash
proveria projects list
proveria attestations --project evaluation-evidence
proveria access grant <attestation-id> --email verifier@example.com
proveria export create --limit 100 --output ./evidence-export.json
proveria events --category verification_lookup --limit 25
proveria webhooks list
proveria api-keys list
```

## Compliance JSON

`--compliance-json <path>` attaches compliance metadata without uploading the
JSON body directly. The CLI:

- validates that the file contains a JSON object
- canonicalizes it with stable sorted keys
- hashes the canonical JSON locally
- sends hash metadata to the API alongside the primary proof input

Receipts for these attestations include both the primary file/hash leaf and the
compliance JSON hash leaf.

## Shell Completions

Generate completions for your shell:

```bash
proveria completions zsh > _proveria
proveria completions bash > proveria.bash
proveria completions fish > proveria.fish
```

## License

The Proveria CLI is source-available under the Proveria CLI License. You may
install, run, and inspect it for use with Proveria services. Redistribution,
modified distribution, and competing-service use are not permitted without
Proveria's written permission.
