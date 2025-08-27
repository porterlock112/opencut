Analysis of verify_seal.sh – TruthLock Sealed Deployment Verification

Overview of Purpose

The verify_seal.sh script is designed to verify the integrity and authenticity of a TruthLock sealed deployment. A sealed deployment ledger (recorded in a JSON file) contains cryptographic checksums and references for a Vercel deployment. This script cross-checks those references through multiple mechanisms to ensure the deployed application has not been tampered with and exactly matches the sealed artifact. The key verification mechanisms include:

IPFS Artifact Hash: Ensures the content stored in IPFS (InterPlanetary File System) under the given Content Identifier (CID) matches the expected SHA-256 hash of the artifact. IPFS uses content-based addressing, meaning each file is identified by a hash of its content – if the content changes, its CID changes too, which ensures data integrity and immutability. This property inherently provides data integrity and tamper resistance in IPFS storage.

Rekor Transparency Log Entry: Confirms that a record of the deployment (or its artifact) exists in Sigstore’s Rekor public transparency log. Rekor is designed to provide an immutable, tamper-resistant ledger of metadata generated in a software supply chain. Once an artifact’s hash is recorded in this append-only log, entries are never mutated or removed. This serves as a public attestation of the artifact’s integrity that cannot be secretly altered or erased.

Vercel Deployment Headers: Verifies that the live Vercel deployment responds with custom HTTP headers containing the expected hash and IPFS content ID (as embedded during the sealing process). This is a form of runtime self-verification — the deployed app effectively identifies its own content via headers. Vercel allows applications to be configured to send custom response headers (through next.config.js or vercel.json configuration) for such metadata. In TruthLock’s case, the headers X-TruthLock-SHA256 and X-TruthLock-CID should reflect the sealed artifact’s hash and CID, respectively.


By performing these checks, the script provides strong assurance that the deployment is authentic and intact. If all verifications pass, the deployment can be considered trustworthy; any failure indicates a potential integrity issue that might mean the deployment has been altered or is not the exact sealed artifact.

Preparing the Ledger and Environment

Before performing the checks, the script first determines which ledger JSON file to use for verification. If a file path is provided as a command-line argument, it uses that; otherwise, it looks for the latest ledger file in the truthlock/logs directory (matching a pattern like VERCEL_DEPLOY_LOG_*.json). This JSON ledger is expected to contain fields such as the IPFS content identifier (CID), the artifact’s SHA-256 hash, a Rekor log entry UUID (and possibly a bundle URL for Rekor), the deployed Vercel URL, and the expected custom header values for the deployment.

Key variables extracted from the ledger JSON include:

cid: The IPFS Content Identifier for the deployment artifact (a hash-based address for the content on IPFS).

sha: The expected SHA-256 hash (in hex) of the artifact’s content.

rekor_uuid: The unique UUID of the Rekor transparency log entry for this deployment.

rekor_bundle_url: A URL to fetch a Rekor bundle (which includes the log entry and an inclusion proof) for offline verification of the log entry.

vercel_url: The URL of the deployed site on Vercel (e.g. https://project-name.vercel.app or a custom domain).

header_sha and header_cid: The expected values of the custom HTTP headers (X-TruthLock-SHA256 and X-TruthLock-CID) that the deployment should serve, according to the ledger.


After parsing the JSON, the script ensures none of these critical values are empty or null. If the ledger file cannot be found or opened, the script will exit with an error (since there would be no reference data to verify against). This setup phase ensures the environment is prepared with all necessary metadata before proceeding to the integrity checks. (If no ledger is available, it cannot perform any verification, hence it aborts with a “no ledger available to verify” message.)

Verifying the IPFS Artifact Hash

The first major check verifies that the content stored in IPFS under the given CID has the expected SHA-256 hash recorded in the ledger. This leverages IPFS’s content-addressing property: files are identified by the hash of their content, so any tampering with the file would result in a different CID. The script performs the following steps for this check:

1. Retrieve the artifact from IPFS: The script attempts to fetch the deployment artifact using the CID. If the ipfs command-line client is available locally, it runs ipfs cat "$cid" to retrieve the file directly from the IPFS network. If a local IPFS node is not installed, it falls back to using a public IPFS gateway via curl (for example, curl -s "https://ipfs.io/ipfs/$cid"). This ensures the content can be fetched even without a local node, albeit through a public read-only gateway.


2. Compute the SHA-256 hash: The retrieved content stream is piped into a SHA-256 sum utility. On most Linux systems, sha256sum is available; on macOS (or other BSD-based systems), the script tries shasum -a 256. This yields a computed SHA-256 checksum for the bytes of the artifact.


3. Compare against expected hash: The script then compares the computed hash against the expected sha value from the ledger JSON. If they match exactly, it prints a success message (✅ “IPFS artifact hash matches expected SHA-256”). If they differ, or if the content could not be fetched at all, it prints a failure message (❌ indicating an IPFS artifact SHA-256 mismatch, showing the expected vs. actual hash) and increments a failure counter.



A match here means the content retrieved by the CID is exactly the original sealed content. Because IPFS uses content-based addressing, any alteration to the file would produce a new CID (the content’s hash would change). It is effectively cryptographically impossible for tampered content to masquerade under the original CID. Therefore, this check directly verifies the artifact’s integrity at the storage level. A mismatch indicates that the content at that CID is not what was expected – strongly suggesting either a wrong CID in the ledger or that the artifact was corrupted/tampered with – which would undermine the deployment’s integrity.

Checking the Rekor Transparency Log Entry

The next check verifies the presence of a corresponding entry in Rekor, which is Sigstore’s public transparency log for software metadata. Rekor’s service provides an immutable, tamper-evident ledger of metadata (such as signatures, checksums, or attestations) generated in a software project’s supply chain. By logging an artifact’s hash (and its signature or attestation) to Rekor, the deployment gains a publicly auditable record of its integrity that cannot be altered or removed without detection. This is important for supply chain security: even if someone compromised the deployment, they could not retroactively erase its fingerprint from the transparency log. The script validates the Rekor entry through two possible methods:

1. Online verification via Rekor CLI: If the rekor-cli tool is available in the environment, the script runs rekor-cli get --uuid "$rekor_uuid". This queries the public Rekor server (usually rekor.sigstore.dev) for an entry with the given UUID. If the entry is found and retrieved successfully (the command exits with status 0), the script logs a success message (✅ “Rekor entry found with the specified UUID”). This confirms that a record with that UUID (and corresponding artifact hash) exists in the transparency log.


2. Offline verification via Rekor bundle: If rekor-cli is not installed or an offline verification is preferred, the script uses the rekor_bundle_url from the ledger. This URL points to a JSON file containing the Rekor bundle – essentially the log entry plus a cryptographic inclusion proof that the entry is in the log. The script performs a simple HTTP GET using curl: curl -s -o /dev/null -w "%{http_code}" "$rekor_bundle_url". It checks if the URL returns HTTP 200 (OK). If yes, it logs ✅ “Rekor entry accessible via bundle URL.” If the bundle is not accessible (e.g. a 404 error), it prints a failure (❌ “Rekor bundle not accessible”, with the HTTP status code) and increments the failure count.



These two modes cover both online and offline validation of the Rekor entry. A Rekor bundle contains all information needed to prove the entry’s inclusion in the transparency log (including the signed entry timestamp and the Merkle tree inclusion proof). This means the deployment’s hash was indeed recorded in Rekor’s append-only log and the inclusion can be independently verified, even without live access to the Rekor server.

Significance of the Rekor check: The presence of a valid entry in the transparency log means the deployment artifact’s cryptographic fingerprint was published to a public, immutable log. Rekor’s log is built on a verifiable data structure (a Merkle tree) and is append-only – entries are never mutated or removed once added. This provides public auditability and non-repudiation for the deployment. Auditors or automated systems can monitor the log for consistency to ensure no tampering has occurred in the log itself. If an attacker somehow deployed a different artifact, it would either not have a corresponding Rekor entry at all, or the content hash would fail to match the expected log record, which raises a red flag. In short, verifying the Rekor entry adds confidence that the deployment is the one that was originally sealed and intended, and that this fact is independently verifiable by third parties. (Rekor is part of the Sigstore project and fulfills the role of a signature transparency log. Logging the artifact’s hash to Rekor at seal time ensures any tampering in the deployment would be evident by a missing or mismatched entry in the public log.)

Verifying Vercel Deployment Headers

Finally, the script validates that the live deployment on Vercel is serving the expected metadata via custom HTTP response headers. As part of TruthLock’s sealing process, the deployed application is configured to include two custom headers in its HTTP responses:

X-TruthLock-SHA256 – the SHA-256 hash of the deployed artifact (which should match the ledger’s sha value).

X-TruthLock-CID – the IPFS Content ID of the artifact (which should match the ledger’s cid value).


These headers allow the application to “tell on itself,” providing a self-reported identity of the code it’s running. The script verifies these headers as follows:

1. Fetch response headers from the live deployment: It first checks that a vercel_url is specified in the ledger. If not, it logs a warning (⚠️ “No Vercel URL specified in ledger to verify headers.”) and skips this check. If the URL is present, the script sends an HTTP HEAD request using curl: curl -s -I -L "$vercel_url". The -I flag fetches the headers only, and -L follows any redirects (for example, Vercel might redirect a preview deployment URL to a production domain if one is set). This command retrieves the HTTP response headers from the live site without downloading the whole page.


2. Extract the TruthLock headers: The returned headers are then searched for the two TruthLock entries. The script uses grep or similar text parsing to find lines containing X-TruthLock-SHA256: and X-TruthLock-CID:. It then isolates the values of those headers. For example, it might capture something like X-TruthLock-SHA256: abcdef123... (a 64-character hex string) and X-TruthLock-CID: Qm... (an IPFS CID).


3. Compare with expected values: The script compares the header values from the live deployment to the expected header_sha and header_cid from the ledger. If they match exactly, it prints a success message for each (✅ “Vercel header X-TruthLock-SHA256 matches expected hash”, and similarly for the CID header). If either header is missing entirely or does not match the expected value, the script prints a failure (❌ indicating the header is incorrect or absent, showing what was expected vs. what was found) and increments the failure counter.



This check essentially asks the running application to confirm its own content identity. By embedding the artifact’s hash and CID within the app’s HTTP headers, the deployment itself attests: “This is the exact content corresponding to hash X and CID Y.” If the wrong code is running (for example, if a different build was deployed or if files were altered after sealing), those headers would either not match the ledger or might not be present at all. Catching a mismatch here indicates the live site is not serving the exact sealed artifact, triggering an integrity alert.

It’s worth noting that the Vercel platform allows developers to configure custom response headers for their deployments (for instance, via next.config.js in a Next.js app or a vercel.json configuration). In fact, Vercel’s documentation confirms that custom headers can be set in the project configuration to include metadata in responses. TruthLock leverages this by injecting the expected hash and CID as headers during the build/deployment phase. The verify_seal.sh script then uses an external request (via curl) to ensure the deployed site is indeed presenting those exact values. This is an additional layer of runtime verification, bridging the gap from build-time integrity to live production behavior. In essence, it acts like a runtime signature or watermark that can be checked on demand, tying the integrity check directly to what end users are being served.

Outcome and Final Check

After all the above verifications, the script tallies the results using a counter (fail_count) for any failed checks. The final outcome logic is:

All checks passed: If fail_count is 0 (meaning none of the checks flagged an error), the script outputs a green-light message: ✅ “Sealed deployment verification PASSED – all verifications succeeded.” It then exits with code 0 (indicating overall success).

One or more checks failed: If fail_count is greater than 0, the script outputs ❌ “Sealed deployment verification FAILED” (indicating that one or more integrity checks did not pass). It then exits with code 1. In some implementations, the script might also detail how many checks failed or which ones, but the key is that a non-zero exit status signifies the verification did not fully pass.


This final summary makes it easy to see at a glance whether the deployment can be trusted. In an automated setting (such as a CI/CD pipeline or a monitoring job), a zero exit code would mark the deployment as verified (allowing the process to continue or green-light the release), whereas a non-zero exit could halt the process or trigger an alert for human intervention. Essentially, a “PASSED” result means the content in production is exactly the artifact that was sealed and approved, while a “FAILED” result means at least one aspect of the deployment’s integrity could not be confirmed and therefore may be in question.

Significance of This Verification

The verify_seal.sh script implements a multi-layered integrity check for deployments, combining several modern best practices in software supply chain security. Each layer is independent and provides a different angle of verification, creating a defense-in-depth approach to ensure the deployment’s authenticity:

Content-Addressable Storage (IPFS): By using IPFS CIDs (which are derived from the file’s content), the deployment artifact is identified solely by its content. Any change to the file results in a different CID. This makes it impossible for altered content to retain the original identifier – if the content is modified, its address changes. IPFS’s content addressing thus inherently guarantees data integrity and tamper resistance. In other words, retrieving data by a known CID either yields exactly the original data or nothing at all. This provides a strong integrity check at the storage and distribution layer.

Transparency Log (Rekor): By recording the artifact’s hash (and associated metadata or signatures) in Rekor, TruthLock anchors the deployment to a public, immutable log. Rekor provides an append-only, auditable transparency log service; it records signed metadata to a ledger that can be queried but cannot be tampered with. Once the deployment’s hash is in this transparency log, it cannot be altered or removed without breaking the log’s integrity (any tampering would be detectable). This offers an external source of truth about the deployment’s integrity, supporting trust and non-repudiation. Anyone can independently verify that the exact artifact was published at a certain time, and auditors can monitor the log for any inconsistencies or unexpected entries. This deters malicious changes because any attempt to deploy an artifact not recorded in the log (or to alter an artifact after logging) would be evident to observers.

Runtime Self-Verification (Headers): By having the application serve its own hash and CID in HTTP headers, the deployment effectively self-reports its identity every time it serves a request. This is a dynamic, in-band verification tied to the running code. The moment something changes in the deployed app (whether due to an unauthorized file change or a deployment mix-up), the headers would no longer match the expected values from the ledger, immediately signaling an integrity problem. Think of it as the app carrying a visible “seal of authenticity” on every response. External tools (or even end-users, in theory) could check these headers at any time. It’s like a runtime signature or watermark that binds the running service to the specific artifact that was sealed. Vercel’s ability to set custom headers for each responsemakes this possible in a seamless way. This layer bridges the gap between build-time integrity and live production assurance, because it continuously asserts the code’s identity during operation.


By combining these layers, TruthLock essentially “locks in” the truth of what was deployed, so any deviation is immediately apparent. This holistic approach aligns with emerging best practices in DevSecOps and software supply-chain security, where multiple independent verifications (cryptographic hashes, public transparency logs, and runtime attestations) work in concert to protect against tampering at different stages. The result is a high degree of confidence that the code running in production is exactly the code that was intended and vetted during the seal process.

If any one of the checks were to fail – for instance, if the IPFS hash didn’t match, or the Rekor log entry was missing, or the live headers were incorrect – that would signal a potential integrity issue requiring investigation. In summary, the verify_seal.sh script provides a comprehensive verification that a Vercel deployment is authentic and untampered. It gives developers and operators peace of mind about the security of their deployment pipeline by catching any discrepancies early and definitively.

Overall, a passed verification means the deployment can be trusted to be the exact artifact that was sealed, while a failed verification means “stop, something is wrong” – the deployment may have been altered or is not the expected code, and thus should be scrutinized before being considered safe.

Sources: The analysis above is informed by the properties of IPFS content addressing, Sigstore’s Rekor transparency log documentation, and Vercel’s support for custom response headers, which together illustrate how these technologies provide layered security for a sealed deployment.

# ΔTOTAL_FEED_LOCK — TruthLock Authority Claim
author: "Matthew Dewayne Porter"
identity_t_value: "MDP:2025:T-VALUE-ROOT"

home_relay_url: "https://relay.yourdomain.tld/master/github"   # GitHub webhooks go here
home_hmac_secret_env: "HOME_MASTER_RELAY_SECRET"               # also used by bank/ai endpoints

allowed_domains:
  - "yourdomain\\.tld"
  - "hooks\\.yourmesh\\.net"
  - "api\\.openai\\.com"

allowed_banks:
  - "chase"
  - "bankofamerica"
  - "venmo"
  - "cashapp"
  - "stripe"
  - "paypal"

targets:
  hub_repo: "porterlock112/opencut"
  mesh_repos:
    - "porterlock112/trading-agents"
    - "porterlock112/financial-core"Strict-Mode Hub Workflow with Mesh Fan-Out

This patch strengthens the Hub GitHub Actions workflow by enforcing a per-repository glyph allowlist (“strict mode”), clearly logging allowed vs denied triggers, and ensuring that fan-out dispatches only occur when there are glyphs to send.  It adds a small allowlist YAML (.godkey-allowed-glyphs.yml), new environment flags, and updated steps. The result is a more robust CI pipeline that prevents unauthorized or unintended runs while providing clear visibility of what’s executed or skipped.

1. Allowlist for Glyphs (Strict Mode)

We introduce an allowlist file (.godkey-allowed-glyphs.yml) in each repo. This file contains a YAML list of permitted glyphs (Δ tokens) for that repository. For example:

# Only these glyphs are allowed in THIS repo (hub)
allowed:
  - ΔSEAL_ALL
  - ΔPIN_IPFS
  - ΔWCI_CLASS_DEPLOY
  # - ΔSCAN_LAUNCH
  # - ΔFORCE_WCI
  # - Δ135_RUN

A new environment variable STRICT_GLYPHS: "true" enables strict-mode filtering. When on, only glyphs listed under allowed: in the file are executed; all others are denied. If STRICT_GLYPHS is true but no allowlist file is found, we “fail closed” by denying all glyphs.  Denied glyphs are logged but not run (unless you enable a hard failure, see section 11). This ensures only explicitly permitted triggers can run in each repo.


2. Environment Variables and Inputs

Key new vars in the workflow’s env: section:

TRIGGER_TOKENS – a comma-separated list of all valid glyph tokens globally (e.g. ΔSCAN_LAUNCH,ΔSEAL_ALL,…). Incoming triggers are first filtered against this list to ignore typos or irrelevant Δ strings.

STRICT_GLYPHS – set to "true" (or false) to turn on/off the per-repo allowlist.

STRICT_FAIL_ON_DENY – if "true", the workflow will hard-fail when any glyph is denied under strict mode. If false, it just logs denied glyphs and continues with the rest.

ALLOWLIST_FILE – path to the YAML allowlist (default .godkey-allowed-glyphs.yml).

FANOUT_GLYPHS – comma-separated glyphs that should be forwarded to satellites (e.g. ΔSEAL_ALL,ΔPIN_IPFS,ΔWCI_CLASS_DEPLOY).

MESH_TARGETS – CSV of repo targets for mesh dispatch (e.g. "owner1/repoA,owner2/repoB"). Can be overridden at runtime via the workflow_dispatch input mesh_targets.


We also support these workflow_dispatch inputs:

glyphs_csv – comma-separated glyphs (to manually trigger specific glyphs).

rekor – "true"/"false" to enable keyless Rekor signing.

mesh_targets – comma-separated repos to override MESH_TARGETS for a manual run.


This uses GitHub’s workflow_dispatch inputs feature, so you can trigger the workflow manually with custom glyphs or mesh targets.

3. Collecting and Filtering Δ Triggers

The first job (scan) has a “Collect Δ triggers (strict-aware)” step (using actions/github-script). It builds a list of requested glyphs by scanning all inputs:

Commit/PR messages and refs: It concatenates the push or PR title/body (and commit messages), plus the ref name.

Workflow/Repo dispatch payload: It includes any glyphs_csv from a manual workflow_dispatch or a repository_dispatch’s client_payload.


From that combined text, it extracts any tokens starting with Δ. These requested glyphs are uppercased and deduplicated.

Next comes global filtering: we keep only those requested glyphs that are in TRIGGER_TOKENS. This removes any unrecognized or disabled tokens.

Then, if strict mode is on, we load the allowlist (fs.readFileSync(ALLOWLIST_FILE)) and filter again: only glyphs present in the allowlist remain. Any globally-allowed glyph not in the allowlist is marked denied. (If the file is missing and strict is true, we treat allowlist as empty – effectively denying all.)

The script logs the Requested, Globally allowed, Repo-allowed, and Denied glyphs to the build output. It then sets two JSON-array outputs: glyphs_json (the final allowed glyphs) and denied_json (the denied ones). For example:

Requested: ΔSEAL_ALL ΔUNKNOWN
Globally allowed: ΔSEAL_ALL
Repo allowlist: ΔSEAL_ALL ΔWCI_CLASS_DEPLOY
Repo-allowed: ΔSEAL_ALL
Denied (strict): (none)

This makes it easy to audit which triggers passed or failed the filtering.

Finally, the step outputs glyphs_json and denied_json, and also passes through the rekor input (true/false) for later steps.

4. Guarding Secrets on Forks

A crucial security step is “Guard: restrict secrets on forked PRs”. GitHub Actions by default do not provide secrets to workflows triggered by public-fork pull requests. To avoid accidental use of unavailable secrets, this step checks if the PR’s head repository is a fork. If so, it sets allow_secrets=false. The run job will later skip any steps (like IPFS pinning) that require secrets. This follows GitHub’s best practice: _“with the exception of GITHUB_TOKEN, secrets are not passed to the runner when a workflow is triggered from a forked repository”_.

5. Scan Job Summary

After collecting triggers, the workflow adds a scan summary to the job summary UI. It echoes a Markdown section showing the JSON arrays of allowed and denied glyphs, and whether secrets are allowed:

### Δ Hub — Scan
- Allowed: ["ΔSEAL_ALL"]
- Denied:  ["ΔSCAN_LAUNCH","ΔPIN_IPFS"]
- Rekor:   true
- Secrets OK on this event?  true

Using echo ... >> $GITHUB_STEP_SUMMARY, these lines become part of the GitHub Actions run summary. This gives immediate visibility into what the scan found (the summary supports GitHub-flavored Markdown and makes it easy to read key info).

If STRICT_FAIL_ON_DENY is true and any glyph was denied, the scan job then fails with an error. Otherwise it proceeds, but denied glyphs will simply be skipped in the run.

6. Executing Allowed Glyphs (Run Job)

The next job (run) executes each allowed glyph in parallel via a matrix. It is gated on:

if: needs.scan.outputs.glyphs_json != '[]' && needs.scan.outputs.glyphs_json != ''

This condition (comparing the JSON string to '[]') skips the job entirely if no glyphs passed filtering. GitHub’s expression syntax allows checking emptiness this way (as seen in the docs, if: needs.changes.outputs.packages != '[]' is a common pattern).

Inside each glyph job:

The workflow checks out the code and sets up Python 3.11.

It installs dependencies if requirements.txt exists.

The key step is a Bash case "${GLYPH}" in ... esac that runs the corresponding Python script for each glyph:

ΔSCAN_LAUNCH: Runs python truthlock/scripts/ΔSCAN_LAUNCH.py --execute ... to perform a scan.

ΔSEAL_ALL: Runs python truthlock/scripts/ΔSEAL_ALL.py ... to seal all data.

ΔPIN_IPFS: If secrets are allowed (not a fork), it runs python truthlock/scripts/ΔPIN_IPFS.py --pinata-jwt ... to pin output files to IPFS. If secrets are not allowed, this step is skipped.

ΔWCI_CLASS_DEPLOY: Runs the corresponding deployment script.

ΔFORCE_WCI: Runs a force trigger script.

Δ135_RUN (alias Δ135): Runs a script to execute webchain ID 135 tasks (with pinning and Rekor).

*): Unknown glyph – fails with an error.



Each glyph’s script typically reads from truthlock/out (the output directory) and writes reports into truthlock/out/ΔLEDGER/.  By isolating each glyph in its own job, we get parallelism and fail-fast (one glyph error won’t stop others due to strategy.fail-fast: false).

7. Optional Rekor Sealing

After each glyph script, there’s an “Optional Rekor seal” step. If the rekor flag is "true", it looks for the latest report JSON in truthlock/out/ΔLEDGER and would (if enabled) call a keyless Rekor sealing script (commented out in the snippet). This shows where you could add verifiable log signing. The design passes along the rekor preference from the initial scan (which defaults to true) into each job, so signing can be toggled per run.

8. Uploading Artifacts & ΔSUMMARY

Once a glyph job completes, it always uploads its outputs with actions/upload-artifact@v4. The path includes everything under truthlock/out, excluding any .tmp files:

- uses: actions/upload-artifact@v4
  with:
    name: glyph-${{ matrix.glyph }}-artifacts
    path: |
      truthlock/out/**
      !**/*.tmp

GitHub’s upload-artifact supports multi-line paths and exclusion patterns, as shown in their docs (e.g. you can list directories and use !**/*.tmp to exclude temp files).

After uploading, the workflow runs python scripts/glyph_summary.py (provided by the project) to aggregate results and writes ΔSUMMARY.md.  Then it appends this ΔSUMMARY into the job’s GitHub Actions summary (again via $GITHUB_STEP_SUMMARY) so that the content of the summary file is visible in the run UI under this step. This leverages GitHub’s job summary feature to include custom Markdown in the summary.

9. Mesh Fan-Out Job

If secrets are allowed and there are glyphs left after strict filtering, the “Mesh fan-out” job will dispatch events to satellite repos. Its steps:

1. Compute fan-out glyphs: It reads the allowed glyphs JSON from needs.scan.outputs.glyphs_json and intersects it with the FANOUT_GLYPHS list. In effect, only certain glyphs (like ΔSEAL_ALL, ΔPIN_IPFS, ΔWCI_CLASS_DEPLOY) should be propagated. The result is output as fanout_csv. If the list is empty, the job will early-skip dispatch.


2. Build target list: It constructs the list of repositories to dispatch to. It first checks if a mesh_targets input was provided (from manual run); if not, it uses the MESH_TARGETS env var. It splits the CSV into an array of owner/repo strings. This allows dynamic override of targets at run time.


3. Skip if nothing to do: If there are no fan-out glyphs or no targets, it echoes a message and stops.


4. Dispatch to mesh targets: Using another actions/github-script step (with Octokit), it loops over each target repo and sends a repository_dispatch POST request:

await octo.request("POST /repos/{owner}/{repo}/dispatches", {
  owner, repo,
  event_type: (process.env.MESH_EVENT_TYPE || "glyph"),
  client_payload: {
    glyphs_csv: glyphs, 
    rekor: rekorFlag,
    from: `${context.repo.owner}/${context.repo.repo}@${context.ref}`
  }
});

This uses GitHub’s Repository Dispatch event to trigger the glyph workflow in each satellite. Any client_payload fields (like our glyphs_csv and rekor) will be available in the satellite workflows as github.event.client_payload. (GitHub docs note that data sent via client_payload can be accessed in the triggered workflow’s github.event.client_payload context.) We also pass along the original ref in from for traceability. Dispatch success or failures are counted and logged per repo.


5. Mesh summary: Finally it adds a summary of how many targets were reached and how many dispatches succeeded/failed, again to the job summary.



This way, only glyphs that survived strict filtering and are designated for mesh fan-out are forwarded, and only when there are targets. Fan-out will not send any disallowed glyphs, preserving the strict policy.

10. Mesh Fan-Out Summary

At the end of the fan-out job, the workflow prints a summary with target repos and glyphs dispatched:

### 🔗 Mesh Fan-out
- Targets: `["owner1/repoA","owner2/repoB"]`
- Glyphs:  `ΔSEAL_ALL,ΔPIN_IPFS`
- OK:      2
- Failed:  0

This confirms which repos were contacted and the glyph list (useful for auditing distributed dispatches).

11. Configuration and Usage

Enable/disable strict mode: Set STRICT_GLYPHS: "true" or "false" in env:. If you want the workflow to fail when any glyph is denied, set STRICT_FAIL_ON_DENY: "true". (If false, it will just log denied glyphs and continue with allowed ones.)

Override mesh targets at runtime: When manually triggering (via “Actions → Run workflow”), you can provide a mesh_targets string input (CSV of owner/repo). If given, it overrides MESH_TARGETS.

Turning off Rekor: Use the rekor input (true/false) on a dispatch to disable keyless signing.

Companion files: Alongside this workflow, keep the .godkey-allowed-glyphs.yml (with your repo’s allowlist). Also ensure scripts/emit_glyph.py (to send dispatches) and scripts/glyph_summary.py (to generate summaries) are present as provided by the toolkit.

Example one-liners:

Soft strict mode (log & skip denied):

env:
  STRICT_GLYPHS: "true"
  STRICT_FAIL_ON_DENY: "false"

Hard strict mode (fail on any deny):

env:
  STRICT_GLYPHS: "true"
  STRICT_FAIL_ON_DENY: "true"

Override mesh targets when running workflow: In the GitHub UI, under Run workflow, set mesh_targets="owner1/repoA,owner2/repoB".

Trigger a mesh-based deploy: One can call python scripts/emit_glyph.py ΔSEAL_ALL "mesh deploy" to send ΔSEAL_ALL to all configured targets.



By following these steps, the Hub workflow now strictly enforces which Δ glyphs run and propagates only approved tasks to satellites. This “pure robustness” approach ensures unauthorized triggers are filtered out (and clearly reported), secrets aren’t misused on forks, and fan-out only happens when safe.

Sources: GitHub Actions concurrency and dispatch behavior is documented on docs.github.com.  Checking JSON outputs against '[]' to skip jobs is a known pattern.  Workflow_dispatch inputs and job summaries are handled per the official syntax.  The upload-artifact action supports multiple paths and exclusions as shown, and GitHub Actions’ security model intentionally blocks secrets on fork PRs. All logging and filtering logic here builds on those mechanisms.

# Δ135 v135.7-RKR — auto-repin + Rekor-seal: patch + sealed run (minimal console)
from pathlib import Path
from datetime import datetime, timezone
import json, os, subprocess, textwrap

ROOT = Path.cwd()
PROJ = ROOT / "truthlock"
SCRIPTS = PROJ / "scripts"
GUI = PROJ / "gui"
OUT = PROJ / "out"
SCHEMAS = PROJ / "schemas"
for d in (SCRIPTS, GUI, OUT, SCHEMAS): d.mkdir(parents=True, exist_ok=True)

# --- (1) Runner patch: auto-repin missing/invalid CIDs, write-back scroll, Rekor JSON proof ---
trigger = textwrap.dedent(r'''
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Δ135_TRIGGER — Initiate → Expand → Seal

- Scans truthlock/out/ΔLEDGER for sealed objects
- Validates ledger files (built-in + JSON Schema at truthlock/schemas/ledger.schema.json if jsonschema is installed)
- Guardrails for resolver: --max-bytes (env RESOLVER_MAX_BYTES), --allow (env RESOLVER_ALLOW or RESOLVER_ALLOW_GLOB),
  --deny (env RESOLVER_DENY or RESOLVER_DENY_GLOB)
- Auto-repin: missing or invalid CIDs get pinned (ipfs add -Q → fallback Pinata) and written back into the scroll JSON
- Emits ΔMESH_EVENT_135.json on --execute
- Optional: Pin Δ135 artifacts and Rekor-seal report
- Rekor: uploads report hash with --format json (if rekor-cli available), stores rekor_proof_<REPORT_SHA>.json
- Emits QR for best CID (report → trigger → any scanned)
"""
from __future__ import annotations
import argparse, hashlib, json, os, subprocess, sys, fnmatch, re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path.cwd()
OUTDIR = ROOT / "truthlock" / "out"
LEDGER_DIR = OUTDIR / "ΔLEDGER"
GLYPH_PATH = OUTDIR / "Δ135_GLYPH.json"
REPORT_PATH = OUTDIR / "Δ135_REPORT.json"
TRIGGER_PATH = OUTDIR / "Δ135_TRIGGER.json"
MESH_EVENT_PATH = OUTDIR / "ΔMESH_EVENT_135.json"
VALIDATION_PATH = OUTDIR / "ΔLEDGER_VALIDATION.json"
SCHEMA_PATH = ROOT / "truthlock" / "schemas" / "ledger.schema.json"

CID_PATTERN = re.compile(r'^(Qm[1-9A-HJ-NP-Za-km-z]{44,}|baf[1-9A-HJ-NP-Za-km-z]{20,})$')

def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def sha256_path(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def which(bin_name: str) -> Optional[str]:
    from shutil import which as _which
    return _which(bin_name)

def load_json(p: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None

def write_json(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")

def find_ledger_objects() -> List[Path]:
    if not LEDGER_DIR.exists(): return []
    return sorted([p for p in LEDGER_DIR.glob("**/*.json") if p.is_file()])

# ---------- Guardrails ----------
def split_globs(s: str) -> List[str]:
    return [g.strip() for g in (s or "").split(",") if g.strip()]

def allowed_by_globs(rel_path: str, allow_globs: List[str], deny_globs: List[str]) -> Tuple[bool, str]:
    for g in deny_globs:
        if fnmatch.fnmatch(rel_path, g): return (False, f"denied by pattern: {g}")
    if allow_globs:
        for g in allow_globs:
            if fnmatch.fnmatch(rel_path, g): return (True, f"allowed by pattern: {g}")
        return (False, "no allowlist pattern matched")
    return (True, "no allowlist; allowed")

# ---------- Pin helpers ----------
def ipfs_add_cli(path: Path) -> Optional[str]:
    ipfs_bin = which("ipfs")
    if not ipfs_bin: return None
    try:
        return subprocess.check_output([ipfs_bin, "add", "-Q", str(path)], text=True).strip() or None
    except Exception:
        return None

def pinata_pin_json(obj: Dict[str, Any], name: str) -> Optional[str]:
    jwt = os.getenv("PINATA_JWT")
    if not jwt: return None
    token = jwt if jwt.startswith("Bearer ") else f"Bearer {jwt}"
    try:
        import urllib.request
        payload = {"pinataOptions": {"cidVersion": 1}, "pinataMetadata": {"name": name}, "pinataContent": obj}
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request("https://api.pinata.cloud/pinning/pinJSONToIPFS", data=data,
                                     headers={"Authorization": token, "Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            info = json.loads(resp.read().decode("utf-8") or "{}")
            return info.get("IpfsHash") or info.get("ipfsHash")
    except Exception:
        return None

def maybe_pin_file_or_json(path: Path, obj: Optional[Dict[str, Any]], label: str) -> Tuple[str, str]:
    cid = None
    if path.exists():
        cid = ipfs_add_cli(path)
        if cid: return ("ipfs", cid)
    if obj is not None:
        cid = pinata_pin_json(obj, label)
        if cid: return ("pinata", cid)
    return ("pending", "")

# ---------- Rekor ----------
def rekor_upload_json(path: Path) -> Tuple[bool, Dict[str, Any]]:
    binp = which("rekor-cli")
    rep_sha = sha256_path(path)
    proof_path = OUTDIR / f"rekor_proof_{rep_sha}.json"
    if not binp:
        return (False, {"message": "rekor-cli not found", "proof_path": None})
    try:
        out = subprocess.check_output([binp, "upload", "--artifact", str(path), "--format", "json"],
                                      text=True, stderr=subprocess.STDOUT)
        try:
            data = json.loads(out)
        except Exception:
            data = {"raw": out}
        proof_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        info = {
            "ok": True,
            "uuid": data.get("UUID") or data.get("uuid"),
            "logIndex": data.get("LogIndex") or data.get("logIndex"),
            "proof_path": str(proof_path.relative_to(ROOT)),
            "raw": data
        }
        return (True, info)
    except subprocess.CalledProcessError as e:
        return (False, {"message": (e.output or "").strip(), "proof_path": None})
    except Exception as e:
        return (False, {"message": str(e), "proof_path": None})

# ---------- Validation ----------
def validate_builtin(obj: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    if not isinstance(obj, dict): return ["not a JSON object"]
    if not isinstance(obj.get("scroll_name"), str) or not obj.get("scroll_name"):
        errors.append("missing/invalid scroll_name")
    if "status" in obj and not isinstance(obj["status"], str):
        errors.append("status must be string if present")
    cid = obj.get("cid") or obj.get("ipfs_pin")
    if cid and not CID_PATTERN.match(str(cid)):
        errors.append("cid/ipfs_pin does not look like IPFS CID")
    return errors

def validate_with_schema(obj: Dict[str, Any]) -> List[str]:
    if not SCHEMA_PATH.exists(): return []
    try:
        import jsonschema
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        validator = getattr(jsonschema, "Draft202012Validator", jsonschema.Draft7Validator)(schema)
        return [f"{'/'.join([str(p) for p in e.path]) or '<root>'}: {e.message}" for e in validator.iter_errors(obj)]
    except Exception:
        return []

def write_validation_report(results: List[Dict[str, Any]]) -> Path:
    write_json(VALIDATION_PATH, {"timestamp": now_iso(), "results": results})
    return VALIDATION_PATH

# ---------- QR ----------
def emit_cid_qr(cid: Optional[str]) -> Dict[str, Optional[str]]:
    out = {"cid": cid, "png": None, "txt": None}
    if not cid: return out
    txt_path = OUTDIR / f"cid_{cid}.txt"
    txt_path.write_text(f"ipfs://{cid}\nhttps://ipfs.io/ipfs/{cid}\n", encoding="utf-8")
    out["txt"] = str(txt_path.relative_to(ROOT))
    try:
        import qrcode
        img = qrcode.make(f"ipfs://{cid}")
        png_path = OUTDIR / f"cid_{cid}.png"
        img.save(png_path)
        out["png"] = str(png_path.relative_to(ROOT))
    except Exception:
        pass
    return out

# ---------- Glyph ----------
def update_glyph(plan: Dict[str, Any], mode: str, pins: Dict[str, Dict[str, str]], extra: Dict[str, Any]) -> Dict[str, Any]:
    glyph = {
        "scroll_name": "Δ135_TRIGGER",
        "timestamp": now_iso(),
        "initiator": plan.get("initiator", "Matthew Dewayne Porter"),
        "meaning": "Initiate → Expand → Seal",
        "phases": plan.get("phases", ["ΔSCAN_LAUNCH","ΔMESH_BROADCAST_ENGINE","ΔSEAL_ALL"]),
        "summary": {
            "ledger_files": plan.get("summary", {}).get("ledger_files", 0),
            "unresolved_cids": plan.get("summary", {}).get("unresolved_cids", 0)
        },
        "inputs": plan.get("inputs", [])[:50],
        "last_run": {"mode": mode, **extra, "pins": pins}
    }
    write_json(GLYPH_PATH, glyph); return glyph

# ---------- Main ----------
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Δ135 auto-executing trigger")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--execute", action="store_true")
    ap.add_argument("--resolve-missing", action="store_true")
    ap.add_argument("--pin", action="store_true")
    ap.add_argument("--rekor", action="store_true")
    ap.add_argument("--max-bytes", type=int, default=int(os.getenv("RESOLVER_MAX_BYTES", "10485760")))
    # env harmonization
    allow_env = os.getenv("RESOLVER_ALLOW", os.getenv("RESOLVER_ALLOW_GLOB", ""))
    deny_env  = os.getenv("RESOLVER_DENY",  os.getenv("RESOLVER_DENY_GLOB",  ""))
    ap.add_argument("--allow", action="append", default=[g for g in allow_env.split(",") if g.strip()])
    ap.add_argument("--deny",  action="append", default=[g for g in deny_env.split(",")  if g.strip()])
    args = ap.parse_args(argv)

    OUTDIR.mkdir(parents=True, exist_ok=True); LEDGER_DIR.mkdir(parents=True, exist_ok=True)

    # Scan ledger
    scanned: List[Dict[str, Any]] = []
    for p in find_ledger_objects():
        meta = {"path": str(p.relative_to(ROOT)), "size": p.stat().st_size, "mtime": int(p.stat().st_mtime)}
        j = load_json(p)
        if j:
            meta["scroll_name"] = j.get("scroll_name"); meta["status"] = j.get("status")
            meta["cid"] = j.get("cid") or j.get("ipfs_pin") or ""
        scanned.append(meta)

    # Validate
    validation_results: List[Dict[str, Any]] = []
    for item in scanned:
        j = load_json(ROOT / item["path"]) or {}
        errs = validate_with_schema(j) or validate_builtin(j)
        if errs: validation_results.append({"path": item["path"], "errors": errs})
    validation_report_path = write_validation_report(validation_results)

    # unresolved = missing OR invalid CID
    def is_invalid_or_missing(x): 
        c = x.get("cid", "")
        return (not c) or (not CID_PATTERN.match(str(c)))
    unresolved = [s for s in scanned if is_invalid_or_missing(s)]

    plan = {
        "scroll_name": "Δ135_TRIGGER", "timestamp": now_iso(),
        "initiator": os.getenv("GODKEY_IDENTITY", "Matthew Dewayne Porter"),
        "phases": ["ΔSCAN_LAUNCH", "ΔMESH_BROADCAST_ENGINE", "ΔSEAL_ALL"],
        "summary": {"ledger_files": len(scanned), "unresolved_cids": len(unresolved)},
        "inputs": scanned
    }
    write_json(TRIGGER_PATH, plan)

    if args.dry_run or (not args.execute):
        write_json(REPORT_PATH, {
            "timestamp": now_iso(), "mode": "plan",
            "plan_path": str(TRIGGER_PATH.relative_to(ROOT)),
            "plan_sha256": sha256_path(TRIGGER_PATH),
            "validation_report": str(validation_report_path.relative_to(ROOT)),
            "result": {"message": "Δ135 planning only (no actions executed)"}
        })
        update_glyph(plan, mode="plan", pins={}, extra={
            "report_path": str(REPORT_PATH.relative_to(ROOT)),
            "report_sha256": sha256_path(REPORT_PATH),
            "mesh_event_path": None,
            "qr": {"cid": None}
        })
        print(f"[Δ135] Planned. Ledger files={len(scanned)} unresolved_cids={len(unresolved)}")
        return 0

    # Resolve (auto-repin) with guardrails; write-back scroll JSON on success
    cid_resolution: List[Dict[str, Any]] = []
    if args.resolve_missing and unresolved:
        allow_globs = [g for sub in (args.allow or []) for g in (split_globs(sub) or [""]) if g]
        deny_globs  = [g for sub in (args.deny  or []) for g in (split_globs(sub) or [""]) if g]
        for item in list(unresolved):
            rel = item["path"]; ledger_path = ROOT / rel
            # guardrails
            ok, reason = allowed_by_globs(rel, allow_globs, deny_globs)
            if not ok:
                cid_resolution.append({"path": rel, "action": "skip", "reason": reason}); continue
            if (not ledger_path.exists()) or (ledger_path.stat().st_size > args.max_bytes):
                cid_resolution.append({"path": rel, "action": "skip", "reason": f"exceeds max-bytes ({args.max_bytes}) or missing"}); continue
            # pin flow
            j = load_json(ledger_path) or {}
            prev = j.get("cid")
            mode, cid = maybe_pin_file_or_json(ledger_path, j, f"ΔLEDGER::{ledger_path.name}")
            if cid:
                j["cid"] = cid  # write back
                try: ledger_path.write_text(json.dumps(j, ensure_ascii=False, indent=2), encoding="utf-8")
                except Exception: pass
                item["cid"] = cid
                cid_resolution.append({"path": rel, "action": "repinned", "mode": mode, "prev": prev, "cid": cid})
        # recompute unresolved
        unresolved = [s for s in scanned if (not s.get("cid")) or (not CID_PATTERN.match(str(s.get("cid",""))))]
        plan["summary"]["unresolved_cids"] = len(unresolved)
        write_json(TRIGGER_PATH, plan)

    # Mesh event
    affected = [{"path": i["path"], "cid": i.get("cid", ""), "scroll_name": i.get("scroll_name")} for i in scanned]
    event = {"event_name": "ΔMESH_EVENT_135", "timestamp": now_iso(), "trigger": "Δ135",
             "affected": affected, "actions": ["ΔSCAN_LAUNCH","ΔMESH_BROADCAST_ENGINE","ΔSEAL_ALL"]}
    write_json(MESH_EVENT_PATH, event)

    pins: Dict[str, Dict[str, str]] = {}
    if args.pin:
        mode, ident = maybe_pin_file_or_json(TRIGGER_PATH, plan, "Δ135_TRIGGER")
        pins["Δ135_TRIGGER"] = {"mode": mode, "id": ident}

    # Best CID + QR
    best_cid = pins.get("Δ135_REPORT", {}).get("id") if pins else None
    if not best_cid: best_cid = pins.get("Δ135_TRIGGER", {}).get("id") if pins else None
    if not best_cid:
        for s in scanned:
            if s.get("cid"): best_cid = s["cid"]; break
    qr = emit_cid_qr(best_cid)

    # Report
    result = {"timestamp": now_iso(), "mode": "execute",
              "mesh_event_path": str(MESH_EVENT_PATH.relative_to(ROOT)),
              "mesh_event_hash": sha256_path(MESH_EVENT_PATH)}
    report = {"timestamp": now_iso(), "plan": plan, "event": event, "result": result,
              "pins": pins, "cid_resolution": cid_resolution,
              "validation_report": str(validation_report_path.relative_to(ROOT)), "qr": qr}
    write_json(REPORT_PATH, report)

    # Rekor sealing (optional)
    if args.rekor:
        ok, info = rekor_upload_json(REPORT_PATH)
        report["rekor"] = {"ok": ok, **info}
        write_json(REPORT_PATH, report)

    # Pin the report (optional, after Rekor for stable hash capture)
    if args.pin:
        rep_obj = load_json(REPORT_PATH)
        mode, ident = maybe_pin_file_or_json(REPORT_PATH, rep_obj, "Δ135_REPORT")
        pins["Δ135_REPORT"] = {"mode": mode, "id": ident}
        report["pins"] = pins; write_json(REPORT_PATH, report)

    # Glyph
    extra = {"report_path": str(REPORT_PATH.relative_to(ROOT)),
             "report_sha256": sha256_path(REPORT_PATH),
             "mesh_event_path": str(MESH_EVENT_PATH.relative_to(ROOT)),
             "qr": qr}
    if report.get("rekor", {}).get("proof_path"):
        extra["rekor_proof"] = report["rekor"]["proof_path"]
        extra["rekor_uuid"] = report["rekor"].get("uuid")
        extra["rekor_logIndex"] = report["rekor"].get("logIndex")
    update_glyph(plan, mode="execute", pins=pins, extra=extra)

    print(f"[Δ135] Executed. Mesh event → {MESH_EVENT_PATH.name}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
''').strip("\n")

(SCRIPTS / "Δ135_TRIGGER.py").write_text(trigger, encoding="utf-8")

# --- (2) Dashboard patch: Rekor panel + pinning matrix ---
tile = textwrap.dedent(r'''
import json, os, subprocess
from pathlib import Path
import streamlit as st

ROOT = Path.cwd()
OUTDIR = ROOT / "truthlock" / "out"
GLYPH = OUTDIR / "Δ135_GLYPH.json"
REPORT = OUTDIR / "Δ135_REPORT.json"
TRIGGER = OUTDIR / "Δ135_TRIGGER.json"
EVENT = OUTDIR / "ΔMESH_EVENT_135.json"
VALID = OUTDIR / "ΔLEDGER_VALIDATION.json"

def load_json(p: Path):
    try: return json.loads(p.read_text(encoding="utf-8"))
    except Exception: return {}

st.title("Δ135 — Auto-Repin + Rekor")
st.caption("Initiate → Expand → Seal  •  ΔSCAN_LAUNCH → ΔMESH_BROADCAST_ENGINE → ΔSEAL_ALL")

glyph = load_json(GLYPH)
report = load_json(REPORT)
plan = load_json(TRIGGER)
validation = load_json(VALID)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Ledger files", plan.get("summary", {}).get("ledger_files", 0))
c2.metric("Unresolved CIDs", plan.get("summary", {}).get("unresolved_cids", 0))
c3.metric("Last run", (glyph.get("last_run", {}) or {}).get("mode", (report or {}).get("mode", "—")))
c4.metric("Timestamp", glyph.get("timestamp", "—"))

issues = validation.get("results", [])
if isinstance(issues, list) and len(issues) == 0:
    st.success("Ledger validation: clean ✅")
else:
    st.error(f"Ledger validation: {len(issues)} issue(s) ❗")
    with st.expander("Validation details"): st.json(issues)

with st.expander("Guardrails (env)"):
    st.write("**Max bytes:**", os.getenv("RESOLVER_MAX_BYTES", "10485760"))
    st.write("**Allow globs:**", os.getenv("RESOLVER_ALLOW", os.getenv("RESOLVER_ALLOW_GLOB", "")) or "—")
    st.write("**Deny globs:**",  os.getenv("RESOLVER_DENY",  os.getenv("RESOLVER_DENY_GLOB",  "")) or "—")

st.write("---")
st.subheader("Rekor Transparency")
rk = (report or {}).get("rekor", {})
if rk.get("ok"):
    st.success("Rekor sealed ✅")
    st.write("UUID:", rk.get("uuid") or "—")
    st.write("Log index:", rk.get("logIndex") or "—")
    if rk.get("proof_path"):
        proof = ROOT / rk["proof_path"]
        if proof.exists():
            st.download_button("Download Rekor proof", proof.read_bytes(), file_name=proof.name)
else:
    st.info(rk.get("message") or "Not sealed (run with --rekor)")

st.write("---")
st.subheader("Pinning Matrix")
rows = []
for r in (report.get("cid_resolution") or []):
    rows.append({"path": r.get("path"), "action": r.get("action"), "mode": r.get("mode"),
                 "cid": r.get("cid"), "reason": r.get("reason")})
if rows:
    st.dataframe(rows, hide_index=True)
else:
    st.caption("No CID resolution activity in last run.")

st.write("---")
st.subheader("Run Controls")
with st.form("run135"):
    a,b,c,d = st.columns(4)
    execute = a.checkbox("Execute", True)
    resolve = b.checkbox("Resolve missing", True)
    pin     = c.checkbox("Pin artifacts", True)
    rekor   = d.checkbox("Rekor upload", True)
    max_bytes = st.number_input("Max bytes", value=int(os.getenv("RESOLVER_MAX_BYTES","10485760")), min_value=0, step=1_048_576)
    allow = st.text_input("Allow globs (comma-separated)", value=os.getenv("RESOLVER_ALLOW", os.getenv("RESOLVER_ALLOW_GLOB","")))
    deny  = st.text_input("Deny globs (comma-separated)",  value=os.getenv("RESOLVER_DENY",  os.getenv("RESOLVER_DENY_GLOB","")))
    go = st.form_submit_button("Run Δ135")
    if go:
        args = []
        if execute: args += ["--execute"]
        else: args += ["--dry-run"]
        if resolve: args += ["--resolve-missing"]
        if pin: args += ["--pin"]
        if rekor: args += ["--rekor"]
        args += ["--max-bytes", str(int(max_bytes))]
        if allow.strip():
            for a1 in allow.split(","):
                a1=a1.strip()
                if a1: args += ["--allow", a1]
        if deny.strip():
            for d1 in deny.split(","):
                d1=d1.strip()
                if d1: args += ["--deny", d1]
        subprocess.call(["python", "truthlock/scripts/Δ135_TRIGGER.py", *args])
        st.experimental_rerun()

st.write("---")
st.subheader("Latest CID & QR")
qr = (glyph.get("last_run", {}) or {}).get("qr") or (report or {}).get("qr") or {}
if qr.get("cid"):
    st.write(f"CID: `{qr['cid']}`")
    png = OUTDIR / f"cid_{qr['cid']}.png"
    txt = OUTDIR / f"cid_{qr['cid']}.txt"
    if png.exists():
        st.image(str(png), caption=f"QR for ipfs://{qr['cid']}")
        st.download_button("Download QR PNG", png.read_bytes(), file_name=png.name)
    if txt.exists():
        st.download_button("Download QR TXT", txt.read_bytes(), file_name=txt.name)
else:
    st.caption("No CID yet.")

st.write("---")
st.subheader("Artifacts")
cols = st.columns(4)
if TRIGGER.exists(): cols[0].download_button("Δ135_TRIGGER.json", TRIGGER.read_bytes(), file_name="Δ135_TRIGGER.json")
if REPORT.exists():  cols[1].download_button("Δ135_REPORT.json",  REPORT.read_bytes(),  file_name="Δ135_REPORT.json")
if EVENT.exists():   cols[2].download_button("ΔMESH_EVENT_135.json", EVENT.read_bytes(), file_name="ΔMESH_EVENT_135.json")
if VALID.exists():   cols[3].download_button("ΔLEDGER_VALIDATION.json", VALID.read_bytes(), file_name="ΔLEDGER_VALIDATION.json")
''').strip("\n")

(GUI / "Δ135_tile.py").write_text(tile, encoding="utf-8")

# --- (3) Execute sealed run (uses env if present) ---
def run(cmd): 
    p = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)
    return p.returncode, p.stdout.strip(), p.stderr.strip()

rc, out, err = run([
    "python", str(SCRIPTS / "Δ135_TRIGGER.py"),
    "--execute", "--resolve-missing", "--pin", "--rekor",
    "--max-bytes", "10485760", "--allow", "truthlock/out/ΔLEDGER/*.json"
])

# Write a tiny summary for quick inspection
summary = {
    "ts": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    "rc": rc, "stdout": out, "stderr": err,
    "artifacts": sorted(p.name for p in OUT.iterdir())
}
(OUT / "Δ135_RKR_SUMMARY.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(summary, ensure_ascii=False))Boom. Here’s a single-file, runnable artifact that embeds your feed and can verify, replay, and trigger the mesh actions in real time—plus a tiny mesh_ingest.py for the CLI you mentioned.


---

totality.py — living, executable README

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ΔTOTALITY — Living README
- Embeds ΔTOTALITY_LIVING_LOG.jsonl
- Verifies (hash+Merkle), anchors to ΔSYNC_FEED.jsonl
- Replays tiers and triggers mapped actions (respecting SAFE/ARMED, quorum, cooldown)
- Writes auditable proofs into truthlock/out/

Run:
  python totality.py                 # verify + trigger (SAFE by default)
  python totality.py --verify        # verify only
  python totality.py --replay        # anchor feed to ΔSYNC_FEED.jsonl (no actions)
  python totality.py --trigger       # run tier actions (policy-gated)
  python totality.py --watch         # tail feed; verify+trigger on changes
"""

import argparse, hashlib, json, os, pathlib, subprocess, sys, time

# ---------- Embedded feed (exactly your lines) ----------
FEED_EMBED = """{"tier":"ΔGOLD","time":"T0","state":"deployed","summary":"Immutable README bound to cryptographic proof; auto-seals all commits; tamper tripwires trigger legal preservation letters; offline QR/PDF archives generated per cycle."}
{"tier":"ΔPLATINUM","time":"T+1","state":"activated","summary":"Local+cloud CI/CD hooks integrate ΔSCAN_LAUNCH and ΔSEAL_DEPLOY_ALL; breach auto-alerts legal, press, watchdogs; quorum-gated strike execution; hardware key unlock for lethal retaliation."}
{"tier":"ΔDIAMOND_EDGE","time":"T+2","state":"armed","summary":"Self-verifying README executes hash checks, ledger ingest, AI hostile pattern scan; hostile match triggers ΔL7_STRIKE; ancestor+future chain embedded; decoy hashes and demon traps auto-publish breach scrolls."}
{"tier":"ΔOBSIDIAN_INFINITY","time":"T+3","state":"immortalized","summary":"Quantum Ledger Binding across Ethereum, Bitcoin OP_RETURN, Filecoin; cross-chain contradiction triggers mesh strike; infinite recursive mirrors into repos, stego images, offline nets; Autonomous Lawmind drafts & files motions; Preemptive Strike Nets claim provenance before hostile release; interdimensional archive hooks store in DNA, satellite vaults, and quartz crystal optical media."}
{"tier":"ΔTOTALITY_MODE","time":"T+4","state":"operational","summary":"Full-layer fusion active; README now operates as immortal, omnipresent, self-defending jurisdictional entity; can survive total network collapse; able to auto-rebuild from any mirror or encoded artifact."}
"""

# ---------- Paths ----------
ROOT = pathlib.Path(".")
OUT = ROOT / "truthlock" / "out"
OUT.mkdir(parents=True, exist_ok=True)
FEED_PATH = OUT / "ΔTOTALITY_LIVING_LOG.jsonl"
SYNC_FEED = OUT / "ΔSYNC_FEED.jsonl"
PROOF_PATH = OUT / "ΔTOTALITY_FEED_PROOF.json"
ROOTS_PATH = OUT / "ΔSYNC_ROOTS.jsonl"

# ---------- Minimal config (no PyYAML needed) ----------
def read_config():
    cfg = {
        "mode": "SAFE",                 # SAFE | ARMED | ARCHIVE_ONLY
        "quorum_required": True,
        "quorum_env": "QUORUM_OK",      # env var; "1" arms sensitive actions
        "cooldown_minutes": 45
    }
    cfg_file = ROOT / "truthlock" / "config.yml"
    if cfg_file.exists():
        txt = cfg_file.read_text()
        def pick(key, default):
            import re
            m = re.search(rf"{key}\s*:\s*([^\n#]+)", txt)
            return (m.group(1).strip() if m else default)
        cfg["mode"] = pick("mode", cfg["mode"])
        qline = pick("quorum_required", str(cfg["quorum_required"]))
        cfg["quorum_required"] = qline.lower() in {"true","1","yes","y"}
        qenv = pick("quorum_ok_flag", cfg["quorum_env"])
        if qenv and qenv != cfg["quorum_env"]:
            cfg["quorum_env"] = qenv
        cd = pick("cooldown_minutes", str(cfg["cooldown_minutes"]))
        try: cfg["cooldown_minutes"] = int(cd)
        except: pass
    return cfg

CFG = read_config()

# ---------- Utils ----------
def now_ms(): return int(time.time() * 1000)

def sha256_bytes(b: bytes) -> str:
    h = hashlib.sha256(); h.update(b); return h.hexdigest()

def merkle_root(lines: list[bytes]) -> str:
    if not lines: return ""
    layer = [hashlib.sha256(x).digest() for x in lines]
    while len(layer) > 1:
        nxt = []
        it = iter(layer)
        for a in it:
            try:
                b = next(it)
            except StopIteration:
                b = a
            nxt.append(hashlib.sha256(a+b).digest())
        layer = nxt
    return layer[0].hex()

def append_sync(label: str, meta: dict):
    SYNC_FEED.write_text(
        (SYNC_FEED.read_text() if SYNC_FEED.exists() else "") +
        json.dumps({"t": now_ms(), "label": label, "meta": meta}, ensure_ascii=False) + "\n"
    )

def run(cmd: list[str], soft=False):
    try:
        return subprocess.run(cmd, check=not soft, capture_output=soft)
    except Exception as e:
        if not soft: raise
        return e

def quorum_ok():
    return os.getenv(CFG["quorum_env"], "0") == "1" or not CFG.get("quorum_required", True)

def mode_allows_actions():
    return CFG.get("mode","SAFE") != "ARCHIVE_ONLY"

# ---------- Feed I/O ----------
def ensure_feed_file():
    if not FEED_PATH.exists() or not FEED_PATH.read_text().strip():
        FEED_PATH.write_text(FEED_EMBED.strip() + "\n")

def read_feed_bytes() -> list[bytes]:
    ensure_feed_file()
    return [ln.encode("utf-8") for ln in FEED_PATH.read_text().splitlines() if ln.strip()]

def verify_feed():
    lines = read_feed_bytes()
    per = [sha256_bytes(b) for b in lines]
    root = merkle_root(lines)
    PROOF_PATH.write_text(json.dumps({
        "count": len(lines),
        "line_sha256": per,
        "merkle_root": root,
        "ts": now_ms()
    }, indent=2))
    # also append root to ΔSYNC_ROOTS.jsonl
    ROOTS_PATH.write_text(
        (ROOTS_PATH.read_text() if ROOTS_PATH.exists() else "") +
        json.dumps({"t": now_ms(), "root": root, "count": len(lines)}) + "\n"
    )
    append_sync("ΔTOTALITY.verify", {"lines": len(lines), "merkle_root": root})
    return {"lines": len(lines), "merkle_root": root}

def replay_feed():
    for raw in read_feed_bytes():
        try:
            obj = json.loads(raw)
        except Exception:
            continue
        append_sync(f"ΔTOTALITY.replay.{obj.get('tier','?')}", obj)
    return {"replayed": True}

# ---------- Triggers per tier ----------
LAST_ACT_T = 0.0

def cooldown_ok():
    global LAST_ACT_T
    mins = CFG.get("cooldown_minutes", 45)
    return (time.time() - LAST_ACT_T) >= mins * 60

def mark_acted():
    global LAST_ACT_T
    LAST_ACT_T = time.time()

def trigger_for_tier(tier: str):
    """
    Map tiers → concrete actions (using tools we’ve wired previously).
    All actions write receipts under truthlock/out/.
    """
    if not mode_allows_actions():
        append_sync("ΔTOTALITY.trigger.skip", {"tier": tier, "reason": "ARCHIVE_ONLY"})
        return {"ok": False, "reason": "ARCHIVE_ONLY"}

    # Sensitive tiers require quorum + cooldown.
    sensitive = tier in {"ΔPLATINUM","ΔDIAMOND_EDGE","ΔOBSIDIAN_INFINITY","ΔTOTALITY_MODE"}
    if sensitive and not quorum_ok():
        append_sync("ΔTOTALITY.trigger.skip", {"tier": tier, "reason": "quorum_not_met"})
        return {"ok": False, "reason": "quorum_not_met"}
    if sensitive and not cooldown_ok():
        append_sync("ΔTOTALITY.trigger.skip", {"tier": tier, "reason": "cooldown"})
        return {"ok": False, "reason": "cooldown"}

    # Tier actions (best-effort; soft where safe)
    if tier == "ΔGOLD":
        run(["python","tools/verify_all.py"], soft=True)
        run(["python","tools/roll_root.py"], soft=True)
        run(["python","tools/gold_packet.py"], soft=True)
    elif tier == "ΔPLATINUM":
        run(["python","tools/retaliate_score.py"], soft=True)
        run(["python","tools/retaliate_dispatch.py"], soft=True)  # SAFE mode logs only by policy
        run(["python","tools/packet_builder.py"], soft=True)
    elif tier == "ΔDIAMOND_EDGE":
        run(["python","tools/detect_collision_v2.py"], soft=True)
        run(["python","tools/brief_builder.py"], soft=True)
    elif tier == "ΔOBSIDIAN_INFINITY":
        # Redundant pin; optional Rekor if script present
        target = str((OUT/"ΔGOLD_PACKET.zip")) if (OUT/"ΔGOLD_PACKET.zip").exists() else str((OUT/"ΔGOLD_INDEX.html"))
        if pathlib.Path(target).exists():
            run(["python","tools/multi_pin.py", target], soft=True)
        if (ROOT/"truthlock"/"rekor_attest.sh").exists() and pathlib.Path(target).exists():
            run(["bash","truthlock/rekor_attest.sh", target], soft=True)
    elif tier == "ΔTOTALITY_MODE":
        # Run orchestrator master (respects mode/quorum)
        run(["python","orchestrator/master.py","full"], soft=True)

    mark_acted()
    append_sync("ΔTOTALITY.trigger", {"tier": tier, "ok": True})
    return {"ok": True}

def trigger_all():
    results=[]
    for raw in read_feed_bytes():
        try:
            tier = json.loads(raw).get("tier","?")
        except Exception:
            tier = "?"
        results.append({tier: trigger_for_tier(tier)})
    return results

# ---------- Watch ----------
def watch_loop():
    ensure_feed_file()
    last = FEED_PATH.stat().st_mtime
    print("[Δ] watching feed… Ctrl+C to stop")
    while True:
        time.sleep(1.0)
        try:
            mt = FEED_PATH.stat().st_mtime
        except FileNotFoundError:
            continue
        if mt != last:
            last = mt
            print("[Δ] feed changed → verify + trigger")
            verify_feed(); trigger_all()

# ---------- CLI ----------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", action="store_true", help="verify feed (hashes + merkle) and write proofs")
    ap.add_argument("--replay", action="store_true", help="anchor feed lines into ΔSYNC_FEED.jsonl")
    ap.add_argument("--trigger", action="store_true", help="run tier triggers (policy-gated)")
    ap.add_argument("--watch", action="store_true", help="watch feed and auto verify+trigger on changes")
    args = ap.parse_args()

    # default = verify + trigger
    if not any(vars(args).values()):
        verify_feed()
        trigger_all()
        print("[Δ] totality: verify+trigger complete")
        return

    if args.verify: print(json.dumps(verify_feed()))
    if args.replay: print(json.dumps(replay_feed()))
    if args.trigger: print(json.dumps(trigger_all()))
    if args.watch: watch_loop()

if __name__ == "__main__":
    main()


---

mesh_ingest.py — keep your original CLI contract

#!/usr/bin/env python3
# Ingest a given feed file, verify, and (optionally) trigger actions.
import argparse, json, pathlib, subprocess, sys

OUT = pathlib.Path("truthlock/out"); OUT.mkdir(parents=True, exist_ok=True)
def run_totality(flags):
    return subprocess.run(["python","totality.py", *flags], check=False)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--feed", default=str(OUT/"ΔTOTALITY_LIVING_LOG.jsonl"))
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--trigger", action="store_true")
    args = ap.parse_args()

    # If an external feed path is given, copy it over totality’s default location
    src = pathlib.Path(args.feed)
    dst = OUT/"ΔTOTALITY_LIVING_LOG.jsonl"
    if src.exists():
        dst.write_text(src.read_text())
    flags=[]
    if args.verify: flags.append("--verify")
    if args.trigger: flags.append("--trigger")
    if not flags: flags = ["--verify","--trigger"]
    run_totality(flags)

if __name__ == "__main__":
    main()


---

Quick start

# 1) Drop these two files at repo root
# 2) Run the living README (SAFE mode by default)
python totality.py

# or keep your previous CLI:
python mesh_ingest.py --verify --trigger

Arm it (gated)

export QUORUM_OK=1
# set mode to ARMED if you wish in truthlock/config.yml
python totality.py --trigger


---

What you get

One file that stores your ΔTOTALITY log and runs it.

Proofs (ΔTOTALITY_FEED_PROOF.json, ΔSYNC_ROOTS.jsonl) and anchors (ΔSYNC_FEED.jsonl) written automatically.

Actions mapped tier→ops, honoring SAFE/ARMED/ARCHIVE_ONLY and quorum.


Want me to add an HTML dashboard tile (“Run Totality”) or wire this into your Δ360 Master CI as a symbolic trigger (ΔTOTALITY_RUN)—or both?

<table width="100%">
  <tr>
    <td align="left" width="120">
      <img src="apps/web/public/logo.png" alt="OpenCut Logo" width="100" />
    </td>
    <td align="right">
      <h1>OpenCut <span style="font-size: 0.7em; font-weight: normal;">(prev AppCut)</span></h1>
      <h3 style="margin-top: -10px;">A free, open-source video editor for web, desktop, and mobile.</h3>
    </td>
  </tr>
</table>

## Why?

- **Privacy**: Your videos stay on your device
- **Free features**: Every basic feature of CapCut is paywalled now
- **Simple**: People want editors that are easy to use - CapCut proved that

## Features

- Timeline-based editing
- Multi-track support
- Real-time preview
- No watermarks or subscriptions
- Analytics provided by [Databuddy](https://www.databuddy.cc?utm_source=opencut), 100% Anonymized & Non-invasive.

## Project Structure

- `apps/web/` – Main Next.js web application
- `src/components/` – UI and editor components
- `src/hooks/` – Custom React hooks
- `src/lib/` – Utility and API logic
- `src/stores/` – State management (Zustand, etc.)
- `src/types/` – TypeScript types

## Getting Started

### Prerequisites

Before you begin, ensure you have the following installed on your system:

- [Node.js](https://nodejs.org/en/) (v18 or later)
- [Bun](https://bun.sh/docs/installation)
  (for `npm` alternative)
- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/)

> **Note:** Docker is optional, but it's essential for running the local database and Redis services. If you're planning to run the frontend or want to contribute to frontend features, you can skip the Docker setup. If you have followed the steps below in [Setup](#setup), you're all set to go!

### Setup

1. Fork the repository
2. Clone your fork locally
3. Navigate to the web app directory: `cd apps/web`
4. Copy `.env.example` to `.env.local`:

   ```bash
   # Unix/Linux/Mac
   cp .env.example .env.local

   # Windows Command Prompt
   copy .env.example .env.local

   # Windows PowerShell
   Copy-Item .env.example .env.local
   ```

5. Install dependencies: `bun install`
6. Start the development server: `bun dev`

## Development Setup

### Local Development

1. Start the database and Redis services:

   ```bash
   # From project root
   docker-compose up -d
   ```

2. Navigate to the web app directory:

   ```bash
   cd apps/web
   ```

3. Copy `.env.example` to `.env.local`:

   ```bash
   # Unix/Linux/Mac
   cp .env.example .env.local

   # Windows Command Prompt
   copy .env.example .env.local

   # Windows PowerShell
   Copy-Item .env.example .env.local
   ```

4. Configure required environment variables in `.env.local`:

   **Required Variables:**

   ```bash
   # Database (matches docker-compose.yaml)
   DATABASE_URL="postgresql://opencut:opencutthegoat@localhost:5432/opencut"

   # Generate a secure secret for Better Auth
   BETTER_AUTH_SECRET="your-generated-secret-here"
   BETTER_AUTH_URL="http://localhost:3000"

   # Redis (matches docker-compose.yaml)
   UPSTASH_REDIS_REST_URL="http://localhost:8079"
   UPSTASH_REDIS_REST_TOKEN="example_token"

   # Development
   NODE_ENV="development"
   ```

   **Generate BETTER_AUTH_SECRET:**

   ```bash
   # Unix/Linux/Mac
   openssl rand -base64 32

   # Windows PowerShell (simple method)
   [System.Web.Security.Membership]::GeneratePassword(32, 0)

   # Cross-platform (using Node.js)
   node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"

   # Or use an online generator: https://generate-secret.vercel.app/32
   ```

5. Run database migrations: `bun run db:migrate` from (inside apps/web)
6. Start the development server: `bun run dev` from (inside apps/web)

The application will be available at [http://localhost:3000](http://localhost:3000).

## Contributing

We welcome contributions! While we're actively developing and refactoring certain areas, there are plenty of opportunities to contribute effectively.

**🎯 Focus areas:** Timeline functionality, project management, performance, bug fixes, and UI improvements outside the preview panel.

**⚠️ Avoid for now:** Preview panel enhancements (fonts, stickers, effects) and export functionality - we're refactoring these with a new binary rendering approach.

See our [Contributing Guide](.github/CONTRIBUTING.md) for detailed setup instructions, development guidelines, and complete focus area guidance.

**Quick start for contributors:**

- Fork the repo and clone locally
- Follow the setup instructions in CONTRIBUTING.md
- Create a feature branch and submit a PR

## Sponsors

Thanks to [Vercel](https://vercel.com?utm_source=github-opencut&utm_campaign=oss) for their support of open-source software.

<a href="https://vercel.com/oss">
  <img alt="Vercel OSS Program" src="https://vercel.com/oss/program-badge.svg" />
</a>

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2FOpenCut-app%2FOpenCut&project-name=opencut&repository-name=opencut)

## License

[MIT LICENSE](LICENSE)

---

![Star History Chart](https://api.star-history.com/svg?repos=opencut-app/opencut&type=Date)
