# BloodHound Integration

CredsHound can export findings as BloodHound OpenGraph JSON. The export maps local credential exposure to the host, attributable local user when one can be inferred, the exposed location, deduplicated credential identity, and the related service.

The BloodHound export is intended for defensive analysis of hosts you own or are authorized to assess. Treat exported files as sensitive because they contain redacted credential evidence, paths, usernames, hostnames, service context, and keyed credential fingerprints.

## Generate OpenGraph JSON

Run a scan with BloodHound output enabled:

```bash
credshound -bloodhound -o credshound-bloodhound.json .
```

Short flag form:

```bash
credshound -bh -o credshound-bloodhound.json .
```

With a local or offline LOLCreds template source:

```bash
credshound -t ~/lolcreds-templates -bh -o credshound-bloodhound.json .
```

```bash
credshound -t ~/Downloads/lolcreds-data-main.zip -bh -o credshound-bloodhound.json .
```

Do not use `-show-secrets` unless you explicitly want plaintext secrets in the exported graph data and can protect the output file.

## Import Into BloodHound

Before importing scan data, run the setup command once per BloodHound instance to register CredsHound node icons and saved Cypher queries:

```bash
credshound -bh-setup -server http://localhost:8080
```

CredsHound reads these environment variables when the matching flag is not provided:

```bash
BLOODHOUND_URL=http://localhost:8080
BLOODHOUND_TOKEN=...
BLOODHOUND_USERNAME=admin
BLOODHOUND_PASSWORD=...
```

For normal use, prefer `BLOODHOUND_TOKEN` or `BLOODHOUND_PASSWORD` over command-line secrets because command-line arguments may be visible in shell history or process listings:

```bash
BLOODHOUND_URL=http://localhost:8080 BLOODHOUND_TOKEN=... credshound -bh-setup
```

Running setup again refreshes bundled CredsHound saved queries by name and removes known obsolete CredsHound UI queries. If you want to remove every older CredsHound saved query before importing the current set:

```bash
credshound -bh-setup -reset-queries
```

Import `credshound-bloodhound.json` as an OpenGraph file through BloodHound's OpenGraph import flow.

The exact UI can vary by BloodHound version, but the general workflow is:

1. Run `credshound -bh-setup` to register icons and saved queries.
2. Generate the JSON file with `-bh` or `-bloodhound`.
3. Open BloodHound.
4. Import the JSON as OpenGraph data.
5. Open the CredsHound saved queries or use Cypher to query `CH*` node kinds and edges.

CredsHound does not replace Active Directory, Azure, or other BloodHound collectors. It adds local credential-surface context that can enrich graph analysis.

## BloodHound Setup Integration

```text
credshound -bh-setup [flags]
```

Useful flags:

```text
-server URL        BloodHound server URL, default BLOODHOUND_URL or http://localhost:8080
-token TOKEN       BloodHound JWT bearer token, default BLOODHOUND_TOKEN
-username USER     BloodHound username, default BLOODHOUND_USERNAME
-password PASSWORD BloodHound password, default BLOODHOUND_PASSWORD
-reset-queries     delete existing CredsHound saved queries before import
-no-icons          skip custom node icon setup
-no-queries        skip saved query import
-no-verify-ssl     skip TLS certificate verification
```

The setup command uses BloodHound's documented custom node and saved query APIs. It creates or updates icons for `CHHost`, `CHLocalUser`, `CHExposure`, `CHCredential`, and `CHService`, then imports graph-oriented CredsHound queries that return paths for the BloodHound UI.

## Graph Model

CredsHound emits custom OpenGraph node kinds:

```text
CHHost
CHLocalUser
CHExposure
CHCredential
CHService
```

Main credential relationship flow:

```text
CHHost -> CHLocalUser -> CHExposure -> CHCredential -> CHService
```

When an exposure cannot be honestly attributed to a local user, CredsHound links it directly to the host:

```text
CHHost -> CHExposure -> CHCredential -> CHService
```

`CHExposure` is the exposed location container. For file findings, this is the file path without the line number. For environment and process findings, it is the environment variable or process-environment location.

Detection-specific evidence lives on the `CHRevealsCredential` edge: detector, confidence, raw location, line number, redacted evidence, origin, and LOLCreds references.

`CHCredential` is the credential identity node. When a pre-redaction fingerprint is available, repeated discoveries of the same credential converge on one `CHCredential` node. This keeps reuse analysis possible without storing plaintext secrets.

Informational-only findings also use `CHExposure`, but they do not create a `CHRevealsCredential` edge. Examples include interesting credential-bearing paths or references to known environment variable names. The rule is simple:

```text
CHExposure without CHRevealsCredential = observation, not credential
```

## Edge Kinds

CredsHound emits these edge kinds:

```text
CHHasLocalUser
CHHasExposure
CHRevealsCredential
CHAuthenticatesTo
```

`CHHasExposure` attaches evidence to either a `CHLocalUser` or directly to `CHHost`.

`CHRevealsCredential` is emitted only for non-info findings and carries finding-specific evidence properties.

`CHAuthenticatesTo` is emitted when a credential finding has product or service context from LOLCreds or a built-in detector.

## Credential Fingerprints

CredsHound computes credential fingerprints before redaction and exports only a keyed HMAC fingerprint:

```text
hmac-sha256:<truncated-digest>
```

By default, CredsHound uses a built-in stable fingerprint key. This makes credential reuse analysis work immediately across multiple host exports and BloodHound imports.

For real environments, prefer a private org-local key so your exported fingerprints are not comparable with anyone else's CredsHound exports:

```bash
export CREDSHOUND_FINGERPRINT_KEY='replace-with-a-long-random-org-local-secret'
credshound -bh -o credshound-bloodhound.json .
```

For lab or demo workflows, you can also pass the key explicitly:

```bash
credshound -fingerprint-key 'shared-lab-key' -bh -o credshound-bloodhound.json .
```

Use the same key on every host/export you want to correlate. Do not put this key in the BloodHound export or commit it to a repository. The environment variable is usually preferable on real systems because command-line arguments may be visible in process listings.

For sensitive one-off exports where cross-scan reuse is not needed, use an ephemeral per-scan key:

```bash
credshound -ephemeral-fingerprint -bh -o credshound-bloodhound.json .
```

## Useful Queries

Show credential paths from host to service:

```cypher
MATCH p=(:CHHost)-[*1..4]->(:CHExposure)-[:CHRevealsCredential]->(:CHCredential)-[:CHAuthenticatesTo]->(:CHService)
RETURN p
LIMIT 50
```

Show credential findings as a table:

```cypher
MATCH (h:CHHost)-[*1..3]->(e:CHExposure)-[:CHRevealsCredential]->(c:CHCredential)
OPTIONAL MATCH (c)-[:CHAuthenticatesTo]->(s:CHService)
RETURN h.displayname AS host,
       e.username AS user,
       e.location AS location,
       c.credential_type AS type,
       s.name AS service
ORDER BY host, service, location
```

Show credential findings with line and detector details:

```cypher
MATCH (h:CHHost)-[*1..3]->(e:CHExposure)-[r:CHRevealsCredential]->(c:CHCredential)
OPTIONAL MATCH (c)-[:CHAuthenticatesTo]->(s:CHService)
RETURN h.displayname AS host,
       e.username AS user,
       e.location AS exposure,
       r.raw_location AS raw_location,
       r.line AS line,
       r.detector_id AS detector,
       c.credential_type AS type,
       s.name AS service,
       r.confidence AS confidence
ORDER BY host, service, raw_location
```

Find credential reuse across multiple exposure sites:

```cypher
MATCH (e:CHExposure)-[:CHRevealsCredential]->(c:CHCredential)
WITH c, collect(e) AS exposures
WHERE size(exposures) > 1
RETURN c.displayname AS credential,
       c.credential_type AS type,
       size(exposures) AS exposure_count,
       [e IN exposures | e.location] AS exposures
ORDER BY exposure_count DESC
```

Show observations only:

```cypher
MATCH (e:CHExposure)
WHERE NOT (e)-[:CHRevealsCredential]->(:CHCredential)
RETURN e.location AS location,
       e.source AS source
ORDER BY location
LIMIT 100
```

Count CredsHound node kinds:

```cypher
MATCH (n)
WHERE "CHHost" IN labels(n)
   OR "CHLocalUser" IN labels(n)
   OR "CHExposure" IN labels(n)
   OR "CHCredential" IN labels(n)
   OR "CHService" IN labels(n)
RETURN labels(n) AS labels, count(n) AS count
ORDER BY count DESC
```

Find high-confidence credential findings:

```cypher
MATCH (e)-[r:CHRevealsCredential]->(c)
WHERE r.confidence = "high"
OPTIONAL MATCH (c)-[:CHAuthenticatesTo]->(s:CHService)
RETURN e.location AS exposure,
       c.credential_type AS type,
       r.raw_location AS location,
       s.name AS service,
       r.url AS reference
ORDER BY service, type
```

Find services reachable from a specific host:

```cypher
MATCH (h:CHHost)-[*1..3]->(:CHExposure)-[:CHRevealsCredential]->(:CHCredential)-[:CHAuthenticatesTo]->(s:CHService)
WHERE h.displayname CONTAINS "HOSTNAME"
RETURN h.displayname AS host,
       s.name AS service,
       s.category AS category,
       count(*) AS credential_count
ORDER BY credential_count DESC, service
```

## Node Properties

Exposure nodes include location-container properties such as:

```text
source
location
username
profile_path
```

`CHRevealsCredential` edges include finding-specific evidence properties such as:

```text
template_id
credential_id
detector_id
detector_name
origin
product
vendor
category
credential
source
confidence
raw_location
line
credential_type
evidence
url
references
reference_count
```

Credential nodes include:

```text
credential_type
confidence
secret_fingerprint
```

Service nodes are generated from LOLCreds template metadata or built-in detector metadata when available:

```text
service_id
vendor
category
url
```

`origin` identifies where the exposure came from:

```text
template
builtin
observation
```

## Optional Custom Icons

BloodHound can import CredsHound data without custom icons. If custom node kinds are not configured, BloodHound may display `CH*` nodes with default or question-mark icons.

Suggested icon mapping:

```text
CHHost         desktop or server
CHLocalUser    user
CHExposure     file, document, or alert
CHCredential   key
CHService      cube, package, or cloud service
```

Custom icons are configured in BloodHound as custom node-kind metadata. Run `credshound -bh-setup` to register the suggested icons automatically.

For early testing, it is enough to import the OpenGraph JSON and query by `CH*` labels.

## Notes and Limitations

- The BloodHound exporter is focused on local credential exposure and credential surface mapping.
- CredsHound does not validate whether a discovered credential is still active.
- Redacted evidence is included by default; plaintext evidence is included only with `-show-secrets`.
- Host and local user nodes are inferred from the scanning host and finding paths.
- User attribution is optional. System-level findings attach directly to `CHHost`.
- `CHService` represents the product or service associated with the credential, not a guaranteed reachable network target.
- The model is expected to evolve as CredsHound adds more graph enrichment.
