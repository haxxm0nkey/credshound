# BloodHound Integration

CredsHound can export findings as BloodHound OpenGraph JSON. This lets you map local credential exposure to the host, user profile, filesystem location, credential finding, and related product or service.

The BloodHound export is intended for defensive analysis of hosts you own or are authorized to assess. Treat exported files as sensitive because they contain redacted credential evidence, paths, usernames, hostnames, and product context.

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

Import `credshound-bloodhound.json` as an OpenGraph file through BloodHound's OpenGraph import flow.

The exact UI can vary by BloodHound version, but the general workflow is:

1. Generate the JSON file with `-bh` or `-bloodhound`.
2. Open BloodHound.
3. Import the JSON as OpenGraph data.
4. Use Cypher to query `CH*` node kinds and edges.

CredsHound does not replace Active Directory, Azure, or other BloodHound collectors. It adds local credential-surface context that can enrich graph analysis.

## Graph Model

CredsHound emits custom OpenGraph node kinds:

```text
CHHost
CHLocalUser
CHUserProfile
CHLocation
CHCreds
CHObservation
CHProduct
```

Main relationship flow:

```text
CHHost -> CHLocalUser -> CHUserProfile -> CHLocation -> CHCreds -> CHProduct
```

For locations that cannot be mapped to a user profile, CredsHound links the host directly to the location:

```text
CHHost -> CHLocation -> CHCreds -> CHProduct
```

Informational findings use `CHObservation` instead of `CHCreds`. Examples include interesting credential-bearing paths or references to known environment variable names.

## Edge Kinds

CredsHound emits these edge kinds:

```text
CHHasLocalUser
CHHasUserProfile
CHContainsLocation
CHContainsCreds
CHMayAuthenticateTo
```

`CHMayAuthenticateTo` is emitted for credential findings that point to a product or service. Informational observations do not create product edges.

## Useful Queries

Show credential paths from host to product:

```cypher
MATCH p=(:CHHost)-[*1..5]->(:CHCreds)-[:CHMayAuthenticateTo]->(:CHProduct)
RETURN p
LIMIT 50
```

Show findings as a table:

```cypher
MATCH (h:CHHost)-[*1..5]->(c:CHCreds)-[:CHMayAuthenticateTo]->(p:CHProduct)
RETURN h.displayname AS host,
       c.displayname AS creds,
       p.name AS product,
       c.origin AS origin,
       c.confidence AS confidence
ORDER BY host, product
```

Show locations with credential findings:

```cypher
MATCH p=(:CHLocation)-[:CHContainsCreds]->(:CHCreds)
RETURN p
LIMIT 50
```

Show observations only:

```cypher
MATCH p=(:CHLocation)-[:CHContainsCreds]->(:CHObservation)
RETURN p
LIMIT 50
```

Count CredsHound node kinds:

```cypher
MATCH (n)
WHERE "CHHost" IN labels(n)
   OR "CHLocalUser" IN labels(n)
   OR "CHUserProfile" IN labels(n)
   OR "CHLocation" IN labels(n)
   OR "CHCreds" IN labels(n)
   OR "CHObservation" IN labels(n)
   OR "CHProduct" IN labels(n)
RETURN labels(n) AS labels, count(n) AS count
ORDER BY count DESC
```

Find high-confidence credential findings:

```cypher
MATCH (c:CHCreds)
WHERE c.confidence = "high"
RETURN c.displayname AS finding,
       c.credential_type AS type,
       c.location AS location,
       c.product AS product,
       c.url AS reference
ORDER BY product, type
```

Find products reachable from a specific host:

```cypher
MATCH (h:CHHost)-[*1..5]->(c:CHCreds)-[:CHMayAuthenticateTo]->(p:CHProduct)
WHERE h.displayname CONTAINS "HOSTNAME"
RETURN h.displayname AS host,
       c.displayname AS creds,
       p.name AS product,
       p.category AS category
ORDER BY product
```

## Node Properties

Credential and observation nodes include useful properties such as:

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
location
credential_type
evidence
url
references
reference_count
```

`origin` identifies where the finding came from:

```text
template
builtin
observation
```

Product nodes are generated from LOLCreds template metadata when available. Built-in generic detections use their built-in product/category metadata.

## Optional Custom Icons

BloodHound can import CredsHound data without custom icons. If custom node kinds are not configured, BloodHound may display `CH*` nodes with default or question-mark icons.

Suggested icon mapping:

```text
CHHost          desktop or server
CHLocalUser     user
CHUserProfile   folder
CHLocation      file or document
CHCreds         key
CHObservation   info or warning
CHProduct       package, cube, or service
```

Custom icons are configured in BloodHound as custom node-kind metadata. The exact API and UI can vary between BloodHound versions, so CredsHound does not currently ship public icon setup scripts.

For early testing, it is enough to import the OpenGraph JSON and query by `CH*` labels.

## Notes and Limitations

- The BloodHound exporter is focused on local credential exposure and credential surface mapping.
- CredsHound does not validate whether a discovered credential is still active.
- Redacted evidence is included by default; plaintext evidence is included only with `-show-secrets`.
- Host, local user, and user profile nodes are inferred from the scanning host and finding paths.
- `CHProduct` represents the product or service associated with the credential, not a guaranteed reachable network target.
- The model is expected to evolve as CredsHound adds more graph enrichment.
