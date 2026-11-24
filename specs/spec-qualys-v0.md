# Qualys Plugin Specification

**A read-only collector for Qualys VMDR. On a schedule it reads the host detections Qualys holds, from Cloud Agents and from scanner-appliance scans, and the knowledge-base record behind each QID. It writes them to the grid as Qualys-owned nodes holding Qualys's data as Qualys returns it, with packages extracted from each detection's result text. Each node is linked to the AWS EC2 instance it concerns, the `computing_core` packages a parser vouches for, and the shared `compliance_core` vulnerability records, so a vulnerability detection and response (VDR) implementation can read what Qualys knows without going to Qualys. When nobody on the team has API access, the same data arrives as an export archive that someone with access produces, and the collector loads it the same way.**

## Plugin Identity

| Field | Value |
| --- | --- |
| Slug | `qualys` |
| Display name | Qualys TAP |
| Description | A read-only collector for Qualys VMDR that lands host detections, the QID knowledge base and the packages named in detection results on the grid, linked to the AWS EC2 instances they concern. |
| Kind | Leaf plugin. It writes `compliance_core`'s neutral finding, one per Qualys host and CVE, and creates the shared vulnerability record a CVE names when the grid holds none (`req-qualys-neutral`). It writes or links `computing_core` packages (by edge, only when a parser is sure, creating the package with its key fields when the grid holds none, `req-qualys-package-link`). It links to `aws_core`'s EC2 instance by exact instance id and never writes it, with `aws_core` an optional dependency (`req-qualys-ec2-link`). VDR plugins read it through the grid, with no import. |

**Default dimensions.**

| Key | Value | Why |
| --- | --- | --- |
| `qualys.area` | `run` on subscription and scan-run nodes; `observation` on host nodes; `finding` on detection nodes; `knowledge` on QID nodes | Lets a page or Search group the Qualys-owned nodes without listing types. The key is namespaced by this vocabulary, which only this plugin gives meaning. It is declared in the plugin's GRIFT dimension bundle with its four values. The `compliance_core`, `computing_core` and `aws_core` nodes this plugin writes or links keep their owners' dimensions and receive none from here. |

## Philosophy

Qualys already does the hard part. Its agents and scanners find vulnerabilities, its knowledge base says what each QID means, and it tracks when a detection was first found, last found and fixed. A VDR implementation needs those answers on the grid, next to the EC2 instances they concern, with their provenance. This plugin carries them across. It does not scan, does not decide what a detection means for any compliance factor, and never changes Qualys. It carries Qualys's data as Qualys returns it and does not interpret, consolidate or judge it: no severity scale, risk model or mapping is applied. How an organisation reads Qualys beside its other scanners is a later layer.

Eight consequences shape v0:

1. **Read-only actions only.** Every request the plugin can send is on an enumerated list of read operations, and the transport refuses everything else. Every detection and knowledge-base read is a GET, because every read Qualys documents for them accepts one. A POST is admitted only for a read that has no GET form, named on the list by a spec change (ruled 2026-11-20, Q8a); the one such read is the tag search, whose body can carry paging and nothing else (ruled 2026-11-23, `req-qualys-tags`). The credential is a Reader user with API access only, scoped to the in-scope asset groups or tags, so a bug here cannot change Qualys.
2. **Qualys's data in Qualys's shape; link, never merge.** The subscription, scan run, host, detection and QID are Qualys-owned nodes. The EC2 instance, the package and the shared vulnerability belong to other plugins and are reached by edge. A ruled exception (2026-11-17, for every scanner): beside its own records the plugin writes `compliance_core`'s neutral finding, one per Qualys host and CVE. It also creates the shared vulnerability record a CVE names when the grid holds none, and gives a record with no CVSS score the one Qualys's knowledge base carries. Following the Tenable ruling of 2026-11-19 (Q62), adopted here on 2026-11-20 (Q8b), a package a parser is sure of is created with its key fields only when the grid holds none. Nothing else on a record another producer shares is changed. The EC2 instance is never written.
3. **Qualys says when a detection is fixed.** A detection resolves only when Qualys reports it `Fixed`. Qualys marks a detection fixed only after a scan or an agent check looked for it and did not find it, which is a better test than any absence the plugin could infer. So a detection that is merely absent from a read never resolves (ruled 2026-11-20, Q7c).
4. **Three states, never two.** Several situations are each recorded as what they are, never as clean or as "no package": a scope that could not be read, a page that failed validation, a QID with no knowledge-base record, a detection whose result text has no parser, and a parser that failed. A fact nothing observed is `null`.
5. **CVEs hang off the QID.** One QID can name many CVEs, and a host can carry hundreds of QIDs. So the CVE link is drawn once per QID, never once per detection, and the neutral finding is one per host and CVE however many QIDs name that CVE (Tenable's lesson, taken from Cartography).
6. **The API is a contract we can check.** Qualys publishes no OpenAPI file, but it publishes a document type definition (DTD) for each output. A generated extract of the elements the plugin reads is tested offline, compared on a schedule against what Qualys serves, and checked against every response before any node is written.
7. **The version is pinned and its end is visible.** Qualys retires API versions on a published timeline. Host detection versions 2.0 to 4.0 are past end of support. Knowledge base 2.0 reaches end of life in December 2026 and 3.0 in February 2027. v0 reads host detection 6.0 and knowledge base 4.0, each held in one constant, and any end-of-support warning Qualys puts in a response is recorded on the run.
8. **No access is not a blocker.** Someone with access runs a small read-only export script (`tools/qualys-export/`). The collector loads the archive it produces through the same parser, contract check and resolution rules as a live read, and records that the run came from a file (ruled 2026-11-20, Q9).

**Prior art, and what it changed.** Surveyed 2026-11-20 from Qualys's documentation and from each project's source, not by running against a subscription.

- Qualys's Host List Detection reference ([HLD](https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-assets/host_lists/host_detection.htm)) and versioning page ([VER](https://docs.qualys.com/en/vm/qweb-all-api/get_started/api_versioning_standards.htm)) moved v0 off the `/api/2.0/` paths most integrations still use, onto 6.0 and the knowledge base's 4.0 ([KB](https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-scan/kbase/knowledgebase.htm)).
- The same reference says one `UNIQUE_VULN_ID` can be shared by a vulnerability and an information-gathered finding, and to pair it with the QID. That is why the detection key carries both.
- It also says that without an explicit `status` list, Fixed detections never come back. That is why every read asks for all four statuses.
- The 10.12 release notes ([RN1012](https://cdn2.qualys.com/docs/release-notes/qualys-cloud-platform-10.12-api-release-notes.pdf)) moved the EC2 instance id to `CLOUD_RESOURCE_ID` and left `EC2_INSTANCE_ID` deprecated and also carrying Azure ids. That is why the join reads the former with the provider check.
- The limits document ([LIM](https://www.qualys.com/docs/qualys-api-limits.pdf)) gives 2 concurrent calls and 300 per hour per API, per subscription, and HTTP 409 with code 1960 or 1965 when throttled. That is why calls are serial and a 409 is classified by its code.
- Elastic's `qualys_vmdr` integration ([ELASTIC](https://github.com/elastic/integrations/tree/main/packages/qualys_vmdr)) supplied two things: the package-table parse (`Package / Installed Version / Required Version`) and the rule of asking the knowledge base only for QIDs seen, in batches of at most 500, after it hit HTTP 414. Its key of `UNIQUE_VULN_ID` alone is rejected.
- Microsoft Sentinel's Qualys connector supplied the incremental read: a `vm_processed_after` window with all four statuses. `detection_updated_since` is not used until it is observed, because Qualys's 10.37.2 release fixed inconsistent results from it.
- The `qualysapi` Python package is rejected as a dependency: it sends every call as a POST, hard-codes the 2.0 paths, and was last released in July 2023. The client is ours, over `requests`, as Anchore's is.
- QualysETL's release notes report knowledge-base XML that is sometimes not well-formed. That is why a malformed page is a recorded failure, not a crash.
- `anchore-tap` and `tenable-tap` (this organisation) supplied the structure this plugin inherits: three states, keys by assertion, operator settings never read from nodes, the observation command, the neutral finding and the parser registry.

**Provenance markers.** *Documented* (read from the Qualys pages and PDFs above and from each integration's source, 2026-11-20): every endpoint, parameter, field and limit named below. *Designed* (this document): every node, edge, key, rule and verdict. *Observed*: only the two output DTDs, which Qualys serves without a credential (fetched from `qualysapi.qualys.com` on 2026-11-21 and committed as the contract's sources). No Qualys subscription has been called and no export archive has been received. Every field mapping, parser and "Qualys returns X" claim is provisional until a recorded response or an export archive replaces it, and no requirement below reaches `Implemented` on a documented claim alone.

## Goals

| # | Name | Description |
| --- | --- | --- |
| 1 | What Qualys Knows About A Host | Every detection on every in-scope host, with Qualys's fields and result text as returned, and the knowledge-base record behind each QID. |
| 2 | Read-Only By Construction | Only an enumerated list of read operations can leave the client; a Reader credential with API access only is enough. |
| 3 | Reachable From The EC2 Instance | A Qualys host links to the EC2 instance `aws_core` holds, by exact instance id, so an instance's vulnerabilities are one traversal away. |
| 4 | Fixed Means Qualys Said So | A detection resolves only on Qualys's own Fixed status; absence and filters never resolve anything. |
| 5 | Never Clean By Omission | A scope not read, a QID with no record, a result with no parser and a parser that failed are each recorded as such; unobserved facts are `null`. |
| 6 | Seen By The Shared Pages | The neutral finding per host and CVE puts Qualys beside every other scanner on the shared vulnerability page. |
| 7 | Detect API Drift | A generated DTD extract, offline tests, a scheduled comparison and a per-response check catch a changed API before bad data lands. |
| 8 | Works Without Our Own Access | An export archive from someone with access loads through the same path as a live read. |
| 9 | Backend Only | No page or panel ships; the outputs are nodes and edges other surfaces read. |

## Requirements

| RID | Name | Status | Notes |
| --- | --- | --- | --- |
| req-qualys-connection | [Connection And Credential](#connection-and-credential) | In Development | One operator-owned envelope per subscription: API host, subscription label, Reader credential, optional CA bundle and scope; never fields on a node |
| req-qualys-transport | [The Read-Only Transport](#the-read-only-transport) | In Development | One `send` that admits only enumerated read operations, bound to the API host; serial calls; 409 classified by code; bounded input; `defusedxml` |
| req-qualys-probe | [Probe And Provenance](#probe-and-provenance) | In Development | A one-host first page confirms the credential and version; rate-limit headers and end-of-support text recorded on the run |
| req-qualys-contract-extract | [Contract Extract And Offline Tests](#contract-extract-and-offline-tests) | In Development | A generated extract of the DTD elements read, tests with no network, every response checked before any node is written |
| req-qualys-drift-ci | [Scheduled Drift Check](#scheduled-drift-check) | In Development | A scheduled read-only workflow compares the DTDs Qualys serves with the extract and fails on drift in what is read |
| req-qualys-observe | [The Observation Command](#the-observation-command) | In Development | A read-only command that records what a subscription returns, locally and privately, and settles the open-assumptions ledger |
| req-qualys-states | [Three States And Resolution](#three-states-and-resolution) | In Development | Not read is never clean; null is unobserved; only Qualys's Fixed resolves; re-opened reopens; an unreported host is withdrawn, its detections untouched |
| req-qualys-detection-read | [The Detection Read](#the-detection-read) | In Development | Complete first read, then a `vm_processed_after` window; all four statuses; ignored and disabled included; filter and watermark recorded |
| req-qualys-subscription-run | [Subscription And Scan Run](#subscription-and-scan-run) | In Development | The subscription node and one scan run per collection, with probe, filter, watermark, scopes not read, counters and warnings |
| req-qualys-host | [Hosts](#hosts) | In Development | A node per host as Qualys tracks it, with its cloud fields |
| req-qualys-detection | [Detections](#detections) | In Development | A node per detection keyed by subscription, host id, QID and unique vulnerability id, with Qualys's fields and result text as returned |
| req-qualys-qid | [Knowledge-Base Records](#knowledge-base-records) | In Development | A node per QID seen, from knowledge base 4.0, with CVSS and the CVE list; linked to each CVE's shared vulnerability record |
| req-qualys-ec2-link | [EC2 Instance Link](#ec2-instance-link) | In Development | A host links to `aws_core`'s EC2 instance by exact `CLOUD_RESOURCE_ID` with provider AWS, only when it exists; never written; optional dependency |
| req-qualys-neutral | [The Neutral Finding](#the-neutral-finding) | In Development | `compliance_core`'s finding per Qualys host and CVE, carried by the package or the host; vulnerability record created when absent and scored where unscored |
| req-qualys-parsers | [Result Parsers](#result-parsers) | In Development | A parser registry, four parse states, a fixture and a test each; the first parser reads Qualys's package table |
| req-qualys-package-link | [Package Link](#package-link) | In Development | A detection links to a `computing_core` package only when the parser is sure; an absent package is created with its key fields |
| req-qualys-file-import | [Export Archive Import](#export-archive-import) | In Development | The collector loads an archive from `tools/qualys-export/` through the same parser, contract check and resolution rules, recorded as file-sourced |
| req-qualys-fips | [FIPS Posture](#fips-posture) | In Development | `requests` over the system OpenSSL and pure-Python `defusedxml`, declared in `[fips]` |
| req-qualys-tags | [Asset Tags](#asset-tags) | In Development | Every tag the credential can see, from the tag search, as a node keyed by tag id, linked to its subscription and its children; a complete list withdraws a tag it lacks |
| req-qualys-sources | [Source Switches](#source-switches) | In Development | Detections, the knowledge base and tags each switched on or off per envelope, all on by default; a source switched off is recorded as not read, never as empty |
| req-qualys-chunked-write | [Chunked Write](#chunked-write) | In Development | A run is written as bounded batches, each its own transaction, opening first and a seal last, so a big run cannot exhaust Postgres's lock table and a failure never moves the watermark |
| req-qualys-event-time | [Event Time](#event-time) | In Development | Each model's event time declared for core's `req-grid-entity-event-time`: a detection's first found time, a QID's published time, none for the rest |
| req-qualys-policy-compliance | Policy Compliance | Backlog | Qualys Policy Compliance (PC) posture results as their own type, like Tenable's compliance results |
| req-qualys-scan-list | Scan List | Backlog | The scans Qualys ran, as nodes a detection's last scan can point at |
| req-qualys-ignored-disabled | Acting On Ignored And Disabled | Backlog | What a consumer should make of `IS_IGNORED` and `IS_DISABLED`; v0 stores both flags and acts on neither |
| req-qualys-json-api | JSON Detection API | Backlog | The `/vmrs/api/1.0` JSON host detection API, a limited release today, as a second read path behind the same vocabulary |
| req-qualys-software-inventory | Software Inventory | Backlog | Installed software from Qualys's asset inventory (CSAM / Global AssetView), a separate API and entitlement |
| req-qualys-shared-facts | Shared Facts | Backlog | Addresses, DNS names and interfaces written to or linked in `computing_core`, as Tenable does |
| req-qualys-other-clouds | Azure And GCP Links | Backlog | The same exact-id link for hosts Qualys reports on Azure or GCP, once a provider plugin holds those instances |
| req-qualys-aws | [AWS Integration](#aws-integration) | In Development | Opt-in (`integrations.aws`): mint the aws_core nodes and edges Qualys's metadata names, only where aws_core holds none; supersedes the Backlog row for creating absent EC2 instances (ruled 2026-11-23, Q38) |
| req-qualys-neutral-scanner | Scanner And Run In The Neutral Shape | Backlog | The subscription and runs also written as `compliance_core`'s scanner and scan-run types |
| req-qualys-reconciler | Cross-Source Reconciliation | Backlog | Linking Qualys's hosts and detections to other scanners' views by evidence-carrying edges, never merges |
| req-qualys-report-import | Host Based Findings Import | Backlog | A parser for the Host Based Findings XML report, for a person with console access but no API access (ruled 2026-11-20, Q9c) |
| req-qualys-nongoals | [v0 Non-Goals](#v0-non-goals) | Approved for Development | What this plugin deliberately does not do, and who owns it |

### Connection And Credential
----
RID: `req-qualys-connection`

Status: `In Development`

How the collector knows which Qualys subscription to read and how to authenticate. The settings and the credential live together in one operator-owned secret envelope per subscription, never in a field on a grid node. Whoever can edit a node must not be able to point a credential at another host or quietly narrow what a compliance view sees.

#### Implementation

The secret is a plugin secret: its consumer is the Qualys collector, so the envelope's scope is `qualys`. Its key is chosen by the operator to name the subscription, and the file is `<key>.secret.json` under the secrets root, never in a repository. Its kind is `qualys_api_credential`, a kind this plugin owns. The collector validates `data` against `tap_plugin/qualys/schemas/qualys_api_credential.schema.json` with `require_secret_kind` before any request. The schema is strict, with a `description` on the top level and every field. `data` holds:

- `api_host`: the platform's API root, such as `https://qualysapi.qg2.apps.qualys.com`, from Qualys's platform identification page. `https://` only. Required. Host and scheme are lower-cased. A URL with userinfo, a path, a query or a fragment is refused before any request.
- `subscription`: an operator-chosen label naming the subscription, such as `acme-prod`. Required. Qualys is a shared service, so many subscriptions answer on one API host, and the host alone cannot identify one. Whether Qualys reports a subscription identifier the plugin could read instead is open in the observation ledger (`subscription-identity`).
- `username`, `password`: a Qualys user with the Reader role and the API Access permission, without UI access where the subscription allows. Required. A username containing `:` is refused, because HTTP Basic separates the user from the password with one.
- `ca_bundle`: the absolute path of a PEM file on the host, never its contents. Optional.
- `sources`: optional, an object of booleans, `detections`, `knowledgebase` and `tags`, each on unless set `false` (`req-qualys-sources`). An envelope with every source off is refused, because it has nothing to read.
- `scope`: optional server-side filters, an object with at most one of `asset_group_ids` (a list of integers) or `tag_ids` (a list of integers), sent as Qualys's `ag_ids`, or as `use_tags=1&tag_set_by=id&tag_include_selector=any&tag_set_include=<ids>` (a host matching any one of the tags; the standing scope has no other selector). The scope is the subscription's **standing scope**: it is recorded on the subscription node and on every run, and a read made with it is a complete read of that scope (`req-qualys-detection-read`, `req-qualys-states`).

The envelope's description states the least-privilege shape: a Reader with API access only, scoped to the asset groups or tags that hold the in-scope AWS hosts. The collector reads every envelope in scope `qualys`. Each yields one subscription node, keyed by the canonical `api_host` and the `subscription` label together, encoded without ambiguity (`req-qualys-subscription-run`). An envelope that fails validation fails only its own run, naming `qualys:<key>`. These credentials have no scannable shape: a Qualys username carries a subscription prefix but no issuer marker, and the password is free text. So no `CredentialPattern` and no entropy rule is added. Protection rests on the envelope layer, the leak guard, `.gitignore` and redaction. The credential reaches `requests` as an auth tuple, never in a URL. No object holding it shows it in its `__repr__`, and no log line, scan-run field or exception carries a value.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-qualys-connection-1 | Settings Are Not Nodes | Proposed | No node type declares a credential, CA-bundle or scope field, and the collector reads no connection setting from the grid. The subscription node holds the canonical API host and label as identity, written from the envelope and never read back to decide where to connect. | |
| req-qualys-connection-2 | Secret Never Echoed | Proposed | The username and password are absent from logs, scan-run properties, exception text and every `__repr__`, including when a request fails; a test fails a request and searches all of them. | |
| req-qualys-connection-3 | HTTPS Only, Strict Host | Proposed | An `api_host` that is not `https://`, or carries userinfo, a path, a query or a fragment, is refused before any request; two spellings of one host give one key. | Qualys serves its API only over HTTPS. |
| req-qualys-connection-4 | One Envelope Per Subscription | Proposed | Two envelopes yielding the same subscription key refuse the run before any request, naming both keys. | Two credentials for one subscription would make a detection set ambiguous. |
| req-qualys-connection-5 | Strict Credential Schema | Proposed | The schema admits only the fields above, every one described; a wrong kind or shape fails that subscription's run before any request, naming `qualys:<key>` and never a value. | |
| req-qualys-connection-6 | Undetectability Is Recorded | Proposed | The spec states these credentials have no scannable shape; a test asserts no `CredentialPattern` was added. | Silence would look like coverage. |

### The Read-Only Transport
----
RID: `req-qualys-transport`

Status: `In Development`

How requests leave the plugin. A small client of our own over `requests`. Every request passes through one `requests.Session` subclass whose `send` decides what may be sent.

#### Implementation

`tap_plugin/qualys/client.py`. The guard is in `Session.send`, so remounting an adapter does not bypass it, and the client does not expose its session. Before anything is sent, `send` refuses:

- any URL outside the configured `api_host`;
- any redirect;
- any override of TLS verification, client certificate or proxies, with `trust_env` off so no proxy, CA bundle or netrc credential is taken from the environment;
- any operation not on the allowlist.

The allowlist is the plugin's one definition of "read", and a change to it is a spec change. It holds five operations, four GET and one POST:

- `GET /api/6.0/fo/asset/host/vm/detection/` with `action=list`;
- `GET /api/4.0/fo/knowledge_base/vuln/` with `action=list`;
- `GET /api/6.0/fo/asset/host/vm/detection/dtd/output.dtd` and `GET /api/4.0/fo/knowledge_base/vuln/knowledge_base_vuln_list_output.dtd`, the two output DTDs, with no parameters at all. The observation command reads them (`req-qualys-observe`); the collector does not;
- `POST /qps/rest/2.0/search/am/tag`, the Asset Management and Tagging tag search (`req-qualys-tags`). It is the only way Qualys lists tags: the API's only tag GET returns one tag by id. The request has no query string, is sent as `text/xml`, and its body must match one fixed template exactly: `<ServiceRequest><preferences>`, an optional `<startFromId>` of digits, a `<limitResults>` of digits, and nothing else. The client builds that body itself, and `send` re-checks it, so the POST can carry no criteria, no tag data and no other operation. An anonymous client may not send it.

A client built with no credential (`ReadOnlyClient.anonymous`) sends no `Authorization` header and may send only the two DTD reads; a credentialed client refuses to be built with an empty username or password, and the transport treats anything short of both as no credential, so the observation command can learn whether Qualys serves them without one. An optional observer on the client sees every response, with the response headers minus `Set-Cookie` and only the names of the request headers, so the observation command can record it.

The two list operations each name the parameters they may carry, as pinned values or as free values of a stated shape (digits, a comma-separated id list, an ISO-8601 time). An unnamed parameter is refused. A POST is admitted only for a read Qualys offers in no GET form, added to the list by a spec change (ruled 2026-11-20, Q8a); the tag search is the one admitted (ruled 2026-11-23, when George chose to collect every tag in the subscription knowing the list needs a POST).

Authentication is HTTP Basic with the `X-Requested-With` header Qualys requires. The session-login endpoint (`/api/2.0/fo/session/`) is not on the list, so that path is unreachable. Calls run one at a time, because the standard tier allows 2 concurrent calls per API shared by every integration on the subscription.

A 409 is read by its `SIMPLE_RETURN` code. Code 1960 (concurrency) or 1965 (rate) means wait: `X-RateLimit-ToWait-Sec` is honoured, and retries are bounded in count and total time. Any other code is a recorded error, never a wait, because a 409 from the knowledge base has been reported to mean a missing permission. The concurrency headers are read under both documented spellings (`X-Concurrency-Limit-*` and `X-ConcurrencyLimit-*`), case-insensitively. A 1960 wait is at least 30 seconds: XSOAR's integration reports the header as 0 for 1960 and waits a fixed 60 (one vendor comment, not a Qualys statement), and 8 retries of a 1-second wait would be spent in 8 seconds (unified-systems-com/qualys-tap#48).

A transient failure is asked again: a 429, 500, 502, 503 or 504, a refused or reset connection, a connect or read timeout, or a body cut short. It is retried at most 3 times, after 5, 30 and 120 seconds, inside the same total wait bound as the throttle waits; then the read fails with the last status or network error (unified-systems-com/qualys-tap#47). Any other status, a certificate or TLS failure, a proxy error, a refusal by the transport and a body over the ceiling are never retried. Reading a list again is safe because every operation is a read. The observation command turns transient retries off, because it records what Qualys answered and a retry would hide the first answer.

The per-request ceiling bounds each attempt, the request and its body, and not the waits between attempts, which the total wait bound covers; otherwise a long 1965 wait would hit the 900-second ceiling before the 1800-second wait budget (unified-systems-com/qualys-tap#49). An attempt abandoned at the ceiling is not retried, and the transport replaces the session that attempt still holds, so no later request shares a connection pool with it. Until the abandoned attempt finishes, every further read is refused unsent, so calls stay one at a time against the subscription's shared concurrency limit. The run's total ceiling reaches inside the retries: no attempt starts once it has passed, and no wait starts that would reach it, so a run ends at most one per-request ceiling past its own (plus however late the operating system returns from a sleep, which no sleep can rule out), the bound it had before the per-request ceiling moved around each attempt (PR #62 round 4).

The next-page URL in `RESPONSE/WARNING/URL` is followed only when it names the same host and the same operation's path, and its parameters pass the same allowlist.

Responses are bounded before parsing: a body over 256 MiB is refused, and so is XML nested deeper than 64 levels or carrying a DTD that declares entities. XML is parsed with `defusedxml`, never the standard library parser. Each refusal is recorded as not read. A read also has a total time ceiling.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-qualys-transport-1 | Allowlist At The Transport | Proposed | Every request passes through one `send` that refuses any operation not on the list; a POST, a DELETE, the session-login path, an aliased method and a request from another module are each refused. | Negative tests for each; a source scan is secondary. |
| req-qualys-transport-2 | Bound To The Host | Proposed | A request to any other host, scheme or port is refused, and so is any redirect, before a second request is sent. | The session holds the credential. |
| req-qualys-transport-3 | Unnamed Parameters Refused | Proposed | A request carrying a parameter the allowlist does not name, or a named one in the wrong shape, is refused before it is sent. | |
| req-qualys-transport-4 | Throttling Is Waited, Other 409s Are Errors | Proposed | A 409 with code 1960 or 1965 waits the time Qualys gives, within the retry bound; a 409 with any other code is a recorded error; exhaustion is a recorded failure, never an empty result. | `LIM`; Microsoft's KB note. |
| req-qualys-transport-5 | Next Page Stays Put | Proposed | A next-page URL naming another host, another path or an unlisted parameter ends the read as a recorded failure. | |
| req-qualys-transport-6 | Hostile XML Refused | Proposed | A body over the size ceiling, nested past the depth ceiling, or declaring entities is refused and recorded as not read, never partly stored; tests feed each case. | `defusedxml`. |
| req-qualys-transport-7 | Verification Cannot Be Overridden | Proposed | A per-request `verify`, `cert` or `proxies` override is refused; the CA bundle is applied on the session by the plugin only. | |
| req-qualys-transport-8 | POST Only By Spec Change | Proposed | The allowlist holds exactly one POST, the tag search, and a test fails if the POST list changes. That POST is refused unsent with a query string, with any content type but `text/xml`, with a body outside its template (criteria, tag data, anything else), from an anonymous client, and on any other path, the tag create, update and delete paths among them; a GET to the tag search path is refused too. | Ruled 2026-11-20 (Q8a); the tag search admitted 2026-11-23. `test_qualys_tags.py::TestTheOnePost`. |
| req-qualys-transport-9 | Transient Failures Retried, Waits Outside The Ceiling | Proposed | A 429 or 5xx in the transient set, or a network error, is retried at most 3 times with backoff inside the total wait bound; other failures are not retried; a 1960 wait is at least 30 seconds; the per-request ceiling wraps each attempt and no wait runs inside it; no attempt starts once the run's ceiling has passed, and no wait starts that would reach it. | unified-systems-com/qualys-tap#47, #48, #49. |

### Probe And Provenance
----
RID: `req-qualys-probe`

Status: `In Development`

Before reading data in earnest, the collector checks that the credential works and the pinned version answers, and records what the subscription says about itself, so a detection can be judged against the read behind it.

#### Implementation

The probe is the first detection page with `truncation_limit=1`. It is an ordinary allowlisted read, so the plugin needs no extra endpoint. A 401, or a response that is not a detection document, ends the run before any node is written, recorded as an error. From the probe and from every later response, the run records:

- the API versions used (from the constants);
- the rate-limit and concurrency headers as returned, under both spellings;
- any end-of-support or deprecation text Qualys puts in a response's warning element, as `API_VERSION_EOS` with the text bounded and stored.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-qualys-probe-1 | Probe Before Data | Proposed | The probe completes before the full read, and its results are on the scan run. | |
| req-qualys-probe-2 | Refused Credential Stops | Proposed | A 401 or a non-detection response to the probe ends the run with nothing written. | |
| req-qualys-probe-3 | End Of Support Is Visible | Proposed | Deprecation or end-of-support text in any response is recorded on the run as `API_VERSION_EOS`; a test feeds a response carrying it. | The text's shape is unobserved. |
| req-qualys-probe-4 | Limits Recorded | Proposed | The rate-limit and concurrency headers of the last response are on the run, `null` where absent. | |

### Contract Extract And Offline Tests
----
RID: `req-qualys-contract-extract`

Status: `In Development`

A committed extract of the part of Qualys's output DTDs this plugin reads, produced by a script and never typed, and tests that check the parser against it with no network. The plugin's `ci` boot record excludes network access, so nothing in the normal suite calls Qualys.

#### Implementation

`tap_plugin/qualys/contract/extract.json`, with a JSON Schema and a `description` on the top level and every entry. `tap_plugin/qualys/contract/reduce.py` produces it from a DTD and the element paths named in `contract/consumed.json`: each consumed element, its content model, its attributes and whether each is required. The committed sources are the host detection 6.0 output DTD and the knowledge base 4.0 output DTD, under `tests/vendor/`, with `provenance.json` recording where each came from, the fetch date and its hash. They are the DTDs Qualys serves at the documented paths, fetched without a credential from the US1 platform host and saved byte for byte. The first copies came from Qualys's DTD reference ([DTD](https://cdn2.qualys.com/docs/qualys-api-vmpc-dtd-reference.pdf)), which shows the `/api/2.0` outputs. The served 6.0 and 4.0 DTDs extend those with optional children only, and replaced them on 2026-11-21. `contract/build.py` regenerates the extract, and `--check` tests it.

Every response is checked against the extract before any node is written. A required element that is missing or malformed fails that page. An empty or whitespace-only page within the page-size ceiling (even with a 200) fails it too, refused as `EmptyBody` (an oversized one is refused for its size first, never scanned) so the run's record tells it from a malformed page: an empty answer is missing evidence, never a page with no hosts, because a complete read that took it for one would withdraw every host held (unified-systems-com/qualys-tap#52, ruled Q30a). An element the extract does not name is tolerated and not stored. A required child is checked only when the plugin reads it, so an unread element the DTD requires (the knowledge base's `DISCOVERY`) cannot fail a page. Where a DTD names an element in a content model but never declares it, `consumed.json` lists it under `named_not_declared` with the reason; the reducer checks the name really is named and really is undeclared, and records it with no content model. The reference PDF left `ASSET_ID` undeclared; the served DTD declares it, so no element is listed today. The served DTD declares `CLOUD_PROVIDER_TAGS` as `(CLOUD_TAG+)` and `CLOUD_TAG` as `(NAME, VALUE, LAST_SUCCESS_DATE)`. Each tag's `NAME` and `VALUE` are read into the host's `cloud_tags` (`req-qualys-aws`). `LAST_SUCCESS_DATE` is not read under `CLOUD_TAG`. The check matches children by name, and the same element is read under `ATTRIBUTE`, so the parser names it as not read under `CLOUD_TAG`. A tag that lacks it therefore refuses no page, while one lacking `NAME` or `VALUE` still does. Ledger `cloud-provider-tags-shape` stays open until a recording confirms the DTD. The reducer takes a DTD as data and never resolves an external entity or fetches anything. It refuses a document over a fixed size, treats a parameter-entity cycle as an error, and bounds expansion: at most 1,000 parameter-entity references expanded and at most 1 MiB of expanded text per document, so an acyclic chain cannot grow exponentially.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-qualys-contract-extract-1 | Generated, Not Typed | Proposed | The extract is the reducer's output from the committed DTDs; a test regenerates it and compares. | |
| req-qualys-contract-extract-2 | No Network In The Suite | Proposed | The plugin's tests open no socket; the client and parser run against fixtures. | |
| req-qualys-contract-extract-3 | Validate Before Write | Proposed | A page whose required elements fail the extract writes nothing; a required scope that fails is an error, an optional one is recorded as not read. | |
| req-qualys-contract-extract-4 | Reducer Is Bounded | Proposed | The reducer refuses an external entity, an entity cycle, an oversized document and an acyclic exponential parameter-entity chain, each without any I/O of its own; tests feed each case. | |
| req-qualys-contract-extract-5 | Malformed Knowledge Base Is A Recorded Failure | Proposed | A knowledge-base page that is not well-formed is recorded as not read for its QIDs, and the run continues. | QualysETL release notes. |
| req-qualys-contract-extract-6 | Empty Body Is A Named Failure | Proposed | An empty or whitespace-only page within the page-size ceiling is refused as `EmptyBody` (an oversized one is refused for its size), recorded as `not read: EmptyBody`; the walk is incomplete, nothing is withdrawn and the watermark holds. On the probe it is a failed probe. | unified-systems-com/qualys-tap#52, ruled Q30a. |

### Scheduled Drift Check
----
RID: `req-qualys-drift-ci`

Status: `In Development`

A scheduled workflow compares the DTDs Qualys serves with the committed sources, reduces both with the same reducer, and fails when what the plugin reads has changed.

#### Implementation

`.github/workflows/qualys-drift.yml`, scheduled weekly and on demand, with `contents: read` and no write token: the failing run is the signal, and no issue is opened. Its `served` job runs `python -m tap_plugin.qualys.contract.drift`, which uses only the standard library, so that job installs nothing. It fails on a changed consumed element and lists other changes in the run summary without failing.

Qualys serves its API DTDs without a credential: fetched from `qualysapi.qualys.com` on 2026-11-21. So the workflow fetches both from the documented DTD paths on that host (`drift served`), with no redirect followed and a size bound. Other platforms are not checked; the ledger entry `dtd-unauthenticated` stays open for them, and the observation command reports it per subscription. Two other modes stay available by hand:

- `drift reference` compares the reference PDF's hash with the one recorded in `provenance.json`, for a platform that does not serve its DTDs;
- `drift file <document> < <path>` compares a DTD on disk, read from standard input; the command takes no path.

The DTDs carried by each export archive are compared at load time through the same function (`req-qualys-file-import`).

A second job, `elastic-fixtures`, holds the parsers to third-party pages (unified-systems-com/qualys-tap#45, ruled Q28a). Elastic's `qualys_vmdr` integration ships a mock Qualys server whose configuration carries 5.0 detection pages and 4.0 knowledge-base pages from three platforms. It is under the Elastic License 2.0, so it is never committed here. `python -m tap_plugin.qualys.contract.elastic` fetches it at a pinned commit, refuses it unless its SHA-256 is the recorded one, and parses every page. The job fails if a page is refused, or if a page yields a different count of hosts, detections or QIDs than recorded. The parser needs `defusedxml`, which the job installs by hash into a throwaway virtual environment, at the same pin as `pyproject.toml`. The suite opens no socket (`req-qualys-contract-extract-2`), so the fetch lives here; the extraction and the expectations are tested offline. Moving the pin is one deliberate change: commit, hash and expectations together.

No credential is ever placed in CI.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-qualys-drift-ci-1 | Fails On Consumed Drift | Proposed | A change to a consumed element, attribute or content model fails the run. | |
| req-qualys-drift-ci-2 | Reports Other Changes Without Failing | Proposed | A change outside the consumed set is listed in the run summary and does not fail. | |
| req-qualys-drift-ci-3 | Read-Only Permissions, No Credential | Proposed | The workflow grants `contents: read` only, opens no issue and uses no Qualys credential. | |
| req-qualys-drift-ci-4 | DTDs In Hand Are Compared Too | Proposed | The DTDs an export archive or a live run carries are reduced and compared with the extract when they are loaded, and a consumed difference is recorded on the run as `CONTRACT_DRIFT`. | Covers the case where CI cannot reach a DTD. |
| req-qualys-drift-ci-5 | Third-Party Pages Are Parsed | Proposed | A scheduled job fetches Elastic's `qualys_vmdr` mock configuration at a pinned commit, refuses it unless its SHA-256 matches, and fails if any page is refused or yields other counts than recorded. | unified-systems-com/qualys-tap#45; not vendored (Elastic License 2.0). |

### The Observation Command
----
RID: `req-qualys-observe`

Status: `In Development`

A tool for whoever tests against a real subscription. It reads a subscription through the read-only client in a fixed order, records every raw response locally, and reports which entries in the open-assumptions ledger the responses answered. It is not the collector and writes nothing to the grid.

#### Implementation

`tap_plugin/qualys/observe.py`, run as `python -m tap_plugin.qualys.observe --list` to see the envelopes and `--key <key>` to observe one. `--dry-run` prints the plan and sends nothing. It imports nothing from the grid, so it runs without Django. The order is:

1. the probe;
2. one full detection page with every parameter of `req-qualys-detection-read`;
3. the knowledge-base records for that page's QIDs, at most ten requests, no paging followed;
4. two comparison reads two ledger entries need: the probe's host again, pinned by its id, without `host_metadata` (`cloud-resource-id-without-metadata`; a different host returned is not compared), and, only when the page holds an ignored or disabled detection, the same page from its first host id without `include_ignored` and `include_disabled` (`ignored-disabled-default`);
5. the two DTDs, first by a client with no credential (`dtd-unauthenticated`), then with the credential only if that was refused (HTTP 401 or 403); any other failure leaves the DTD unread.

Every request goes through `ReadOnlyClient` and its allowlist, each bounded by the collector's per-request ceiling. A read that fails is reported as a step outcome, and the reads after it still run, except that a failed probe skips the reads that depend on it.

A response is saved as one file with its status, the response headers minus any `Set-Cookie`, the names (never the values) of the request headers, and the body. A response whose body the transport refused to read (past the size ceiling, or a broken stream) is still saved, with its status and headers, an empty body and the reason. The file is a JSON header line, a blank line, then the body exactly as received. The files go under `~/.local/state/qualys-observe/<key>/<UTC time>/`, or under `--out`, refused when the directory is inside a repository or any directory below the checked base is a symbolic link, and refused when the base or key directory is writable by group or others, or the key directory belongs to another user. Each directory below the base is opened relative to the one above it without following a link, and every file is written through a handle held on the run directory, so renaming or replacing a directory on the path after its check cannot redirect a recording. Directories the command creates are owner-only (0700); an existing one keeps its mode and files owner-only (0600), never overwriting; a second observation of the same key in the same second gets its own directory, suffixed `-2`, `-3` and so on. The report prints shapes, counts and statuses, never a body, credential, host name, address or account id. It exits 0 when the probe was read, 1 when it was not, and 2 when it could not start.

The open-assumptions ledger is `tap_plugin/qualys/observe_assumptions.json`, with a JSON Schema. Its v0 entries, each settled only by a recording:

| Entry | The assumption |
| --- | --- |
| `subscription-identity` | Whether any read in the allowlist returns a subscription identifier |
| `ec2-account-attribute` | The EC2 account-id attribute name in `METADATA/EC2` |
| `cloud-resource-id-without-metadata` | Whether `CLOUD_RESOURCE_ID` is returned without `host_metadata` |
| `ignored-disabled-default` | Whether ignored and disabled detections are excluded when the parameters are omitted |
| `unique-vuln-id-collision` | Whether one `UNIQUE_VULN_ID` is seen under two QIDs |
| `kb-409-meaning` | Whether a knowledge-base 409 can carry a code other than 1960 or 1965 |
| `concurrency-header-spelling` | Which concurrency header spelling is returned |
| `dtd-unauthenticated` | Whether the API DTDs are served without a credential |
| `eos-warning-shape` | The shape of an end-of-support warning |
| `package-table-variants` | Which package-table header variants appear in result text |
| `cloud-provider-tags-shape` | The shape of `CLOUD_PROVIDER_TAGS`, which the DTD names but does not declare |

Each entry states the question, the assumption the plugin works under today, and which response settles it. The report gives every entry one outcome: settled (a recording agrees with the assumption), contradicted (one disagrees) or not reached (nothing recorded could decide it). A contradicted entry is a spec change to make, citing the recording. A check that itself fails is reported as not reached, never hiding the others.

Recordings are never committed. A fixture is committed only after the operator has reviewed a trimmed copy.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-qualys-observe-1 | Only Allowlisted Reads | Proposed | Every request goes through the same transport; nothing outside the allowlist is reachable. | |
| req-qualys-observe-2 | Local And Private | Proposed | Recordings are written outside any repository with owner-only permissions, and nothing is written to the grid. | The repository is public. |
| req-qualys-observe-3 | Nothing Sensitive Printed | Proposed | The report contains no body, credential, host name, address or account id; text that came from Qualys is stripped of control characters and bounded before it is printed. | |
| req-qualys-observe-4 | Every Ledger Entry Reported | Proposed | Each ledger entry appears in the report as settled, contradicted or not reached. | |
| req-qualys-observe-5 | Dry Run Sends Nothing | Proposed | `--dry-run` and `--list` send no request. | |

### Three States And Resolution
----
RID: `req-qualys-states`

Status: `In Development`

How the collector records absence and change. Every place absence can occur has three outcomes, and the plugin keeps them apart. A detection resolves on Qualys's word alone.

#### Implementation

The following are each recorded as *not read* on the scan run with the reason, never as zero detections:

- a page that failed validation;
- a call that failed after its retries;
- a read refused by a filter Qualys rejected;
- a QID whose knowledge-base record could not be read.

A field nothing observed is `null`, an observed-empty list is `[]`, and an observed empty string stays `""`.

**Resolution.** A detection's state follows Qualys's `STATUS` as returned (`New`, `Active`, `Re-Opened`, `Fixed`) and is stored exactly. It is `resolved` exactly when Qualys reports `Fixed`, with `resolution_source: qualys_fixed` and Qualys's `LAST_FIXED_DATETIME`. When a later read reports the same detection `Re-Opened` or `Active`, it reopens. A detection absent from a read never changes state, whatever the read's scope: absence in a window read means only "not processed in this window", and absence in a complete read has no meaning Qualys has documented (ruled 2026-11-20, Q7c). Nothing is deleted. So a detection stays open, and its neutral finding with it, until Qualys says Fixed: a host purged from Qualys, an ignored or disabled detection Qualys never re-tests, and a QID Qualys stops returning all stay open. That is deliberate, and the README and the neutral finding's description state it so a consumer does not read it as a collector fault.

**Withdrawn hosts.** A host Qualys no longer reports in a complete read of the subscription's standing scope is marked `withdrawn`, with the run that saw it gone. A complete read has no time window and no filter beyond the standing scope, which is the least-privilege setup this spec recommends, so withdrawal works under it. Its detections keep the state they had, because a host leaving the scope or the subscription is not evidence that anything on it was fixed. A host that returns becomes `current`. A window read, a read narrower than the standing scope, a failed read and the first read after the standing scope changed withdraw nothing.

QID nodes carry no `state`: they are reference data, not assertions.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-qualys-states-1 | Not Read Is Not Clean | Proposed | A page or call not read produces no state change and is listed as not read on the run with its reason. | |
| req-qualys-states-2 | Null Is Unobserved | Proposed | A field the response did not carry is `null`, never `""`, `0` or `false`. | |
| req-qualys-states-3 | Only Fixed Resolves | Proposed | A detection is `resolved` only when Qualys reports it `Fixed`; a test drops a detection from a complete read and finds it unchanged. | Ruled 2026-11-20 (Q7c). |
| req-qualys-states-4 | Re-Opened Reopens | Proposed | A resolved detection that Qualys reports `Re-Opened` or `Active` becomes open again, with every other field updated as returned. | |
| req-qualys-states-5 | Withdrawn Host, Untouched Detections | Proposed | A host absent from a complete read of the standing scope becomes `withdrawn` and none of its detections change state; a window read, a narrower read and the first read after a scope change withdraw nothing; a test sets a standing asset-group scope and withdraws a host that left the group. | Ruled 2026-11-20 (Q7c). |
| req-qualys-states-6 | Nothing Is Deleted | Proposed | No run deletes a node the plugin wrote. | |

### The Detection Read
----
RID: `req-qualys-detection-read`

Status: `In Development`

What one run asks Qualys for, and how a run knows where the last one stopped.

#### Implementation

Every detection read sends `action=list`, `status=New,Active,Re-Opened,Fixed`, `show_results=1`, `show_reopened_info=1`, `include_ignored=1`, `include_disabled=1`, `show_asset_id=1`, `host_metadata=ec2`, `show_cloud_tags=1`, `show_qds=1` and `show_qds_factors=1` (without it Qualys returns no `QDS_FACTORS`, so `qds_factors` would always be null on a live read; unified-systems-com/qualys-tap#50), plus the envelope's scope filter when set. It pages by the next-page URL Qualys returns (`truncation_limit=1000`, documented default).

The first run for a subscription is **complete**: no time filter, and no filter beyond the standing scope. A later run is a **window** read: `vm_processed_after` set to the previous successful run's watermark, minus a fixed overlap of one hour so a detection processed during the last read is not missed. The watermark is the start time of a run whose every page was read and validated, and it is stored on the subscription node. A run that failed, stopped early, ended on a next-page URL it did not follow (`TRUNCATED`), holds pages that are not one unbroken next-page chain (`TRUNCATED`: a page other than the last with no link, or a following page whose first host is below the link's `id_min` or not above the linking page's last host; `unified-systems-com/qualys-tap#19`), hit a size or time ceiling, recorded any detection page in `scopes_not_read`, or read any page only partly (an unkeyable detection, `req-qualys-detection-5`) does not advance it. A complete read is repeated on a fixed interval (default 7 days, a constant in v0) so host withdrawal (`req-qualys-states`) can be judged. `detection_updated_since` is not used until the ledger settles it.

The run records:

- the canonical filter it applied;
- whether it was complete or a window, and the window bounds;
- the page count;
- whether the last page ended on a next-page URL that was not followed, and, when the pages are not one chain, where it broke.

The chain check cannot see a page dropped cleanly from the middle whose successor still starts above the link's `id_min`, because host ids are sparse and Qualys does not say where the next page starts. A live read builds its own chain, so this limit matters only for an archive, whose page list the operator vouches for (`req-qualys-file-import`).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-qualys-detection-read-1 | All Statuses Requested | Proposed | Every detection read carries all four statuses; a test fails a request without `Fixed`. | Without it, Fixed never arrives. |
| req-qualys-detection-read-2 | Ignored And Disabled Collected | Proposed | Every detection read carries `include_ignored=1` and `include_disabled=1`, and the flags are stored on each detection. | Ruled 2026-11-20 (Q5b). |
| req-qualys-detection-read-3 | Watermark Only From A Clean Run | Proposed | The watermark advances only after a run whose every page was read and validated; a failed run, a `TRUNCATED` run, a run that hit a ceiling, a run with any detection page not read, and a run with a page holding one unkeyable detection each leave it as it was, and a test covers each. | |
| req-qualys-detection-read-4 | Filter Recorded | Proposed | The run records the canonical filter, the read kind and the window bounds exactly as sent. | |
| req-qualys-detection-read-5 | Invalid Filter Refuses | Proposed | A scope Qualys rejects ends the run before any node is written; it never falls back to an unfiltered read. | |

### Subscription And Scan Run
----
RID: `req-qualys-subscription-run`

Status: `In Development`

The record of which subscription was read and what each collection did.

#### Implementation

- `qualys_subscription` (`qualys.area: run`): one per envelope, keyed by `subscription_key`: the compact JSON array `[canonical api_host, subscription label]`, never a delimiter join, so no two (host, label) pairs encode alike. It carries the watermark, the standing scope, the time of the last complete read and the API versions last used.
- `qualys_scan_run` (`qualys.area: run`): one per collection, keyed `(subscription_key, run_id)` with a `run_id` the collector mints once per run, so every edge a run's batch writes resolves to one run node. It carries:
  - `source` (`api` or `file`);
  - the probe results;
  - the read kind, filter and window;
  - `scopes_not_read`, with a reason each;
  - the counters (hosts, detections, QIDs, neutral findings, packages, EC2 links found and unresolved);
  - the warning codes below, the one place they are defined.

`RUN_OF_SUBSCRIPTION__qualys` joins the run to its subscription.

| Warning | Meaning | Source |
| --- | --- | --- |
| `API_VERSION_EOS` | Qualys reported end of support for a version read | `req-qualys-probe-3` |
| `CONTRACT_DRIFT` | A DTD in hand differs from the extract in a consumed element | `req-qualys-drift-ci-4` |
| `THROTTLED` | At least one 409 wait occurred | `req-qualys-transport-4` |
| `TRUNCATED` | A read stopped with a next-page URL not followed | `req-qualys-detection-read-4` |
| `EC2_UNRESOLVED` | One or more hosts named an AWS instance `aws_core` does not hold | `req-qualys-ec2-link-3` |
| `AWS_CORE_ABSENT` | `aws_core` is not installed, so no EC2 link was attempted | `req-qualys-ec2-link-4` |
| `VALUE_DROPPED` | One or more values were stored as null because their column could not hold them; the detail names each | `req-qualys-detection` |
| `READ_KIND_DOWNGRADED` | A run labelled complete carried a filter other than the standing scope, so it was treated as narrower and withdrew nothing | `req-qualys-states-5` |

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-qualys-subscription-run-1 | One Subscription Per Envelope | Proposed | The subscription key is the JSON array of the canonical API host and the label; two labels on one host are two subscriptions, and a test shows that pairs whose concatenations match (`("a.b", "c")` and `("a", "b.c")`) give different keys. | |
| req-qualys-subscription-run-2 | Run Records Its Source | Proposed | Every run records `source` as `api` or `file`, with the export manifest's time for a file. | |
| req-qualys-subscription-run-3 | Warnings Defined Once | Proposed | Every warning code a run can record is in the table above; a test fails on an unlisted code. | |

### Hosts
----
RID: `req-qualys-host`

Status: `In Development`

A host as Qualys tracks it. This is Qualys's view of a machine, not the machine itself. The EC2 instance is `aws_core`'s, and this node links to it (`req-qualys-ec2-link`).

#### Implementation

`qualys_host` (`qualys.area: observation`), keyed `(subscription_key, host_id)` where `host_id` is Qualys's `ID`. It carries, as returned:

- identity and tracking: `ASSET_ID`, `IP`, `IPV6`, `TRACKING_METHOD` (for example `IP`, `DNS`, `AGENT`, `EC2`), `DNS`, `NETBIOS` and `OS`;
- scan times: `LAST_SCAN_DATETIME`, `LAST_VM_SCANNED_DATE`, `LAST_VM_AUTH_SCANNED_DATE` and the agent's last check-in where returned;
- cloud fields: `CLOUD_PROVIDER`, `CLOUD_SERVICE`, `CLOUD_RESOURCE_ID` and the deprecated `EC2_INSTANCE_ID`, each kept as returned;
- the EC2 metadata attributes as a JSON object of name to value;
- the cloud tags as a list.

`state` is `current` or `withdrawn` (`req-qualys-states-5`). Timestamps are stored as the strings Qualys returns, beside a parsed UTC value. `LAST_SEEN_IN_RUN__qualys` moves to the run that last read the host.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-qualys-host-1 | Keyed By Qualys's Host Id | Proposed | Two reads of one host id in one subscription are one node; the same id in two subscriptions is two nodes. | Whether host ids are unique across subscriptions is unobserved; the key does not rely on it. |
| req-qualys-host-2 | Cloud Fields As Returned | Proposed | `CLOUD_RESOURCE_ID`, `CLOUD_PROVIDER`, `CLOUD_SERVICE` and `EC2_INSTANCE_ID` are stored exactly as returned, each `null` when absent. | |
| req-qualys-host-3 | Agent And Scanner Alike | Proposed | Hosts tracked by agent and by IP or DNS are the same type, with `TRACKING_METHOD` telling them apart. | Ruled 2026-11-20 (Q1a). |

### Detections
----
RID: `req-qualys-detection`

Status: `In Development`

One detection: Qualys's assertion that a QID was found on a host.

#### Implementation

`qualys_detection` (`qualys.area: finding`), keyed `(subscription_key, host_id, qid, unique_vuln_id)`. Qualys documents that one `UNIQUE_VULN_ID` can be shared by a vulnerability and an information-gathered finding, so the QID is part of the key. The host id is in the key so that the key never rests on a fact the node does not carry. Port, protocol and SSL are properties, not key parts.

The node carries, as returned:

- the detection: `TYPE`, `PORT`, `PROTOCOL`, `FQDN`, `SSL`, `STATUS`, `SEVERITY`;
- its history: `FIRST_FOUND_DATETIME`, `LAST_FOUND_DATETIME`, `LAST_FIXED_DATETIME`, `LAST_REOPENED_DATETIME`, `TIMES_FOUND`, `TIMES_REOPENED`, `LAST_TEST_DATETIME`, `LAST_UPDATE_DATETIME`, `LAST_PROCESSED_DATETIME`;
- `IS_IGNORED`, `IS_DISABLED`;
- `QDS`, its `severity` attribute (`qds_severity`, unified-systems-com/qualys-tap#51) and its factors;
- `RESULTS` in full, never truncated into a key or a hash.

It also carries the resolution fields of `req-qualys-states` and, from `req-qualys-parsers`, the parse state, the parser id and version, and the observations.

Edges: `DETECTED_ON_HOST__qualys` (detection to host), `ABOUT_QID__qualys` (detection to QID) and `LAST_SEEN_IN_RUN__qualys` (to the run that last read it, moved each run). The detection draws no edge to a CVE; the QID does (`req-qualys-qid`).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-qualys-detection-1 | Keyed By Assertion | Proposed | The key is subscription, host id, QID and unique vulnerability id, never the run; two reads of the same detection are one node. | |
| req-qualys-detection-2 | QID In The Key | Proposed | A vulnerability and an information-gathered detection sharing one `UNIQUE_VULN_ID` on one host are two nodes. | `HLD`. |
| req-qualys-detection-3 | Fields As Returned | Proposed | Severity, status, QDS and every timestamp are stored as Qualys returns them; no scale, mapping or selection is applied. | |
| req-qualys-detection-4 | Result Text Whole | Proposed | `RESULTS` is stored in full and is in no key, digest or index. | DefectDojo had to remove output from its hash. |
| req-qualys-detection-5 | Unkeyable Entries Counted | Proposed | A detection missing its QID or unique vulnerability id is not stored, is counted on the run, and its host's page is recorded as partly read. | |

### Knowledge-Base Records
----
RID: `req-qualys-qid`

Status: `In Development`

What a QID means, from Qualys's knowledge base: its title, severity, scores and the CVEs it names.

#### Implementation

`qualys_qid` (`qualys.area: knowledge`), keyed `(subscription_key, qid)`. The knowledge base is the same for every subscription on a platform, but Qualys documents that what a subscription may see can differ, and the key does not assume otherwise.

The records are read only for the QIDs the run's detections named: `details=All`, in batches of at most 500 ids so the request URL stays short. They are refreshed on later runs by `last_modified_after` for the QIDs already held.

The node carries, as returned:

- `VULN_TYPE`, `SEVERITY_LEVEL`, `TITLE`, `CATEGORY`, `PATCHABLE`, `PUBLISHED_DATETIME`, `LAST_SERVICE_MODIFICATION_DATETIME`;
- the CVSS v2 and v3 base scores and vectors, and CVSS v4 where the 4.0 output carries it;
- `VENDOR_REFERENCE_LIST`;
- `CVE_LIST` as a list of identifiers, each with its URL.

A QID a detection names but the knowledge base did not return is recorded on the run as not read. Its detections keep their `ABOUT_QID__qualys` edge to a QID node written with its id and `kb_returned` false, so a record the knowledge base never returned is told apart from one whose fields Qualys left empty. `kb_returned` is true once a record is read, and null before any read was attempted.

`ABOUT_VULNERABILITY__qualys` goes from the QID to the shared `compliance_core__compliance_vulnerability`, one edge per CVE in the list. The record is matched exactly and case-sensitively, and created when the grid holds none (`req-qualys-neutral`). No alias is resolved.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-qualys-qid-1 | Only QIDs Seen | Proposed | The knowledge base is asked only for QIDs the run's detections named, in batches of at most 500. | Elastic's 414 lesson. |
| req-qualys-qid-2 | CVEs From The QID | Proposed | `ABOUT_VULNERABILITY__qualys` edges come from the QID, one per CVE; no detection carries a CVE edge. | Cartography's fan-out lesson. |
| req-qualys-qid-3 | Scores As Returned | Proposed | CVSS scores and vectors are stored per version as returned; none is chosen over another on this node. | |
| req-qualys-qid-4 | Missing Record Is Not Read | Proposed | A QID with no returned record is listed as not read on the run, and its node carries the id only. | |

### EC2 Instance Link
----
RID: `req-qualys-ec2-link`

Status: `In Development`

How a Qualys host reaches the EC2 instance it is. `aws_core` collects EC2 instances from AWS itself, the source of record, so the provider collector wins and this plugin only links (ruled 2026-11-20, Q2a; the Anchore stage-one rule).

#### Implementation

For a host whose `CLOUD_PROVIDER` is `AWS` and whose `CLOUD_SERVICE` is `EC2`, the plugin looks up `aws_core__aws_ec2_instance` by its natural key, `instance_id`, using the exact string in `CLOUD_RESOURCE_ID`.

- **Found:** it draws `TRACKS_EC2_INSTANCE__qualys` from the host to the instance, carrying the field the id came from. It changes nothing on the instance.
- **Not found:** the host is counted on the run as unresolved, with `EC2_UNRESOLVED`. Nothing is created.

`EC2_INSTANCE_ID` alone is never used to link. It is deprecated and also carries Azure ids, so a host with only `EC2_INSTANCE_ID` is counted as unresolved with that reason. `aws_core` is declared in `depends_on` with `optional = true`. Where it is not installed, no lookup is made and the run records `AWS_CORE_ABSENT`. Account and region from the EC2 metadata are stored on the host. They are not part of the link, because `aws_core` keys an instance by its id alone.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-qualys-ec2-link-1 | Exact Id, AWS Only | Proposed | The link is drawn only when `CLOUD_PROVIDER` is `AWS`, `CLOUD_SERVICE` is `EC2`, and `CLOUD_RESOURCE_ID` equals an instance's `instance_id` exactly. | |
| req-qualys-ec2-link-2 | Instance Never Written | Proposed | With the AWS integration off (the default), no node or field of `aws_core__aws_ec2_instance` is written by this plugin. With it on, an instance is created only where aws_core holds none, and one it holds is never written (`req-qualys-aws-2`). | Stage one; amended 2026-11-23 (Q38a reversed Q2a for the opt-in setting). |
| req-qualys-ec2-link-3 | Unresolved Is Counted | Proposed | A host naming an instance the grid does not hold is counted on the run and does not fail it. | |
| req-qualys-ec2-link-4 | Optional Dependency | Proposed | Without `aws_core` installed, no lookup is made, the run records `AWS_CORE_ABSENT`, and the run succeeds. | |
| req-qualys-ec2-link-5 | Deprecated Field Never Links | Proposed | A host carrying only `EC2_INSTANCE_ID` draws no link, and a test gives it an Azure-shaped id. | `RN1012`. |

### The Neutral Finding
----
RID: `req-qualys-neutral`

Status: `In Development`

The shared vulnerability page reads `compliance_core`'s types, not each scanner's. The rule ruled on 2026-11-17 for every scanner applies: a scanner writes the neutral finding beside its own records, may create the shared vulnerability record when it is absent, and uses its own CVSS score where the record has none. Qualys's QID fan-out sets the unit to the host and the CVE, as for Tenable.

#### Implementation

For each CVE in the CVE list of the QID of an open detection on a Qualys host, there is one `compliance_core__compliance_finding`, keyed `(source, source_key)`:

- `source` is `qualys`;
- `source_key` is the SHA-256 of the compact JSON array `[subscription_key, host_id, cve_id]` encoded as UTF-8, never of a concatenation, so distinct triples cannot collide by framing.

Two QIDs naming one CVE on one host make one neutral finding. Its status is `open` while any detection on that host whose QID names the CVE is open. It becomes `resolved` once every such detection is resolved under `req-qualys-states`, that is, once Qualys reported each one Fixed. Its name says the CVE and the host. Its summary gives the highest Qualys severity among the detections naming it, and `first_detected_at` the earliest `FIRST_FOUND_DATETIME` among them.

Edges:

- `DETAILS_COMPLIANCE_FINDING__qualys`, from each detection whose QID names the CVE to the neutral finding. It stays after the detection resolves.
- `CARRIES_COMPLIANCE_FINDING__compliance_core`, to the neutral finding from its carrier: the `computing_core` package when parsers resolved exactly one package across the detections naming the CVE on that host (`req-qualys-package-link`), otherwise the Qualys host, including when they resolved several (ruled 2026-11-20, Q7b; several packages carry no single answer, so none is chosen). The EC2 instance is reached through the host's link. Each run sends one edge-authority claim per neutral finding it writes, so a carrier that changes leaves exactly one edge.
- `CONCERNS_COMPLIANCE_VULNERABILITY__compliance_core`, from the neutral finding to the vulnerability record. The packages parser gives the required version, which is carried as `fixed_versions` when a parser is sure of it, and is otherwise absent.

**The vulnerability record.** For each CVE id a QID names, the record is created with that id when the grid holds none, and nothing is invented. When the record has no CVSS score, the QID's is written: the v3 base score before the v2, with its vector and version, and `cvss_source` "Qualys knowledge base". Nothing else on a held record changes. A CVE id over the record's 128 characters gets no record, edge or neutral finding.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-qualys-neutral-1 | One Per Host And CVE | Proposed | Two QIDs naming one CVE on one host give one neutral finding with source `qualys` and two detail edges; a second run writes no second finding or edge; the source key is a digest of a JSON array, and a test shows triples whose concatenations match give different keys. | |
| req-qualys-neutral-2 | Status Follows Qualys's Fixed | Proposed | The neutral finding is `open` while any detection naming the CVE on the host is open, and `resolved` once Qualys has reported every one Fixed. | |
| req-qualys-neutral-3 | Carried By The Package Or The Host | Proposed | The carrier is the one package parsers resolved for the CVE on the host, else the Qualys host, which also carries it when two or more packages were resolved; a fixture with two unambiguous package rows gives a host-carried finding; after a run with authority, a changed carrier leaves exactly one edge. | Ruled 2026-11-20 (Q7b). |
| req-qualys-neutral-4 | An Absent Record Is Created | Proposed | A vulnerability record the grid does not hold is created with the CVE's exact id; an id over 128 characters gets none. | |
| req-qualys-neutral-5 | Qualys's Score Fills, Never Replaces | Proposed | The QID's CVSS v3 base score, else its v2, is written to a record with no score, leaving its other fields as they were; a scored record is not written. | |
| req-qualys-neutral-6 | No Qualys Dimension | Proposed | The neutral finding carries no `qualys.*` dimension. | |

### Result Parsers
----
RID: `req-qualys-parsers`

Status: `In Development`

What ties a detection to a package is in its result text, not in a structured field. Qualys's package QIDs print a tab-separated table headed `Package`, `Installed Version`, `Required Version`. That shape is far more uniform across distributions than Tenable's per-plugin output, so v0 starts from one table parser with per-ecosystem version rules, under the same registry contract as Tenable's.

#### Implementation

`tap_plugin/qualys/parsers/` holds one module per output format. A module declares the QIDs it reads explicitly, as `QIDS`, or by a header match it states, as `HEADERS`. A QID listed by a module is matched before a header match. A parser is a pure function `parse(detection) -> list[PackageObservation]` with no I/O, where `detection` is the validated fields (`RESULTS`, the QID, the host's `OS`).

A `PackageObservation` has `ecosystem`, `name`, `installed_version`, `required_version`, `evidence` and `mapping_unambiguous`. Every field but the last is nullable. `mapping_unambiguous` is true only when `ecosystem`, `name` and `installed_version` identify exactly one `computing_core` package. `evidence` is the exact line the values were read from. The ecosystem comes from the host's `OS` (Debian or Ubuntu gives `deb`, an RPM-based distribution gives `rpm`). An `OS` the parser cannot place leaves `ecosystem` null and the mapping ambiguous.

A parser is registered in `parsers.REGISTERED` with its `PARSER_VERSION`. A QID claimed by two modules is refused. QIDs known to carry no package information are listed with a reason in `parsers.NOT_APPLICABLE`. The collector records exactly one parse state per detection:

- `parsed`: the parser returned observations (an empty list is a recorded result);
- `no_parser`: none matches. This never means "no package";
- `parser_failed`: the text matched a header but not the format; the raw text is kept and the failure counted on the run;
- `not_applicable`: listed in the registry with a reason.

The first module is `package_table`. It reads results beginning with the `Package` / `Installed Version` / `Required Version` header, including the `Installed_Version` and `#table` variants Elastic handles. It splits on newlines and tabs and tolerates trailing lines that are not package rows. It keeps the dpkg epoch and the RPM architecture inside the raw version string, and marks the mapping ambiguous wherever an epoch or architecture makes the `computing_core` version uncertain.

Every parser ships with a fixture at `tests/fixtures/<module>.txt` whose first line is `# fixture-evidence: documented (...)` or `# fixture-evidence: observed (...)`, plus a test. Parsing edits no stored Qualys field, so an improved parser re-parses stored detections without re-collecting.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-qualys-parsers-1 | Four States | Proposed | Every detection carries exactly one of parsed, no parser, parser failed, not applicable; no detection reads as "no package" without a parse. | |
| req-qualys-parsers-2 | Pure And Registered | Proposed | Parsers do no I/O, declare a version, and a QID claimed twice is refused at import. | |
| req-qualys-parsers-3 | Evidence Kept | Proposed | Each observation carries the exact line it came from, and the raw result text is unchanged. | |
| req-qualys-parsers-4 | Fixture Per Parser | Proposed | Every registered parser has a fixture with an evidence line and a test; a parser with a documented fixture does not reach `Implemented`. | Built blind. |
| req-qualys-parsers-5 | Package Table Variants | Proposed | The table parser reads the `Installed Version`, `Installed_Version` and `#table` header forms, and a test covers each. | Elastic's pipeline. |

### Package Link
----
RID: `req-qualys-package-link`

Status: `In Development`

A detection reaches the `computing_core` package it concerns only when the parser is sure which one it is.

#### Implementation

For a `parsed` observation with `mapping_unambiguous` true, `FOUND_IN_PACKAGE__qualys` goes from the detection to the `computing_core__package` keyed by `ecosystem`, `name` and `installed_version`. When the grid holds none, the package is created with those key fields only (ruled 2026-11-20, Q8b, following the Tenable ruling of 2026-11-19, Q62). An existing package is never changed. An ambiguous observation draws no edge and is stored on the detection as it was parsed.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-qualys-package-link-1 | Only When Sure | Proposed | The edge is drawn only for an unambiguous observation; an ambiguous one draws none. | |
| req-qualys-package-link-2 | Absent Package Created With Keys Only | Proposed | A package the grid does not hold is created with its key fields and no others; a held package is never written. | Ruled 2026-11-20 (Q8b). |

### Export Archive Import
----
RID: `req-qualys-file-import`

Status: `In Development`

When nobody running the collector has API access, someone who does runs `tools/qualys-export/qualys-export.sh`. It is a standalone, read-only script with its own README, kept as simple as possible so anyone can run it (ruled 2026-11-20, Q9a). The collector loads the archive it produces onto the grid through the same code a live read uses.

#### Implementation

`python manage.py qualys_load <archive.tgz> --subscription <label>`, a management command beside the collector. It:

1. Opens the archive without extracting outside a private temporary directory. Only regular files and directories are accepted: absolute paths, `..` segments, symbolic and hard links, devices and FIFOs are refused. Limits are enforced while reading, before anything is written: each member at most the response size ceiling, at most 10,000 members, at most 4 GiB expanded in total, a compression ratio of at most 100 to 1, and a wall-clock ceiling on the whole load.
2. Reads `export.json` (`script_version` 2 or 3) for the API host, the scope, the API versions and the file counts. An archive whose API versions differ from the plugin's constants, or whose counts disagree with its members, is refused. The manifest's `created_at` is recorded but trusted for nothing: the archive is not authenticated, so a time the archive asserts cannot gate state.
3. Reduces any DTDs the archive carries and compares them with the extract (`req-qualys-drift-ci-4`).
4. Feeds the `hld-*.xml` pages and `kb-*.xml` files, in order, through the same contract check, parsers and resolution rules as a live read, and submits the same GRIFT batch. Version 3 of the script asks again, by id, for the QIDs a cut-short knowledge-base batch left out, rather than following Qualys's link, and saves each further page as `kb-<batch>-NN.xml` (`unified-systems-com/qualys-tap#16`). The loader requires each batch's pages to be numbered from 1 without a gap, and refuses a continuation page in a version 2 archive. Only a link on a batch's last page makes the knowledge base incomplete, so the QIDs that batch did not return are unobserved, not absent.

The subscription key is the archive's API host and the `--subscription` label. An operator who later runs live reads uses the same label in the envelope, so the two line up. The run's read time is the earliest `RESPONSE/DATETIME` Qualys stamped on the archive's detection pages, read from the data rather than the manifest. A read time later than the moment of loading is refused. The run records `source: file`, that read time, the manifest's `created_at` as reported, and the archive's SHA-256.

**Trust.** An archive is not authenticated, and v0 does not try to authenticate it: loading one is an operator act, and the operator who loads it vouches for where it came from, as with any other data an operator brings onto the grid (ruled 2026-11-20, Q12c). What the loader does guarantee is that a malformed or hostile archive cannot escape its limits (step 1), that its contents pass the same contract check as a live read, and that the run names exactly which archive was loaded, by SHA-256, so its effects can be traced and undone.

The manifest's `scope` is `null` or `{kind, values, tag_match}`, with `kind` one of `asset_group_ids`, `asset_group_titles`, `tag_ids` or `tag_names`. An archive is a complete read when its scope matches the subscription's standing scope exactly: both empty; or `asset_group_ids` with the same set of ids as the standing `asset_group_ids`; or `tag_ids` with the same set of ids as the standing `tag_ids` and `tag_match` `any`, the selector a live read sends. Every other archive is a narrower read and withdraws nothing, including one scoped by titles or names, which v0 does not resolve to ids, so it fails closed rather than guess. The withdrawal rules of `req-qualys-states` then apply unchanged: a matching-scope archive marks every current host it does not contain `withdrawn`, which changes no detection and deletes nothing, and the next read that reports the host makes it current again (ruled 2026-11-20, Q15a). Under the trust rule above, that is the only way a subscription fed by files notices a decommissioned host. A file load never advances the live watermark. An archive whose read time is older than the subscription's newest recorded read is refused, with no override: an old file must not reopen what a newer read showed fixed, nor add detections a newer read no longer showed.

The script is part of this requirement's surface. Its allowlist of reads is the transport's, written out in shell, and it is held to a static form: exactly one `curl` invocation, in one function, with fixed options; every URL built from the parsed API host and a literal path; no `eval`, no command built from a string. It keeps TLS verification on and the password off the command line, and it drops cookies from the saved headers. A change to what it requests is a change to this spec.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-qualys-file-import-1 | Same Path As A Live Read | Proposed | A recorded set of pages loaded from an archive and the same pages read through a faked transport produce the same nodes and edges, apart from the run's source fields. | |
| req-qualys-file-import-2 | Archive Is Untrusted | Proposed | Absolute paths, `..`, links, devices, FIFOs, an oversized member, too many members, too many expanded bytes and a compression bomb are each refused before anything is written; tests feed each. | |
| req-qualys-file-import-3 | Manifest Checked | Proposed | An archive whose versions or counts disagree with the plugin or with its own members is refused, naming the mismatch. | |
| req-qualys-file-import-4 | Older Archive Is Refused | Proposed | An archive whose read time, taken from Qualys's `RESPONSE/DATETIME` and never from the manifest, is older than the subscription's newest recorded read is refused with no override and changes nothing; a read time later than the load is refused; a test edits `created_at` to the future and finds the decision unchanged. | |
| req-qualys-file-import-6 | Only A Matching Scope Is Complete | Proposed | An archive is a complete read only when its scope equals the standing scope (both empty; the same asset-group id set; or the same tag id set with `tag_match` `any`); an archive scoped by titles or names, by a different set, or by tags with `tag_match` `all` is a narrower read and withdraws nothing; a test covers each. | A matching-scope archive withdraws, ruled 2026-11-20 (Q15a). |
| req-qualys-file-import-5 | Script Stays Read-Only | Proposed | An execution test runs the script with a recording `curl` stub first on `PATH` and canned responses, and fails if any invocation names a host other than the configured one, a path not on the transport's allowlist, a method other than GET, `-k`/`--insecure`, `-L`/`--location`, or a credential on the command line; a source check fails on more than one `curl` call, `eval`, or a URL not built from the parsed host. | Execution-level, not only a text scan. |

### FIPS Posture
----
RID: `req-qualys-fips`

Status: `In Development`

What the plugin declares about its cryptography.

#### Implementation

The client is `requests`, which reaches TLS through Python's `ssl` module and the system OpenSSL. `defusedxml` is pure Python. No dependency bundles its own OpenSSL. `[fips]` declares `status = "compatible"`, a declaration that `validate_plugin`'s crypto-providers report checks.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-qualys-fips-1 | Declared And Checked | Proposed | The manifest declares `[fips] status = "compatible"`, and the crypto-providers report finds no bundled OpenSSL in the plugin's closure. | |

### Chunked Write
----
RID: `req-qualys-chunked-write`

Status: `In Development`

How a run reaches the grid. Core takes one advisory lock for every natural key of every node and edge a batch writes, all held until the batch commits, and Postgres keeps those locks in one shared table of about `max_locks_per_transaction × max_connections` slots. A run written as one batch therefore fails once it names more keys than the table holds: near 1,300 detections at Postgres's defaults, at about five keys a detection. The field test met exactly that (unified-systems-com/qualys-tap#71, unified-systems-com/tap#1348). So a run is written as several batches, each its own transaction (George, 2026-11-23, Q36b). This is `WORKAROUND(unified-systems-com/tap#1348)` until core offers a chunked submit.

#### Implementation

`decompose.documents` turns one run's nodes and edges into GRIFT documents of one batch each, in this order:

1. **Opening:** the run with `finished_at` null, naming its subscription by key. The subscription itself is written here only when the grid does not hold it yet (with no watermark, last complete read or standing scope), so an opening never writes back a held watermark that could undo a newer seal.
2. **Shared records:** vulnerability records and packages, then the QIDs, because later batches name them by key.
3. **Body:** every other node, in groups joined by batch-local refs. A ref means something only inside its batch, so a group is never split: a host, its detections, its neutral findings and their edges land together, and so do a tag and its children. Groups are packed into batches of at most `CHUNK_KEYS` (2,000) nodes plus edges, about one lock each. A single group bigger than that is written alone, over the bound. An edge that names the subscription by ref names it by key instead.
4. **Seal:** the subscription with its new watermark and last complete read, every withdrawn host (and tag) with any edge naming it by ref, and the finished run.

Each authority claim rides with the batch that holds its anchor, whose edges are the claim's asserted set. A claim whose anchor no batch holds is sent partial, so it proposes nothing.

A batch the grid refuses stops the write: the collector's abort default raises, and the file load refuses with the batch's number. What committed stays, since each batch holds true observations. The seal, the only batch that moves the watermark, records a complete read or withdraws anything, is never written, so the run's record keeps `finished_at` null and the next run plans from the old watermark.

`hold_subscription` is a session-level advisory lock, taken before the grid reads and released after the last batch, so a file load and a live run of one subscription still never interleave. An unlock that cannot be sent closes the connection, which releases the lock, because a persistent connection would otherwise hold it for its whole life. Its known gaps (a lock lost silently with a dropped connection, and no PgBouncer transaction mode) are unified-systems-com/qualys-tap#73, a lease row with a fencing token.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-qualys-chunked-write-1 | Every Record Once, No Ref Across Batches | Proposed | Across the body batches every node and edge of the run appears exactly once, every ref an edge names is a node of its own batch, and a run written in small parts lands the same hosts and detections as one batch. | `test_qualys_chunked_write.py::TestTheParts`, `TestTheCollectorWritesInParts`. |
| req-qualys-chunked-write-2 | Bounded Batches | Proposed | No body batch holds more than `CHUNK_KEYS` nodes plus edges unless it is a single ref-joined group. | `TestTheParts.test_each_body_batch_stays_inside_the_bound_unless_one_group_is_bigger`. |
| req-qualys-chunked-write-3 | Targets Before References, Seal Last | Proposed | The opening comes first, the seal last; every record an edge names by key lands in the same batch or an earlier one; each finding's claim rides with the finding. | `TestTheParts.test_opening_first_shared_records_next_seal_last`. |
| req-qualys-chunked-write-4 | A Failed Part Never Seals | Proposed | When a batch fails, the run's `finished_at` stays null and the subscription's watermark, last complete read and standing scope stay as held. | `TestTheCollectorWritesInParts.test_a_part_that_fails_keeps_what_landed_and_never_seals`. |

### AWS Integration
----
RID: `req-qualys-aws`

Status: `In Development`

Qualys's host detection reports what AWS's instance metadata says about each EC2 host it tracks. With the envelope's `integrations.aws` set true and `aws_core` installed, a run mints the aws_core records that metadata names, so the AWS side of the grid fills in from Qualys where aws_core has not read it yet (George, 2026-11-23, Q38; this reverses Q2a for the opt-in setting only). It is off by default, and inert without aws_core, which the run records as `AWS_CORE_ABSENT`.

#### Implementation

`tap_plugin/qualys/aws_mint.py` reads each host Qualys reports as provider `AWS`, service `EC2`, with an `i-` `CLOUD_RESOURCE_ID`. It uses the `METADATA/EC2` attribute names a live subscription returned (field report, 2026-11-23, Q38d): the instance identity document under `latest/dynamic/instance-identity/document/`, a few `latest/meta-data/` paths, and flat EC2 API names. It also reads the host's `CLOUD_PROVIDER_TAGS`. From these it derives:

- the **EC2 instance**: `instance_id`; `ec2_type` (`instanceType`); `ami_id` (`imageId`); `private_ip` (`privateIp`, or `local-ipv4`); `public_ip` (`public-ipv4`); `state` (`instanceState`); and `tags` as aws_core's `{Key: Value}` map;
- the **VPC** (`vpcId`) and the **subnet** (`subnetId`, its `availability_zone` from `availabilityZone`), with `PARTITIONED_INTO_SUBNET__aws_core`;
- each **security group** (`groupId`), named by `groupName` only when exactly one of each is reported, with `RESIDES_IN_VPC__aws_core`;
- the **account** (`accountId`, else `ownerId`, twelve digits), with the instance's `BELONGS_TO_ACCOUNT__aws_core`;
- the **region**, and the **account-region**, which `HOSTS_EC2_INSTANCE__aws_core` and `BELONGS_TO_ACCOUNT__aws_core`.

Qualys returns no network-interface id and no availability-zone id, so neither an interface nor a zone node is minted. A value of the wrong shape, or one naming more than one id where one is expected, is left out, never guessed; an empty value is not written. A VPC, subnet or security group gets no account or region edge, because the metadata names the instance's account, and a shared VPC or subnet belongs to another one. aws_core defines no edge from an instance to a subnet or security group, so that relation is not written until it does (Q39).

Every attribute the read returns is kept on the Qualys host, whether or not it is minted. `ec2_metadata` holds each name's `VALUE`, and `ec2_metadata_status` holds its `LAST_STATUS`, `LAST_SUCCESS_DATE`, `LAST_ERROR_DATE` and `LAST_ERROR`, all as returned. These three dates and the error are optional in the DTD, so consuming them can refuse no page. Names vary by host and are kept as sent, including the doubled `latest/meta-data/latest/meta-data/ami-launch-index`.

**Create if absent.** A GRIFT node write replaces the whole node, so writing what Qualys knows over what aws_core read would wipe aws_core's values. Each wanted record is looked up by its aws_core natural key. Only an absent one is created, and a held one is never written. An edge is written only when at least one of its ends was minted by this run; an edge between two held nodes is aws_core's to write. The check and the write are two steps, so aws_core can create the same record between them, and this write then replaces it: `WORKAROUND(unified-systems-com/tap#1071)`, until core has an insert-only write. When aws_core next reads that resource, its own values win. The minted records are shared records of the chunked write (`req-qualys-chunked-write`), so they land before the hosts whose `TRACKS_EC2_INSTANCE__qualys` names an instance by key.

The metadata paths are AWS's documented ones. Qualys's sample attribute (`latest/dynamic/instance-identity/document/region`) follows that scheme, but the full set Qualys returns is unconfirmed until a field host's attribute names are checked (Q38d). A path spelled otherwise leaves its field unminted, never wrong.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-qualys-aws-1 | Every Reported Record, aws_core's Edges | Proposed | With the integration on, a host's reported instance, VPC, subnet, security groups, account, region and account-region are minted with the fields reported and the edges above; its AWS tags land in the instance's `tags`; the host links to the instance; and every attribute's value and status are kept on the host. | `test_qualys_aws.py::TestMinting`, synthetic values under the field's names. |
| req-qualys-aws-2 | Never Rewrites What aws_core Holds | Proposed | A node aws_core holds keeps every field as it was; the run counts it as held. | `TestMinting.test_a_node_aws_core_holds_is_never_rewritten`. |
| req-qualys-aws-3 | Off By Default, Inert Without aws_core | Proposed | With the setting absent nothing is minted, though the host's cloud tags are still read; without aws_core nothing is minted. | `TestMinting.test_off_by_default_mints_nothing`, `test_without_aws_core_it_mints_nothing`. |

### Event Time
----
RID: `req-qualys-event-time`

Status: `In Development`

How this plugin's types meet core's event time (`req-grid-entity-event-time` in `tap_grid/specs/spec-grid-entity.md`, tap 0.4.6). Core derives `event_start`, `event_end`, `event_precision` and the time dimension (`tap.time` from tap 0.4.7) from a field a model names; this plugin only names the field. Event time needs `requires_tap >= 0.4.6`; the floor is `>= 0.4.8`, the release the field test runs, so CI tests at exactly that core.

#### Implementation

Qualys returns its times as `YYYY-MM-DDTHH:MM:SSZ` text, one of the FHIR forms core's reader accepts, so the declared fields are the typed fields as returned and the collector converts nothing.

| Type | Declaration | Why |
| --- | --- | --- |
| Detection | `Moment(first_found_datetime, first_seen)` | A finding is declared at its creation (core rule 13). Not an interval ending at `LAST_FIXED_DATETIME`: Qualys keeps that value when a fixed detection reopens, so the span would read closed while the detection is active again. |
| QID | `Moment(published_datetime, published)` | When Qualys published the record. `LAST_SERVICE_MODIFICATION_DATETIME` is Qualys editing its own record and is not declared (core rule 13). |
| Host | `NO_EVENT_TIME` | Its times are last-scan times, which are last-seen times and stay typed fields (core rule 14). The read carries no time for when the host came to exist. |
| Tag | `Moment(created_datetime, created)` | When Qualys records the tag was made. `modified` is its last change, not an end, and stays a typed field. |
| Scan Run | `NO_EVENT_TIME` | A run is a collection and its times are the collector's own clock: collection time, never declared (core rule 13; `req-grid-entity-collection-time`). |
| Subscription | `NO_EVENT_TIME` | Configuration; its watermark and last complete read are set by this plugin's reads, not stated by Qualys. |

No edge type carries a time property, so none declares an event time; core's default for an edge type is none.

A value core cannot read is kept in the typed field as Qualys sent it and left off the spine (core rule 12). Qualys's own documented sample carries one, `2019-1108T06:37:29Z`.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-qualys-event-time-1 | Every Model Declares | Proposed | Every model declares the event time in the table above, and core's `declaration_problems` finds nothing wrong with any of them. | `TestDeclarations`. |
| req-qualys-event-time-2 | Derived From Qualys's Text | Proposed | After an import, a detection's spine holds its first found time and a QID's its published time, each at precision `second` with its kind as the `time` dimension; a row whose field is empty, and every type declaring none, holds nothing. | `TestDerivedFromQualysText`. |
| req-qualys-event-time-3 | Malformed Value Kept, Not Guessed | Proposed | A detection whose first found time is not a readable value keeps the text in its typed field and has no event time. | `TestDerivedFromQualysText.test_a_malformed_time_is_kept_as_sent_and_left_off_the_spine`, on Qualys's documented sample. |

### Asset Tags
----
RID: `req-qualys-tags`

Status: `In Development`

Every asset tag of the subscription on the grid, kept current as tags are renamed, re-parented and deleted, so later work can filter by tag name and resolve a name to its id from the grid (asked 2026-11-23; filtering is not part of this requirement). Qualys has one tagging system across its applications, the Asset Management and Tagging tags, which VMDR's host detection filters on and Global AssetView shows; that these are the same objects is inferred from Qualys's documentation and not yet confirmed by a read.

#### Implementation

When the envelope leaves `tags` on (`req-qualys-sources`), a live run ends with the tag search, `POST /qps/rest/2.0/search/am/tag` (`req-qualys-transport-8`). It asks for 100 tags a page, Qualys's documented default, and pages by tag id: each next page starts at the last id seen. Qualys does not document whether `startFromId` includes the id it names, so a tag already read is skipped and either reading gives every tag once. The list is **complete** only when a page says `hasMoreRecords` false. It is incomplete, with a `TRUNCATED` warning, when a page does not say, when a page that says more follow moves nothing forward, or when a page returns an unread tag below its start id, because the walk assumes id order and that tag means it may have skipped one. It is also incomplete when a page is not read (listed on the run as `tag page <n>`, `not read: <type>`), when the run's ceiling or the page ceiling stops it, and when a tag has no usable id. A response that is not `SUCCESS` is a page not read; only a code of the documented shape is named. A failed tag read never changes the detection read, its watermark or its withdrawals, and the collector records `TAGS_INCOMPLETE`.

Each tag is a `qualys__qualys_tag` node keyed by subscription and tag id, never by name, so a rename is the node's history. It holds Qualys's values as returned: `name`, `color`, `rule_type`, `rule_text`, `criticality_score`, `description`, `created_datetime`, `modified_datetime`, `parent_tag_id` and `child_tag_ids`. A field the response did not carry is null; a children list not returned is null, never "no children". Its dimension is `qualys.area: tagging`, and its event time is `Moment(created_datetime, created)`: when Qualys records the tag was made. `modified` is a last change, not an end, and stays a typed field.

`TAG_OF_SUBSCRIPTION__qualys` runs from each tag to its subscription. `LISTS_CHILD_TAG__qualys` runs from a tag to each child its children list names, when the list also holds that child. On a complete list whose every children list was returned, the run claims each tag's inbound child edges whole (`req-grid-reconcile-edge-authority`), so an edge to a parent Qualys no longer lists is proposed for removal; otherwise the claims say partial and propose nothing.

A tag a complete list does not contain is rewritten `withdrawn` with the run's id, every other field as held; it is unobserved, not deleted, and the next list that contains it makes it current again. An incomplete list withdraws nothing. A file run reads no tags and changes none.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-qualys-tags-1 | Every Tag As Returned | Proposed | After a run, every tag the list returned is a node with its fields as returned, an edge to its subscription, an edge to each listed child, `qualys.area: tagging`, and its creation as its event time; a children list not returned is null. | `test_qualys_tags.py::TestTagPage`, `TestTagsOnTheGrid`. Synthetic fixtures from the documented shape. |
| req-qualys-tags-2 | Complete Only At Qualys's Last Page | Proposed | The list is complete only when a page says no more follow; a page not read, a page that does not say, a page that moves nothing forward, a tag below its page's start and a tag with no usable id each leave it incomplete, and a failed tag read leaves the detection read untouched. | `TestTheWalk`, `TestTagsOnTheGrid.test_a_failed_tag_read_does_not_touch_the_detection_read`. |
| req-qualys-tags-3 | Keyed By Id | Proposed | A tag renamed in Qualys is the same node with its new name. | `TestTagsOnTheGrid.test_a_rename_is_the_same_node`. |
| req-qualys-tags-4 | Withdrawn Only By A Complete List | Proposed | A held tag a complete list lacks is rewritten `withdrawn` with the run's id; after an incomplete list no tag is withdrawn. | `TestTagsOnTheGrid.test_a_complete_list_withdraws_a_tag_it_lacks_and_an_incomplete_one_does_not`. |

### Source Switches
----
RID: `req-qualys-sources`

Status: `In Development`

Qualys is many services stacked on one another, and a subscription may want some of what this plugin reads and not the rest. The envelope's `sources` switches each kind of Qualys data on or off (asked 2026-11-23). All three are on by default, so an envelope that says nothing reads everything.

#### Implementation

- `detections`: the host detection walk, and with it the hosts, the detections, and everything derived from them (neutral findings, package links, EC2 links). Off, the run reads the probe only, because the probe is how the credential is checked; the run is `narrower`, so it withdraws no host and the watermark stays.
- `knowledgebase`: the knowledge-base read for the QIDs the detections name. Off, no QID is asked, so a QID the grid does not hold is written as a stub whose `kb_returned` is null (unobserved), and the neutral rules treat its CVE list as unknown, so no finding on that host is moved to resolved.
- `tags`: the tag search (`req-qualys-tags`). Off, no POST is sent and no tag is read or changed.

A source switched off is listed on every run in `scopes_not_read` as `{scope: <source>, reason: switched off}`, never as an empty answer, and the run's summary names it. An envelope with every source off is refused before any request.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-qualys-sources-1 | On By Default, Recorded When Off | Proposed | An envelope without `sources` reads all three; a source set false sends none of its requests and is listed on the run as switched off; every source off is refused. | `test_qualys_tags.py::TestSourceSwitches`. |
| req-qualys-sources-2 | Detections Off Changes No Host | Proposed | With detections off the run sends only the probe to host detection and none to the knowledge base, is `narrower`, leaves the watermark, and withdraws no host. | `TestSourceSwitches.test_detections_off_reads_the_probe_only_and_changes_no_host`. |
| req-qualys-sources-3 | Knowledge Base Off Leaves QIDs Unobserved | Proposed | With the knowledge base off no knowledge-base request is sent and a new QID's `kb_returned` is null. | `TestSourceSwitches.test_knowledgebase_off_leaves_new_qids_unobserved`. |

### v0 Non-Goals
----
RID: `req-qualys-nongoals`

Status: `Approved for Development`

What this plugin deliberately does not do, and who owns it instead.

#### Implementation

| Not done | Why | Owner or status |
| --- | --- | --- |
| Any write to Qualys: launching a scan, adding an asset or tag, editing a setting, ignoring or disabling a detection | Read-only actions only | Not built |
| Interpreting severity, scoring risk, or mapping detections to VDR factors | Policy, not collection | The VDR plugins |
| Creating or changing EC2 instances | `aws_core` reads the source of record | `aws_core`; `req-qualys-ec2-create` Backlog |
| Package and vulnerability semantics | Owned by the substrates | `computing_core`, `compliance_core` |
| Pages and panels | Backend only | A later spec |
| The session-login API and every `/api/2.0/` path | Past end of support or due to reach it, and the login is a POST | Not built |
| A client-side filter by AWS account | Qualys's detection API has no account filter; scoping is done in Qualys, with tags or asset groups that stand for accounts, on the Reader user and in the standing scope | Dropped (ruled 2026-11-20, Q11a) |

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-qualys-nongoals-1 | No Write Path | Proposed | No operation on the allowlist changes Qualys. | Same test as `req-qualys-transport-1`. |

## Model catalog

A design-time catalog, superseded by the manifest once the plugin ships.

| Model | Entity type | Category | Rationale |
| --- | --- | --- | --- |
| Subscription | `qualys__qualys_subscription` | Qualys-specific | One subscription, identified by its API host and an operator label. |
| Scan Run | `qualys__qualys_scan_run` | Qualys-specific | One collection, live or from a file, with the probe, filter, window, scopes not read and warnings. |
| Host | `qualys__qualys_host` | Qualys-specific | A machine as Qualys tracks it, by agent or by address; Qualys's view, linked to the EC2 instance. |
| Detection | `qualys__qualys_detection` | Qualys-specific | Qualys's assertion that a QID was found on a host, with its history and result text. |
| QID | `qualys__qualys_qid` | Qualys-specific | The knowledge-base record behind a QID; carries the CVE fan-out so detections do not. |
| Tag | `qualys__qualys_tag` | Qualys-specific | An asset tag of the subscription, keyed by Qualys's tag id so a rename is its history (`req-qualys-tags`). |

## Edge types

| Edge | From → To | Properties | Rationale |
| --- | --- | --- | --- |
| `RUN_OF_SUBSCRIPTION__qualys` | scan run → subscription | none | Which subscription a run read. |
| `DETECTED_ON_HOST__qualys` | detection → host | none | The host a detection concerns. |
| `TAG_OF_SUBSCRIPTION__qualys` | tag → subscription | none | Which subscription's tag search returned a tag. |
| `LISTS_CHILD_TAG__qualys` | tag → tag | none | Qualys lists the target in the source's children list; a complete list claims each child's parents whole. |
| `ABOUT_QID__qualys` | detection → QID | none | What the detection means. |
| `LAST_SEEN_IN_RUN__qualys` | host or detection → scan run | none | The run that last read it, moved each run. |
| `ABOUT_VULNERABILITY__qualys` | QID → `compliance_vulnerability` | none | One per CVE in the QID's list; drawn from the QID, never the detection. |
| `TRACKS_EC2_INSTANCE__qualys` | host → `aws_core__aws_ec2_instance` | `source_field` | Qualys's host is that instance, by exact id; the instance is never written. |
| `FOUND_IN_PACKAGE__qualys` | detection → `computing_core__package` | none | Only when a parser is sure. |
| `DETAILS_COMPLIANCE_FINDING__qualys` | detection → `compliance_finding` | none | Which Qualys detections stand behind a neutral finding. |
