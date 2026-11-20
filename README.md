# Qualys TAP

A read-only collector for Qualys VMDR, a plugin for [TAP](https://github.com/unified-systems-com/tap). It reads the host detections Qualys holds, from Cloud Agents and scanner appliances, and the QID knowledge base behind them. It lands them on the grid in Qualys's own shape, linked to the AWS EC2 instances they concern, the packages a parser reads from the result text, and the shared vulnerability records the VDR pages read.

**Read first:** [`specs/spec-qualys-v0.md`](specs/spec-qualys-v0.md), the specification. Every type, edge and rule here comes from it.

## What this plugin owns

| Type | What it is |
| --- | --- |
| `qualys__qualys_subscription` | One Qualys subscription: its platform API host and the operator's label for it |
| `qualys__qualys_scan_run` | One collection, live or from an export archive |
| `qualys__qualys_host` | A machine as Qualys tracks it, linked to its EC2 instance |
| `qualys__qualys_detection` | Qualys's assertion that a QID was found on a host |
| `qualys__qualys_qid` | The knowledge-base record behind a QID, carrying its CVE list |

It also writes `compliance_core`'s neutral finding, one per Qualys host and CVE, and creates a shared vulnerability record a CVE names when the grid holds none. It creates a `computing_core` package with its key fields only when a parser is sure of it and the grid holds none.

## What lives elsewhere

- **EC2 instances** belong to `aws_core`, which collects them from AWS. This plugin links to an instance by exact instance id and never writes one; `aws_core` is optional.
- **Severity, risk and VDR mapping** belong to the VDR plugins. Qualys's values are stored as returned.

## Two ways in

- **Live:** the collector reads a Qualys subscription with a Reader user that has API access only. It sends GET requests only.
- **From a file:** someone with Qualys access runs [`tools/qualys-export/`](tools/qualys-export/), a standalone read-only script, and the archive it produces is loaded onto the grid.

## A detection stays open until Qualys says Fixed

A detection resolves only when Qualys reports it Fixed. A detection that simply stops appearing never resolves, and neither does its neutral finding. That covers a host purged from Qualys, an ignored or disabled detection Qualys never re-tests, and a QID Qualys stops returning. This is deliberate (`req-qualys-states`), not a collector fault.

## Standing it up

Develop against a TAP session with this plugin checked out editable:

```bash
scripts/spawn-session.sh <label> --from 'git+https://github.com/unified-systems-com/qualys-tap@<tag>#ci' --dev-plugins qualys
```

The in-package `ci` record (`tap_plugin/qualys/boot/ci.boot.json`) installs exactly the plugins this one depends on: `computing_core`, `compliance_core` and `aws_core`. Run the tests in that stack with `pytest --pyargs tap_plugin.qualys`.

## Status

v0 is built without access to a Qualys subscription. Every field mapping comes from Qualys's documentation and is *documented*, not *observed*, until a recorded response or an export archive confirms it.

Licensed under the Apache License 2.0.
