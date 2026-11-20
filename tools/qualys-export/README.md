# Qualys export script

`qualys-export.sh` saves a read-only copy of a Qualys subscription's VM host detections and the knowledge-base entries behind them. Someone with access to Qualys runs it and sends us the archive. We then load the archive onto the grid with the Qualys TAP collector, so nobody else needs access to Qualys itself.

The script only reads. Every request is an HTTP GET with TLS certificate verification on. It changes nothing in Qualys: it launches no scan, adds no asset and edits no setting.

## What you need

- A Linux or macOS shell with `bash`, `curl` and `python3`.
- A Qualys user with the **API Access** permission. A **Reader** role is enough. Ideally the user is scoped to the asset groups or tags that hold the AWS EC2 hosts, so the export holds nothing else.
- Your platform's **API host**, which depends on where your subscription lives. Look it up at <https://www.qualys.com/platform-identification/>. For example, US platform 2 is `https://qualysapi.qg2.apps.qualys.com`.

## Running it

```bash
QUALYS_API=https://qualysapi.qg2.apps.qualys.com ./qualys-export.sh
```

To export only one asset group, give its title as the argument:

```bash
QUALYS_API=https://qualysapi.qg2.apps.qualys.com ./qualys-export.sh "AWS Production"
```

Every file the script writes, including the final archive, is readable by your user alone. It ignores any personal curl settings (`~/.curlrc`), so nothing on your machine can turn TLS verification off or make it follow a redirect.

The script asks for your Qualys username and password. The password is never put on the command line, where other users of the machine could see it. It goes into a private temporary file, which is deleted when the script exits.

A large subscription can take a while. Qualys limits how many API calls a subscription may make, and when the script hits that limit it waits the time Qualys asks for and carries on. You will see `throttled (409), waiting …` when that happens.

## What it produces

One archive in the current directory, `qualys-export-<UTC time>.tgz`, holding:

| File | Contents |
| --- | --- |
| `hld-0001.xml`, `hld-0002.xml`, … | Host detections from the Host List Detection API v6.0, one file per page of up to 1,000 hosts. Every status (New, Active, Re-Opened, Fixed) is included, along with ignored and disabled detections, the result text of each detection, and each host's EC2 metadata and cloud tags. |
| `kb-*.xml` | Knowledge-base entries (API v4.0) for every QID that appears in the detections, with full details, in batches of 500. |
| `qids.txt` | The QIDs found in the detections. |
| `export.json` | Where and when the export was made: the API host, the asset group if one was given, the time, the API versions and the file counts. No credential. |
| `*.headers` | The response headers of each request, kept for Qualys's rate-limit and warning headers. Any cookie Qualys sets is removed before it is saved, so they hold no session token. |
| `hld-output.dtd`, `kb.dtd` | The document type definitions Qualys served, so we can check the files against exactly what your subscription returns. Missing if Qualys did not serve them, which is not an error. |

**Treat the archive as sensitive.** It holds IP addresses, hostnames, AWS account ids and instance ids, and the vulnerabilities on each host. Send it over the secure channel we agreed, never by email or a public link.

## If something goes wrong

- **`HTTP 401`**: the username or password is wrong, or the user lacks the API Access permission.
- **`knowledge-base read failed; continuing without it`**: often an `HTTP 403`, because the knowledge-base API may need to be enabled for your subscription by Qualys Support. The script carries on, still produces the archive with the detections in it, and records `"knowledgebase_complete": false` in `export.json`. Send it, and tell us.
- **`is not a Qualys platform API host`**: the script only sends your password to a Qualys platform API host, such as `qualysapi.qg2.apps.qualys.com`. Check the host against the platform identification page. A private-cloud deployment on its own host can set `QUALYS_ALLOW_OTHER_HOST=1`.
- **An error mentioning `/api/6.0/`**: your subscription may not offer version 6.0 yet. Tell us, and we will send a version for 5.0.
- **`unexpected next-page URL, stopping`**: Qualys returned a next-page link that pointed somewhere other than the detection API. The script refuses to follow it. Send us the files written so far, which are in the `qualys-export-<time>` directory.

When you send the archive, please also tell us your subscription's API tier if you know it, and whether you saw any `throttled (409)` lines.

## No API access?

If your user cannot be given API Access, a **Host Based Findings** report exported as XML from the Qualys web console carries most of the same data. It does not carry Qualys's unique vulnerability id, the CVSS vector strings or a per-detection ignored or disabled flag. Ask us for the report settings. The collector does not read that format yet.
