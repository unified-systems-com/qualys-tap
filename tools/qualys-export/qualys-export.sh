#!/usr/bin/env bash
# Read-only export of Qualys VM host detections (API 6.0) and the matching KnowledgeBase
# entries (API 4.0) for the Qualys TAP plugin. Every request is a GET with TLS verification on.
# Needs: bash, curl, python3, and a Qualys user with the "API Access" permission.
# Usage: QUALYS_API=https://<your platform API host> ./qualys-export.sh ["<asset group title>"]; see README.md
# Scope (optional, at most one): QUALYS_AG_IDS, QUALYS_AG_TITLES, QUALYS_TAG_IDS or QUALYS_TAG_NAMES, each a
# comma-separated list; QUALYS_TAG_MATCH=any|all says whether a host needs any or all of the tags (default any).
# Output: qualys-export-<UTC time>.tgz in the current directory. It contains IPs, hostnames and
# AWS account ids: send it over the agreed secure channel, not email.
set -euo pipefail
umask 077   # everything this script writes is readable by you alone

API=${QUALYS_API:?set QUALYS_API to your platform API host, see https://www.qualys.com/platform-identification/}
# Parse the URL the way curl will, and keep only scheme://host[:port]. Userinfo ("x@host"), a path, a
# query or a fragment is refused: "https://qualysapi.qualys.com:443@evil.example" names evil.example to
# curl, so the host must come from a real parse, never from string trimming.
HOST=$(python3 -I - "$API" <<'PY'
import sys
from urllib.parse import urlsplit
u = urlsplit(sys.argv[1].strip())
ok = (u.scheme == "https" and u.hostname and "@" not in u.netloc and u.path in ("", "/")
      and not u.query and not u.fragment)
if not ok:
    sys.exit("QUALYS_API must be https://<host>[:<port>] with no user, path, query or fragment")
print(u.hostname.lower() + ("" if u.port in (None, 443) else f":{u.port}"))
PY
) || exit 1
API="https://$HOST"; HOST=${HOST%%:*}
# The password goes to whatever host QUALYS_API names, so refuse a host that is not a Qualys platform
# API host (see https://www.qualys.com/platform-identification/). A private-cloud deployment on its own
# host sets QUALYS_ALLOW_OTHER_HOST=1, deliberately.
if ! printf '%s' "$HOST" | grep -Eq '^qualysapi\.([a-z0-9-]+\.)*qualys(ksa)?\.(com|eu|in|ca|ae|co\.uk|com\.au)$'; then
  if [ "${QUALYS_ALLOW_OTHER_HOST:-}" != 1 ]; then
    echo "QUALYS_API host '$HOST' is not a Qualys platform API host; refusing to send your password there." >&2
    echo "For a private-cloud deployment on another host, set QUALYS_ALLOW_OTHER_HOST=1." >&2
    exit 1
  fi
  echo "warning: sending credentials to '$HOST', which is not a public Qualys platform host (QUALYS_ALLOW_OTHER_HOST=1)" >&2
fi
# The scope narrows which hosts Qualys returns, for example to the tags or asset groups that stand for
# particular AWS accounts. Validated here, before the password prompt; the result is the query suffix
# the detection read carries and the scope export.json records.
SCOPE_OUT=$(python3 -I - "${1:-}" <<'PY'
import json, os, re, sys
from urllib.parse import quote
given = {k: os.environ.get(k, "").strip() for k in ("QUALYS_AG_IDS", "QUALYS_AG_TITLES", "QUALYS_TAG_IDS", "QUALYS_TAG_NAMES")}
if sys.argv[1]:  # the positional asset-group title, kept from the first version of this script
    if given["QUALYS_AG_TITLES"]:
        sys.exit("give the asset-group title either as the argument or as QUALYS_AG_TITLES, not both")
    given["QUALYS_AG_TITLES"] = sys.argv[1]
set_ = {k: v for k, v in given.items() if v}
if len(set_) > 1:
    sys.exit("set at most one of QUALYS_AG_IDS, QUALYS_AG_TITLES, QUALYS_TAG_IDS, QUALYS_TAG_NAMES")
match = os.environ.get("QUALYS_TAG_MATCH", "any").strip() or "any"
if match not in ("any", "all"):
    sys.exit("QUALYS_TAG_MATCH must be any or all")
if not set_:
    print(json.dumps({"query": "", "scope": None})); sys.exit()
(name, raw), = set_.items()
values = [v.strip() for v in raw.split(",")]
if not all(values):
    sys.exit(f"{name} has an empty entry")
kind, is_ids = {"QUALYS_AG_IDS": ("asset_group_ids", True), "QUALYS_AG_TITLES": ("asset_group_titles", False),
                "QUALYS_TAG_IDS": ("tag_ids", True), "QUALYS_TAG_NAMES": ("tag_names", False)}[name]
if is_ids and not all(re.fullmatch(r"[0-9]+", v) for v in values):
    sys.exit(f"{name} must be comma-separated numeric ids")
joined = quote(",".join(values), safe=",")
if kind == "asset_group_ids":
    query = f"&ag_ids={joined}"
elif kind == "asset_group_titles":
    query = f"&ag_titles={joined}"
else:
    query = f"&use_tags=1&tag_set_by={'id' if is_ids else 'name'}&tag_include_selector={match}&tag_set_include={joined}"
scope = {"kind": kind, "values": values}
if kind.startswith("tag_"):
    scope["tag_match"] = match
print(json.dumps({"query": query, "scope": scope}))
PY
) || exit 1
SCOPE_QUERY=$(printf '%s' "$SCOPE_OUT" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["query"])')

read -rp 'Qualys username: ' QU
read -rsp 'Password: ' QP; echo

# Credentials go in a private curl config file, never on the command line (where ps can see
# them). Quotes and backslashes are escaped so any password works.
esc() { local s=${1//\\/\\\\}; printf '%s' "${s//\"/\\\"}"; }
CFG=$(mktemp); case "$CFG" in /*) ;; *) CFG="$PWD/$CFG" ;; esac   # absolute: the script changes directory later
chmod 600 "$CFG"; trap 'rm -f "$CFG"' EXIT
printf 'user = "%s:%s"\n' "$(esc "$QU")" "$(esc "$QP")" > "$CFG"; unset QP

OUT=qualys-export-$(date -u +%Y%m%dT%H%M%SZ); mkdir "$OUT"; cd "$OUT"

get() {  # $1=url $2=outfile. GET only, no redirects followed, waits out 409 throttling.
  local code w tries=0
  while :; do
    # -q must come first: it stops curl reading ~/.curlrc, which could otherwise turn off TLS
    # verification or follow redirects. The --no- options state the same thing explicitly.
    code=$(curl -q --no-insecure --no-location -sS --proto =https --config "$CFG" -H 'X-Requested-With: tap-qualys-export' \
           -D "$2.headers" -o "$2" -w '%{http_code}' "$1")
    # Drop any cookie Qualys sets, so no session token ends up in the archive.
    grep -iv '^set-cookie:' "$2.headers" > "$2.headers.tmp" || true; mv "$2.headers.tmp" "$2.headers"
    [ "$code" = 200 ] && return 0
    if [ "$code" = 409 ] && [ $((tries+=1)) -le 20 ]; then
      w=$(grep -i '^x-ratelimit-towait-sec:' "$2.headers" | tr -dc 0-9 || true)
      echo "throttled (409), waiting ${w:-60}s" >&2; sleep "${w:-60}"; continue
    fi
    echo "HTTP $code for ${1%%\?*} (see $2)" >&2; return 1
  done
}

# 1) Host detections: all four statuses, result text, ignored and disabled included, EC2 metadata.
URL="$API/api/6.0/fo/asset/host/vm/detection/?action=list&status=New,Active,Re-Opened,Fixed&show_results=1&show_reopened_info=1&include_ignored=1&include_disabled=1&show_asset_id=1&host_metadata=ec2&show_cloud_tags=1&show_qds=1&truncation_limit=1000"
URL="$URL$SCOPE_QUERY"
n=1
while [ -n "$URL" ]; do
  f=$(printf 'hld-%04d.xml' "$n"); get "$URL" "$f"
  URL=$(python3 -I -c 'import sys,xml.etree.ElementTree as E; u=E.parse(sys.argv[1]).find("RESPONSE/WARNING/URL"); print(u.text.strip() if u is not None and u.text else "")' "$f")
  case "$URL" in ""|"$API"/api/6.0/fo/asset/host/vm/detection/*) ;; *) echo "unexpected next-page URL, stopping" >&2; exit 1 ;; esac
  n=$((n+1))
done

# 2) KnowledgeBase entries for the QIDs seen, 500 per request.
python3 -I -c 'import glob,xml.etree.ElementTree as E; print("\n".join(sorted({q.text.strip() for f in glob.glob("hld-*.xml") for q in E.parse(f).iter("QID") if q.text}, key=int)))' > qids.txt
# A knowledge-base failure (often a 403: the API may need enabling by Qualys Support) does not stop
# the export: the detections are still worth sending, and export.json records that the KB is incomplete.
KB_COMPLETE=true
if [ -s qids.txt ]; then
  split -l 500 qids.txt qchunk-
  for c in qchunk-*; do
    # A chunk Qualys cuts short (RESPONSE/WARNING/URL) is not followed by its link: the QIDs it has not yet
    # returned are asked again by id, so every request is one this script built. Further pages are saved as
    # kb-<chunk>-02.xml, -03.xml, ... A page that returns none of what was asked stops the chunk incomplete.
    ids=$(paste -sd, "$c"); p=1; f="kb-${c#qchunk-}.xml"
    while :; do
      if ! get "$API/api/4.0/fo/knowledge_base/vuln/?action=list&details=All&show_disabled_flag=1&ids=$ids" "$f"; then
        KB_COMPLETE=false; rm -f "$f" "$f.headers"
        echo "knowledge-base read failed; continuing without it" >&2; break
      fi
      left=$(python3 -I -c '
import sys, xml.etree.ElementTree as E
root = E.parse(sys.argv[1]).getroot()
if root.find("RESPONSE/WARNING/URL") is None:
    sys.exit()  # whole: nothing more to ask
returned = {q.text.strip() for q in root.findall("RESPONSE/VULN_LIST/VULN/QID") if q.text}  # only the QID of each returned VULN, as the loader reads it
asked = sys.argv[2].split(",")
left = [q for q in asked if q not in returned]
print(",".join(left) if len(left) < len(asked) else "NO-PROGRESS")
' "$f" "$ids")
      [ -z "$left" ] && break
      if [ "$left" = NO-PROGRESS ] || [ "$p" -ge 50 ]; then
        KB_COMPLETE=false; echo "knowledge-base chunk ${c#qchunk-} was cut short and could not be finished" >&2; break
      fi
      p=$((p+1)); ids=$left; f=$(printf 'kb-%s-%02d.xml' "${c#qchunk-}" "$p")
    done
  done
  rm -f qchunk-*
else
  echo "no detections returned; skipping the KnowledgeBase read" >&2
fi

# 3) The DTDs, so the files can be validated against exactly what Qualys served. Locations are
# documented but unverified, so a failure here is not fatal.
get_optional() {  # like get, but on failure leaves nothing behind, so a saved error page never poses as a DTD
  get "$1" "$2" || { rm -f "$2" "$2.headers"; echo "not served: $2 (not an error)" >&2; }
}
get_optional "$API/api/6.0/fo/asset/host/vm/detection/dtd/output.dtd" hld-output.dtd
get_optional "$API/api/4.0/fo/knowledge_base/vuln/knowledge_base_vuln_list_output.dtd" kb.dtd

# 4) What this archive is: where it came from, when, and how it was asked for. The collector
# reads this to tell which subscription the files belong to. No credential is written.
python3 -I - "$API" "$SCOPE_OUT" "$KB_COMPLETE" <<'PY'
import datetime, glob, json, sys
json.dump({
    "description": "Qualys TAP export manifest: provenance of the files in this archive",
    "script_version": 3,
    "api_host": sys.argv[1],
    "scope": json.loads(sys.argv[2])["scope"],
    "created_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "detection_api": "6.0",
    "knowledgebase_api": "4.0",
    "detection_pages": len(glob.glob("hld-*.xml")),
    "knowledgebase_files": len(glob.glob("kb-*.xml")),
    "knowledgebase_complete": sys.argv[3] == "true",
}, open("export.json", "w"), indent=2)
PY

cd ..; tar czf "$OUT.tgz" "$OUT"
echo "Done. Send $OUT.tgz over the agreed secure channel."
