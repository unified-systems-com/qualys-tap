#!/usr/bin/env bash
# Read-only export of Qualys VM host detections (API 6.0) and the matching KnowledgeBase
# entries (API 4.0) for the Qualys TAP plugin. Every request is a GET with TLS verification on.
# Needs: bash, curl, python3, and a Qualys user with the "API Access" permission.
# Usage: QUALYS_API=https://<your platform API host> ./qualys-export.sh ["<asset group title>"]; see README.md
# Output: qualys-export-<UTC time>.tgz in the current directory. It contains IPs, hostnames and
# AWS account ids: send it over the agreed secure channel, not email.
set -euo pipefail

API=${QUALYS_API:?set QUALYS_API to your platform API host, see https://www.qualys.com/platform-identification/}
API=${API%/}
case "$API" in https://*) ;; *) echo "QUALYS_API must start with https://" >&2; exit 1 ;; esac
AG=${1:-}

read -rp 'Qualys username: ' QU
read -rsp 'Password: ' QP; echo

# Credentials go in a private curl config file, never on the command line (where ps can see
# them). Quotes and backslashes are escaped so any password works.
esc() { local s=${1//\\/\\\\}; printf '%s' "${s//\"/\\\"}"; }
CFG=$(mktemp); chmod 600 "$CFG"; trap 'rm -f "$CFG"' EXIT
printf 'user = "%s:%s"\n' "$(esc "$QU")" "$(esc "$QP")" > "$CFG"; unset QP

OUT=qualys-export-$(date -u +%Y%m%dT%H%M%SZ); mkdir "$OUT"; cd "$OUT"

get() {  # $1=url $2=outfile. GET only, no redirects followed, waits out 409 throttling.
  local code w tries=0
  while :; do
    code=$(curl -sS --proto =https --config "$CFG" -H 'X-Requested-With: tap-qualys-export' \
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
[ -n "$AG" ] && URL="$URL&ag_titles=$(python3 -I -c 'import sys,urllib.parse as u; print(u.quote(sys.argv[1]))' "$AG")"
n=1
while [ -n "$URL" ]; do
  f=$(printf 'hld-%04d.xml' "$n"); get "$URL" "$f"
  URL=$(python3 -I -c 'import sys,xml.etree.ElementTree as E; u=E.parse(sys.argv[1]).find("RESPONSE/WARNING/URL"); print(u.text.strip() if u is not None and u.text else "")' "$f")
  case "$URL" in ""|"$API"/api/6.0/fo/asset/host/vm/detection/*) ;; *) echo "unexpected next-page URL, stopping" >&2; exit 1 ;; esac
  n=$((n+1))
done

# 2) KnowledgeBase entries for the QIDs seen, 500 per request.
python3 -I -c 'import glob,xml.etree.ElementTree as E; print("\n".join(sorted({q.text.strip() for f in glob.glob("hld-*.xml") for q in E.parse(f).iter("QID") if q.text}, key=int)))' > qids.txt
if [ -s qids.txt ]; then
  split -l 500 qids.txt qchunk-
  for c in qchunk-*; do
    get "$API/api/4.0/fo/knowledge_base/vuln/?action=list&details=All&show_disabled_flag=1&ids=$(paste -sd, "$c")" "kb-${c#qchunk-}.xml"
  done
  rm -f qchunk-*
else
  echo "no detections returned; skipping the KnowledgeBase read" >&2
fi

# 3) The DTDs, so the files can be validated against exactly what Qualys served. Locations are
# documented but unverified, so a failure here is not fatal.
get "$API/api/6.0/fo/asset/host/vm/detection/dtd/output.dtd" hld-output.dtd || true
get "$API/api/4.0/fo/knowledge_base/vuln/knowledge_base_vuln_list_output.dtd" kb.dtd || true

# 4) What this archive is: where it came from, when, and how it was asked for. The collector
# reads this to tell which subscription the files belong to. No credential is written.
python3 -I - "$API" "$AG" <<'PY'
import datetime, glob, json, sys
json.dump({
    "description": "Qualys TAP export manifest: provenance of the files in this archive",
    "script_version": 1,
    "api_host": sys.argv[1],
    "asset_group": sys.argv[2] or None,
    "created_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "detection_api": "6.0",
    "knowledgebase_api": "4.0",
    "detection_pages": len(glob.glob("hld-*.xml")),
    "knowledgebase_files": len(glob.glob("kb-*.xml")),
}, open("export.json", "w"), indent=2)
PY

cd ..; tar czf "$OUT.tgz" "$OUT"
echo "Done. Send $OUT.tgz over the agreed secure channel."
