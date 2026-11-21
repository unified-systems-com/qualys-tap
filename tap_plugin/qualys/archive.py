"""Open an export archive from ``tools/qualys-export`` without trusting it (req-qualys-file-import-2, -3).

The archive is a gzip tar, read once from disk into one snapshot (bounded by ``MAX_ARCHIVE_BYTES``) that is
hashed, measured and unpacked, so the bytes recorded and the bytes loaded are the same bytes. Nothing is
extracted to disk, and only the members the loader reads are kept in memory; anything else is skipped unread. Only regular files and directories are accepted, every path must sit under one
top-level directory with no absolute part and no ``..``, and the limits below hold before anything is read:
member size, member count, total expanded size and compression ratio. The manifest (``export.json``) is
checked against the plugin's API versions and against the archive's own members. It is otherwise trusted for
nothing: its ``created_at`` is recorded and never gates state.
"""

import hashlib
import io
import json
import re
import tarfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from tap_plugin.qualys.parse import MAX_PAGE_BYTES

MAX_MEMBERS = 10_000
#: The compressed archive read from disk, and everything it may expand to.
MAX_ARCHIVE_BYTES = 512 << 20
MAX_TOTAL_BYTES = 1 << 30
MAX_RATIO = 100
DETECTION_API = "6.0"
KNOWLEDGEBASE_API = "4.0"
SCRIPT_VERSION = 3
#: Versions the loader reads. Version 3 asks again, by id, for the QIDs a cut-short knowledge-base response did
#: not return, saving each further page as kb-<chunk>-NN.xml (unified-systems-com/qualys-tap#16); version 2
#: wrote one page per chunk and followed nothing.
SCRIPT_VERSIONS = (2, 3)

_DETECTION_PAGE = re.compile(r"hld-(\d{4})\.xml")
_KB_FILE = re.compile(r"kb-([a-z]{2,})(?:-(\d{2}))?\.xml")
_SCOPE_KINDS = {"asset_group_ids", "asset_group_titles", "tag_ids", "tag_names"}


class ArchiveRefused(ValueError):
    """An archive the loader will not read; the message names what was wrong, never a value from inside it."""


@dataclass
class Archive:
    """What an accepted archive holds, in memory."""

    sha256: str
    manifest: dict[str, Any]
    detection_pages: list[bytes] = field(default_factory=list)
    knowledgebase_files: list[bytes] = field(default_factory=list)
    #: Parallel to ``knowledgebase_files``: whether each is the last page of its chunk, the only page whose
    #: next-page link means a QID went unobserved.
    knowledgebase_ends: list[bool] = field(default_factory=list)
    qids_asked: set[str] = field(default_factory=set)
    dtds: dict[str, str] = field(default_factory=dict)


def _check_members(tar: tarfile.TarFile, compressed_size: int) -> tuple[str, list[tarfile.TarInfo]]:
    members = []
    total = 0
    top: str | None = None
    seen: set[str] = set()
    for count, info in enumerate(tar, start=1):
        if count > MAX_MEMBERS:
            raise ArchiveRefused(f"more than {MAX_MEMBERS} members")
        if not (info.isfile() or info.isdir()):
            raise ArchiveRefused("a member is not a regular file or directory (a link, device or FIFO)")
        path = PurePosixPath(info.name)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise ArchiveRefused("a member path is absolute or climbs out of the archive")
        if top is None:
            top = path.parts[0]
        elif path.parts[0] != top:
            raise ArchiveRefused("members are not under one top-level directory")
        name = path.as_posix().rstrip("/")
        if name in seen:
            raise ArchiveRefused("a member name appears twice, so which copy would be read is ambiguous")
        seen.add(name)
        if info.isfile():
            if info.size > MAX_PAGE_BYTES:
                raise ArchiveRefused(f"a member is larger than {MAX_PAGE_BYTES} bytes")
            total += info.size
            if total > MAX_TOTAL_BYTES:
                raise ArchiveRefused(f"expands to more than {MAX_TOTAL_BYTES} bytes")
            if compressed_size and total > MAX_RATIO * compressed_size:
                raise ArchiveRefused(f"expands more than {MAX_RATIO} to 1")
            members.append(info)
    if top is None:
        raise ArchiveRefused("the archive is empty")
    return top, members


def _manifest(raw: bytes) -> dict[str, Any]:
    try:
        manifest = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ArchiveRefused("export.json is not JSON") from exc
    if not isinstance(manifest, dict):
        raise ArchiveRefused("export.json is not an object")
    if manifest.get("script_version") not in SCRIPT_VERSIONS:
        raise ArchiveRefused(f"export.json script_version is not one of {', '.join(map(str, SCRIPT_VERSIONS))}")
    if manifest.get("detection_api") != DETECTION_API or manifest.get("knowledgebase_api") != KNOWLEDGEBASE_API:
        raise ArchiveRefused(f"the archive was not made with detection API {DETECTION_API} and knowledge base API {KNOWLEDGEBASE_API}")
    if not isinstance(manifest.get("api_host"), str):
        raise ArchiveRefused("export.json names no api_host")
    scope = manifest.get("scope")
    if scope is not None:
        if not (isinstance(scope, dict) and scope.get("kind") in _SCOPE_KINDS and isinstance(scope.get("values"), list) and scope["values"]):
            raise ArchiveRefused("export.json scope is not {kind, values}")
        if scope["kind"].startswith("tag_") and scope.get("tag_match") not in ("any", "all"):
            raise ArchiveRefused("export.json tag scope has no tag_match")
    for name in ("detection_pages", "knowledgebase_files"):
        if not isinstance(manifest.get(name), int) or manifest[name] < 0:
            raise ArchiveRefused(f"export.json {name} is not a count")
    if not isinstance(manifest.get("knowledgebase_complete"), bool):
        raise ArchiveRefused("export.json knowledgebase_complete is not a boolean")
    return manifest


def _wanted(name: str) -> bool:
    """The members the loader reads; the export script's headers files and anything else are skipped unread."""
    return name in ("export.json", "qids.txt", "hld-output.dtd", "kb.dtd") or bool(_DETECTION_PAGE.fullmatch(name) or _KB_FILE.fullmatch(name))


def read_snapshot(path: Path) -> bytes:
    """The archive's bytes, read once and bounded: what is hashed is what is loaded."""
    with path.open("rb") as handle:
        data = handle.read(MAX_ARCHIVE_BYTES + 1)
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ArchiveRefused(f"the archive is larger than {MAX_ARCHIVE_BYTES} bytes")
    return data


def open_archive(data: bytes) -> Archive:
    """Check and read an export archive from its snapshot; refuse it whole if anything about it is off."""
    sha256 = hashlib.sha256(data).hexdigest()
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            top, members = _check_members(tar, len(data))
            files: dict[str, bytes] = {}
            for info in members:
                name = PurePosixPath(info.name).relative_to(top).as_posix()
                if "/" in name:
                    raise ArchiveRefused("the archive has a nested directory the export script does not write")
                if not _wanted(name):
                    continue
                handle = tar.extractfile(info)
                if handle is None:
                    raise ArchiveRefused("a member could not be read")
                files[name] = handle.read(MAX_PAGE_BYTES + 1)
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise ArchiveRefused(f"not a readable gzip tar archive ({type(exc).__name__})") from exc

    if "export.json" not in files:
        raise ArchiveRefused("the archive has no export.json")
    manifest = _manifest(files["export.json"])
    pages = sorted((int(m.group(1)), name) for name in files if (m := _DETECTION_PAGE.fullmatch(name)))
    chunks: dict[str, list[tuple[int, str]]] = {}
    for name in files:
        if m := _KB_FILE.fullmatch(name):
            chunks.setdefault(m.group(1), []).append((int(m.group(2) or 1), name))
    kb: list[str] = []
    ends: list[bool] = []
    for chunk in sorted(chunks):
        numbered = sorted(chunks[chunk])
        if [n for n, _ in numbered] != list(range(1, len(numbered) + 1)):
            raise ArchiveRefused("knowledge-base pages of a chunk are not numbered 1..n")
        if len(numbered) > 1 and manifest["script_version"] < 3:
            raise ArchiveRefused("a version 2 archive holds a knowledge-base continuation page")
        kb.extend(name for _, name in numbered)
        ends.extend(i == len(numbered) - 1 for i in range(len(numbered)))
    if [n for n, _ in pages] != list(range(1, len(pages) + 1)):
        raise ArchiveRefused("detection pages are not numbered 1..n")
    if len(pages) != manifest["detection_pages"] or len(kb) != manifest["knowledgebase_files"]:
        raise ArchiveRefused("export.json counts do not match the archive's members")
    if not pages:
        raise ArchiveRefused("the archive holds no detection page")
    qids = set()
    if "qids.txt" in files:
        try:
            text = files["qids.txt"].decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ArchiveRefused("qids.txt is not UTF-8") from exc
        for line in text.splitlines():
            if line.strip():
                if not line.strip().isdigit():
                    raise ArchiveRefused("qids.txt holds something other than QIDs")
                qids.add(line.strip())
    dtds = {name: files[name].decode("utf-8", errors="replace") for name in ("hld-output.dtd", "kb.dtd") if name in files}
    return Archive(
        sha256=sha256,
        manifest=manifest,
        detection_pages=[files[name] for _, name in pages],
        knowledgebase_files=[files[name] for name in kb],
        knowledgebase_ends=ends,
        qids_asked=qids,
        dtds=dtds,
    )
