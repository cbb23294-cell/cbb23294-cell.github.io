#!/usr/bin/env python3
"""Pull newer published JSON faces into a local web root using curl.

Usage: python3 healer.py /srv/pub
Only Python's standard library is used; curl must be installed.
Each face produces exactly one JSON log line. Exit 1 means at least one face
failed; the remaining faces are still processed. Exit 2 means invalid arguments.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile


BASE_URL = "https://cbb23294-cell.github.io/pub"
FACES = (
    "ai-quota-catalog",
    "ai-quota-findings",
    "freebies-scan",
    "panel-daily",
    "panel-light",
    "token-perks",
    "vps-deals",
    "vps-server-status",
    "pool-state",
    "team-status",
)
# These are document-level freshness fields, not timestamps inside individual
# findings or servers. The first present field is authoritative. The live
# findings face uses generated_at; the others use generatedAt or collectedAt.
TIMESTAMP_FIELDS = (
    "collectedAt", "updatedAt", "generatedAt",
    "collected_at", "updated_at", "generated_at",
)


class FaceError(Exception):
    """A fetch or document validation failed without changing the destination."""


def freshness(payload):
    """Return (original timestamp text, UTC datetime) from a JSON object.

    Require an explicit timezone: guessing the zone could cause a rollback.
    Reject ambiguous or missing freshness instead of comparing file mtimes.
    """
    try:
        document = json.loads(payload)
    except (ValueError, UnicodeError) as exc:
        raise FaceError("invalid JSON: {}".format(exc)) from exc
    if not isinstance(document, dict):
        raise FaceError("JSON document must be an object")
    for field in TIMESTAMP_FIELDS:
        if field not in document:
            continue
        text = document[field]
        if not isinstance(text, str) or not text.strip():
            raise FaceError("{} must be an ISO-8601 timestamp string".format(field))
        value = text.strip()
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        try:
            timestamp = datetime.fromisoformat(value)
            if timestamp.utcoffset() is None:
                raise ValueError("timezone is required")
            timestamp = timestamp.astimezone(timezone.utc)
        except (ValueError, OverflowError) as exc:
            raise FaceError("invalid {} timestamp: {}".format(field, exc)) from exc
        return text, timestamp
    raise FaceError("missing freshness field ({})".format(", ".join(TIMESTAMP_FIELDS)))


def fetch(face):
    """Use curl directly, including bounded retries and HTTPS-only redirects."""
    command = [
        "curl", "-q", "--fail", "--silent", "--show-error", "--location",
        "--proto", "=https", "--proto-redir", "=https",
        "--connect-timeout", "5", "--max-time", "15",
        "--retry", "1", "--retry-delay", "1", "--retry-max-time", "30",
        "{}/{}.json".format(BASE_URL, face),
    ]
    try:
        result = subprocess.run(command, capture_output=True, timeout=35, check=False)
    except subprocess.TimeoutExpired as exc:
        raise FaceError("curl exceeded the 35-second total deadline") from exc
    except OSError as exc:
        raise FaceError("cannot run curl: {}".format(exc)) from exc
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise FaceError("curl exit {}: {}".format(result.returncode, detail[:1000]))
    return result.stdout


def atomic_write(destination, payload):
    """Flush a same-directory temporary file, then atomically replace the face.

    Keep an existing file's permission bits; new files are web-readable (0644).
    Any failure before rename leaves the previous face in place.
    """
    try:
        mode = stat.S_IMODE(destination.stat().st_mode)
    except FileNotFoundError:
        mode = 0o644
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=str(destination.parent),
            prefix=".{}-".format(destination.name), suffix=".tmp", delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fchmod(handle.fileno(), mode)
            os.fsync(handle.fileno())
        os.replace(str(temporary), str(destination))
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink()


def heal_face(face, target):
    """Return one log record; never remove the destination on any error."""
    destination = target / (face + ".json")
    record = {"face": face, "old_ts": None, "new_ts": None, "action": "fetch-failed"}
    old_instant = None
    local_error = None
    try:
        try:
            previous = destination.read_bytes()
        except FileNotFoundError:
            previous = None
        if previous is not None:
            record["old_ts"], old_instant = freshness(previous)
    except (OSError, FaceError) as exc:
        local_error = "local copy: {}".format(exc)

    # Fetch even if the local copy is invalid, so each face is attempted and
    # the report can include the source's timestamp. An unreadable or invalid
    # existing local timestamp is never guessed or silently overwritten.
    try:
        payload = fetch(face)
        record["new_ts"], new_instant = freshness(payload)
        if local_error is not None:
            raise FaceError(local_error)
        if old_instant is None or new_instant > old_instant:
            atomic_write(destination, payload)
            record["action"] = "updated"
        else:
            record["action"] = "kept"
    except (OSError, FaceError) as exc:
        record["error"] = str(exc)
        if local_error is not None and local_error != str(exc):
            record["error"] += "; " + local_error
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", type=Path, help="existing local web root, e.g. /srv/pub")
    args = parser.parse_args(argv)
    failed = False
    for face in FACES:
        record = heal_face(face, args.target)
        print(json.dumps(record, ensure_ascii=True), flush=True)
        failed = failed or record["action"] == "fetch-failed"
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
