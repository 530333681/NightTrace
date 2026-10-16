#!/usr/bin/env python3
"""
NightTrace - local web UI for reviewing Windows host artifacts.

Loads the ZIP produced by collector.ps1 and exposes two views:
  * Process Explorer
  * Persistence (Run/RunOnce keys, scheduled tasks, services)

Security posture
----------------
* read-only: the uploaded archive is extracted into a private temp folder and parsed;
* the archive is validated (path traversal, absolute paths, symlinks, size and
  entry-count limits) before anything is written to disk;
* the server binds to 127.0.0.1 by default and never sends data anywhere;
* no database, no external service, no background network activity.

Run:  python app.py    ->  http://127.0.0.1:5000
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import shutil
import sys
import tempfile
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, abort, jsonify, render_template, request

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
HOST = "127.0.0.1"
PORT = int(os.environ.get("NIGHTTRACE_PORT", "5000"))

MAX_UPLOAD_BYTES = 64 * 1024 * 1024          # compressed ZIP size limit
MAX_UNCOMPRESSED_BYTES = 512 * 1024 * 1024   # total expanded size limit
MAX_ENTRIES = 500                            # entry count limit
MAX_ENTRY_BYTES = 128 * 1024 * 1024          # single entry size limit
SESSION_TTL_SECONDS = 6 * 60 * 60            # drop sessions older than 6h
RAW_FILE_CHAR_LIMIT = 200_000                # truncate when returning a raw file

ALLOWED_SUFFIXES = {".json", ".csv", ".txt", ".log", ".md"}

# logical key -> (json filename, csv filename, description)
MODULE_FILES = {
    "processes": (
        "processes.json",
        "processes.csv",
        "process list with PID/PPID, image path and command line",
    ),
    "run_keys": (
        "persistence_run.json",
        "persistence_run.csv",
        "Run / RunOnce registry keys",
    ),
    "scheduled_tasks": (
        "persistence_scheduled_tasks.json",
        "persistence_scheduled_tasks.csv",
        "Windows scheduled tasks",
    ),
    "services": (
        "persistence_services.json",
        "persistence_services.csv",
        "Windows services",
    ),
    "system_info": ("system_info.json", None, "host and operating system information"),
    "meta": ("collection_meta.json", None, "collector metadata and module status"),
}

# ZIP members we are willing to extract. Anything else is ignored (not an error).
RECOGNISED_FILES = {
    name
    for pair in MODULE_FILES.values()
    for name in pair[:2]
    if name
}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES + (2 * 1024 * 1024)
app.config["JSON_SORT_KEYS"] = False

WORK_ROOT = Path(tempfile.gettempdir()) / "nighttrace_sessions"
WORK_ROOT.mkdir(parents=True, exist_ok=True)

SESSIONS: dict[str, dict] = {}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")


def cleanup_sessions() -> None:
    """Remove expired sessions and their temp folders."""
    cutoff = time.time() - SESSION_TTL_SECONDS
    for sid in list(SESSIONS):
        if SESSIONS[sid]["created_ts"] < cutoff:
            drop_session(sid)
    for child in WORK_ROOT.glob("nt_*"):
        try:
            if child.stat().st_mtime < cutoff:
                shutil.rmtree(child, ignore_errors=True)
        except OSError:
            pass


def drop_session(session_id: str) -> None:
    session = SESSIONS.pop(session_id, None)
    if session:
        shutil.rmtree(session["dir"], ignore_errors=True)


def is_unsafe_member(name: str) -> str | None:
    """Return a reason string when a ZIP member name must not be extracted."""
    if not name or name.strip() == "":
        return "empty entry name"
    normalised = name.replace("\\", "/")
    if normalised.startswith("/"):
        return "absolute path"
    if re.match(r"^[a-zA-Z]:", normalised):
        return "drive-letter path"
    if normalised.startswith("~"):
        return "home-relative path"
    parts = [p for p in normalised.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return "path traversal ('..')"
    if "\x00" in name:
        return "null byte in name"
    return None


def safe_target(dest_root: Path, member_name: str) -> Path:
    """Join and confirm the result stays inside dest_root."""
    rel = member_name.replace("\\", "/").lstrip("/")
    target = (dest_root / rel).resolve()
    root = dest_root.resolve()
    if root != target and root not in target.parents:
        raise ValueError("entry escapes extraction directory")
    return target


def extract_archive(zip_path: Path, dest_root: Path) -> tuple[list[str], list[str], list[str]]:
    """Extract recognised files safely.

    Returns (extracted, skipped, security_hits). `security_hits` lists members
    that were refused for a security reason rather than for being unrelated.
    """
    extracted: list[str] = []
    skipped: list[str] = []
    security_hits: list[str] = []
    total_uncompressed = 0

    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_ENTRIES:
            raise ValueError(
                f"archive contains {len(infos)} entries, limit is {MAX_ENTRIES}"
            )

        seen: set[str] = set()
        for info in infos:
            name = info.filename
            if info.is_dir():
                continue

            reason = is_unsafe_member(name)
            if reason:
                skipped.append(f"{name} ({reason})")
                security_hits.append(f"{name} ({reason})")
                continue

            # symlink / special-file detection via the Unix mode stored in the ZIP
            mode = info.external_attr >> 16
            if mode and (mode & 0o170000) == 0o120000:
                skipped.append(f"{name} (symlink)")
                security_hits.append(f"{name} (symlink)")
                continue

            base = os.path.basename(name.replace("\\", "/"))
            suffix = os.path.splitext(base)[1].lower()
            if base not in RECOGNISED_FILES:
                skipped.append(f"{name} (not a NightTrace artifact)")
                continue
            if suffix not in ALLOWED_SUFFIXES:
                skipped.append(f"{name} (unsupported extension)")
                continue
            if info.file_size > MAX_ENTRY_BYTES:
                skipped.append(f"{name} (entry too large)")
                continue

            total_uncompressed += info.file_size
            if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
                raise ValueError(
                    "archive expands beyond the "
                    f"{MAX_UNCOMPRESSED_BYTES // (1024 * 1024)} MB safety limit"
                )

            # Flatten into dest_root: no nested structure is needed.
            if base in seen:
                skipped.append(f"{name} (duplicate filename)")
                continue
            target = safe_target(dest_root, base)
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst, 64 * 1024)
            seen.add(base)
            extracted.append(base)
    return extracted, skipped, security_hits


def read_text(path: Path) -> str:
    raw = path.read_bytes()
    for encoding in ("utf-8-sig", "utf-8", "utf-16", "cp1252", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def load_records(folder: Path, json_name: str, csv_name: str | None):
    """Return (records, source_file, error). records is always a list."""
    json_path = folder / json_name
    if json_path.exists():
        try:
            text = read_text(json_path).strip()
            if not text:
                return [], json_name, "file is empty"
            data = json.loads(text)
            if isinstance(data, dict):
                items = data.get("items") if isinstance(data.get("items"), list) else [data]
            elif isinstance(data, list):
                items = data
            else:
                return [], json_name, f"unexpected JSON root type: {type(data).__name__}"
            return items, json_name, None
        except json.JSONDecodeError as exc:
            error = f"JSON parse error: {exc.msg} (line {exc.lineno})"
            if csv_name and (folder / csv_name).exists():
                csv_records, err2 = load_csv(folder / csv_name)
                if err2 is None:
                    return csv_records, csv_name, error + " - fell back to CSV"
            return [], json_name, error
        except OSError as exc:
            return [], json_name, f"cannot read file: {exc}"

    if csv_name and (folder / csv_name).exists():
        records, error = load_csv(folder / csv_name)
        return records, csv_name, ("JSON missing, used CSV" if error is None else error)

    return [], None, "artifact not found in the package"


def load_csv(path: Path):
    try:
        text = read_text(path)
        if not text.strip():
            return [], "file is empty"
        reader = csv.DictReader(io.StringIO(text))
        return [dict(row) for row in reader], None
    except (OSError, csv.Error) as exc:
        return [], f"CSV parse error: {exc}"


def str_or_none(value):
    if value is None:
        return None
    text = str(value).strip()
    if text == "" or text.lower() in {"null", "none", "nan"}:
        return None
    return text


def normalise_process(record: dict, index: int) -> dict:
    def num(*keys):
        for key in keys:
            if key in record:
                try:
                    return int(str(record[key]).strip())
                except (TypeError, ValueError):
                    continue
        return None

    return {
        "id": f"proc-{index}",
        "Name": str_or_none(record.get("Name")),
        "ProcessId": num("ProcessId", "PID", "pid"),
        "ParentProcessId": num("ParentProcessId", "PPID", "ppid"),
        "ParentName": str_or_none(record.get("ParentName")),
        "CreationDate": str_or_none(record.get("CreationDate")),
        "ExecutablePath": str_or_none(record.get("ExecutablePath", record.get("Path"))),
        "CommandLine": str_or_none(record.get("CommandLine")),
        "UserName": str_or_none(record.get("UserName", record.get("Owner"))),
        "SessionId": num("SessionId"),
        "raw": record,
    }


def normalise_run_key(record: dict, index: int) -> dict:
    return {
        "id": f"run-{index}",
        "kind": "run_key",
        "Type": "Registry Run Key",
        "Name": str_or_none(record.get("Name")),
        "Target": str_or_none(record.get("Command")),
        "Location": "/".join(
            p for p in [str_or_none(record.get("Hive")), str_or_none(record.get("KeyPath"))] if p
        )
        or None,
        "RunAs": str_or_none(record.get("RunAs", record.get("Scope"))),
        "Scope": str_or_none(record.get("Scope")),
        "ValueType": str_or_none(record.get("ValueType")),
        "LastWriteTime": str_or_none(record.get("LastWriteTime")),
        "CollectedAt": str_or_none(record.get("CollectedAt")),
        "raw": record,
    }


def normalise_task(record: dict, index: int) -> dict:
    return {
        "id": f"task-{index}",
        "kind": "scheduled_task",
        "Type": "Scheduled Task",
        "Name": str_or_none(record.get("TaskName", record.get("Name"))),
        "Target": str_or_none(record.get("Execute")),
        "Location": str_or_none(record.get("FullName", record.get("TaskPath"))),
        "RunAs": str_or_none(record.get("RunAs")),
        "RunAsRaw": str_or_none(record.get("RunAsRaw")),
        "GroupId": str_or_none(record.get("GroupId")),
        "State": str_or_none(record.get("State")),
        "Author": str_or_none(record.get("Author")),
        "RunLevel": str_or_none(record.get("RunLevel")),
        "Triggers": str_or_none(record.get("Triggers")),
        "LastRunTime": str_or_none(record.get("LastRunTime")),
        "NextRunTime": str_or_none(record.get("NextRunTime")),
        "LastTaskResult": str_or_none(record.get("LastTaskResult")),
        "Description": str_or_none(record.get("Description")),
        "CollectedAt": str_or_none(record.get("CollectedAt")),
        "raw": record,
    }


def normalise_service(record: dict, index: int) -> dict:
    def num(*keys):
        for key in keys:
            if key in record:
                try:
                    return int(str(record[key]).strip())
                except (TypeError, ValueError):
                    continue
        return None

    name = str_or_none(record.get("Name"))
    return {
        "id": f"svc-{index}",
        "kind": "service",
        "Type": "Windows Service",
        "Name": name,
        "DisplayName": str_or_none(record.get("DisplayName")),
        "Target": str_or_none(record.get("Execute", record.get("PathName"))),
        # Win32_Service does not return the registry path; every Windows service is
        # registered here, so this is a derived location, not a collected field.
        "Location": f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{name}" if name else None,
        "LocationDerived": True,
        "RunAs": str_or_none(record.get("StartName", record.get("RunAs"))),
        "State": str_or_none(record.get("State")),
        "StartMode": str_or_none(record.get("StartMode")),
        "ServiceType": str_or_none(record.get("ServiceType")),
        "ProcessId": num("ProcessId"),
        "Description": str_or_none(record.get("Description")),
        "CollectedAt": str_or_none(record.get("CollectedAt")),
        "raw": record,
    }


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "service": "NightTrace", "version": "1.0.0", "time": now_iso()})


@app.route("/api/upload", methods=["POST"])
def upload():
    cleanup_sessions()

    if "package" not in request.files:
        return jsonify({"error": "No file received. Please choose the ZIP produced by collector.ps1."}), 400

    upload_file = request.files["package"]
    if not upload_file or upload_file.filename == "":
        return jsonify({"error": "Empty file name - nothing was uploaded."}), 400

    if not upload_file.filename.lower().endswith(".zip"):
        return jsonify({"error": "Only .zip evidence packages are accepted."}), 400

    session_id = uuid.uuid4().hex
    session_dir = WORK_ROOT / f"nt_{session_id}"
    session_dir.mkdir(parents=True, exist_ok=True)

    zip_path = WORK_ROOT / f"nt_{session_id}.zip"
    try:
        upload_file.save(zip_path)
    except OSError as exc:
        shutil.rmtree(session_dir, ignore_errors=True)
        return jsonify({"error": f"Could not store the upload: {exc}"}), 500

    size_bytes = zip_path.stat().st_size
    if size_bytes == 0:
        drop_files(session_dir, zip_path)
        return jsonify({"error": "The uploaded file is empty."}), 400
    if size_bytes > MAX_UPLOAD_BYTES:
        drop_files(session_dir, zip_path)
        return jsonify({"error": "Archive exceeds the 64 MB size limit."}), 413

    if not zipfile.is_zipfile(zip_path):
        drop_files(session_dir, zip_path)
        return jsonify({"error": "File is not a valid ZIP archive (it may be corrupted or truncated)."}), 400

    try:
        extracted, skipped, security_hits = extract_archive(zip_path, session_dir)
    except zipfile.BadZipFile:
        drop_files(session_dir, zip_path)
        return jsonify({"error": "ZIP archive is damaged and cannot be read."}), 400
    except ValueError as exc:
        drop_files(session_dir, zip_path)
        return jsonify({"error": f"Archive rejected by the safety check: {exc}"}), 400
    except OSError as exc:
        drop_files(session_dir, zip_path)
        return jsonify({"error": f"Extraction failed: {exc}"}), 500

    if not extracted:
        drop_files(session_dir, zip_path)
        if security_hits:
            return jsonify({
                "error": "该压缩包中的候选文件全部因安全校验被拒绝，未写入磁盘。",
                "hint": "被拒绝的条目：",
                "skipped": security_hits[:20],
            }), 400
        return jsonify({
            "error": "No NightTrace artifacts were found inside this ZIP.",
            "hint": "Expected files such as processes.json, persistence_run.json, "
                    "persistence_scheduled_tasks.json or persistence_services.json. "
                    "Make sure you upload the ZIP created by collector.ps1.",
            "skipped": skipped[:20],
        }), 400

    session = build_session(session_id, session_dir, zip_path, extracted, skipped, size_bytes)
    SESSIONS[session_id] = session
    return jsonify(public_session(session))


def drop_files(session_dir: Path, zip_path: Path) -> None:
    shutil.rmtree(session_dir, ignore_errors=True)
    try:
        zip_path.unlink(missing_ok=True)
    except OSError:
        pass


def build_session(session_id, session_dir, zip_path, extracted, skipped, size_bytes) -> dict:
    warnings: list[str] = []

    processes_raw, proc_src, proc_err = load_records(session_dir, *MODULE_FILES["processes"][:2])
    runs_raw, run_src, run_err = load_records(session_dir, *MODULE_FILES["run_keys"][:2])
    tasks_raw, task_src, task_err = load_records(session_dir, *MODULE_FILES["scheduled_tasks"][:2])
    svcs_raw, svc_src, svc_err = load_records(session_dir, *MODULE_FILES["services"][:2])
    sysinfo_raw, sys_src, sys_err = load_records(session_dir, *MODULE_FILES["system_info"][:2])
    meta_raw, meta_src, meta_err = load_records(session_dir, *MODULE_FILES["meta"][:2])

    for label, error in (
        ("Processes", proc_err),
        ("Run/RunOnce keys", run_err),
        ("Scheduled tasks", task_err),
        ("Services", svc_err),
        ("System info", sys_err),
        ("Collection metadata", meta_err),
    ):
        if error:
            warnings.append(f"{label}: {error}")

    for label, records in (
        ("Processes", processes_raw),
        ("Run/RunOnce keys", runs_raw),
        ("Scheduled tasks", tasks_raw),
        ("Services", svcs_raw),
    ):
        if not records and not any(w.startswith(label + ":") for w in warnings):
            warnings.append(f"{label}: no records in this package (the module may have failed on the host).")

    meta = meta_raw[0] if meta_raw else {}
    if isinstance(meta, dict):
        for module in meta.get("modules", []) or []:
            if isinstance(module, dict) and str(module.get("status", "")).lower() not in ("", "ok"):
                warnings.append(
                    f"Collector module '{module.get('module')}' reported status "
                    f"{module.get('status')} on the target host"
                    + (f": {module.get('error')}" if module.get("error") else "")
                )
        for note in meta.get("notes", []) or []:
            if str(note).strip():
                warnings.append(f"采集降级说明：{note}")
        if meta.get("elevated") is False:
            warnings.append(
                "采集时未以管理员身份运行：进程属主、部分命令行与所有用户注册表配置单元可能不完整。"
            )
        if meta.get("notImplemented"):
            warnings.append(
                "该版本未实现的采集项：" + "、".join(str(x) for x in meta["notImplemented"])
            )

    processes = [normalise_process(r, i) for i, r in enumerate(processes_raw) if isinstance(r, dict)]
    run_keys = [normalise_run_key(r, i) for i, r in enumerate(runs_raw) if isinstance(r, dict)]
    tasks = [normalise_task(r, i) for i, r in enumerate(tasks_raw) if isinstance(r, dict)]
    services = [normalise_service(r, i) for i, r in enumerate(svcs_raw) if isinstance(r, dict)]

    raw_available = sorted(p.name for p in session_dir.iterdir() if p.is_file())

    return {
        "id": session_id,
        "created_ts": time.time(),
        "created_at": now_iso(),
        "dir": session_dir,
        "zip_path": zip_path,
        "zip_name": os.path.basename(zip_path),
        "zip_bytes": size_bytes,
        "extracted": extracted,
        "skipped": skipped,
        "warnings": warnings,
        "meta": meta if isinstance(meta, dict) else {},
        "system_info": sysinfo_raw[0] if sysinfo_raw else {},
        "processes": processes,
        "persistence": {
            "run_keys": run_keys,
            "scheduled_tasks": tasks,
            "services": services,
        },
        "sources": {
            "processes": proc_src,
            "run_keys": run_src,
            "scheduled_tasks": task_src,
            "services": svc_src,
            "system_info": sys_src,
            "meta": meta_src,
        },
        "raw_files": raw_available,
    }


def public_session(session: dict) -> dict:
    return {
        "session": {
            "id": session["id"],
            "created_at": session["created_at"],
            "zip_name": session["zip_name"],
            "zip_bytes": session["zip_bytes"],
            "warnings": session["warnings"],
            "skipped": session["skipped"],
            "raw_files": session["raw_files"],
            "sources": session["sources"],
        },
        "meta": session["meta"],
        "systemInfo": session["system_info"],
        "processes": session["processes"],
        "persistence": session["persistence"],
        "counts": {
            "processes": len(session["processes"]),
            "runKeys": len(session["persistence"]["run_keys"]),
            "scheduledTasks": len(session["persistence"]["scheduled_tasks"]),
            "services": len(session["persistence"]["services"]),
        },
    }


def get_session(session_id: str) -> dict:
    session = SESSIONS.get(session_id)
    if not session:
        abort(404, description="Session not found or expired. Please upload the ZIP again.")
    return session


@app.route("/api/session/<session_id>")
def session_detail(session_id):
    return jsonify(public_session(get_session(session_id)))


@app.route("/api/session/<session_id>/processes")
def session_processes(session_id):
    session = get_session(session_id)
    return jsonify({"records": session["processes"], "source": session["sources"]["processes"]})


@app.route("/api/session/<session_id>/persistence")
def session_persistence(session_id):
    session = get_session(session_id)
    return jsonify({"records": session["persistence"], "sources": session["sources"]})


@app.route("/api/session/<session_id>/raw")
def session_raw(session_id):
    session = get_session(session_id)
    name = request.args.get("file", "")
    safe_name = os.path.basename(name.replace("\\", "/"))
    if safe_name not in session["raw_files"]:
        return jsonify({"error": f"'{safe_name}' is not part of this package."}), 404
    path = session["dir"] / safe_name
    try:
        text = read_text(path)
    except OSError as exc:
        return jsonify({"error": f"Cannot read the file: {exc}"}), 500
    truncated = len(text) > RAW_FILE_CHAR_LIMIT
    return jsonify({
        "file": safe_name,
        "truncated": truncated,
        "bytes": path.stat().st_size,
        "content": text[:RAW_FILE_CHAR_LIMIT],
    })


@app.route("/api/session/<session_id>", methods=["DELETE"])
def session_delete(session_id):
    if session_id in SESSIONS:
        drop_session(session_id)
        return jsonify({"status": "deleted"})
    return jsonify({"status": "not-found"}), 404


# --------------------------------------------------------------------------
# Error handlers - always answer with JSON for /api/* so the UI can show a hint
# --------------------------------------------------------------------------
@app.errorhandler(404)
def handle_404(err):
    if request.path.startswith("/api/"):
        return jsonify({"error": getattr(err, "description", "Not found.")}), 404
    return render_template("index.html"), 404


@app.errorhandler(413)
def handle_413(err):
    return jsonify({"error": "Upload too large (limit is 64 MB)."}), 413


@app.errorhandler(500)
def handle_500(err):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Internal server error while processing the package."}), 500
    return "Internal server error", 500


def main() -> int:
    cleanup_sessions()
    print("=" * 68)
    print(" NightTrace - Windows host artifact review console")
    print(f" Open: http://{HOST}:{PORT}")
    print(f" Session work dir: {WORK_ROOT}")
    print(" Bound to localhost only. No data leaves this machine.")
    print("=" * 68)
    try:
        app.run(host=HOST, port=PORT, debug=False, threaded=True)
    except OSError as exc:
        print(f"[x] Cannot start the server on {HOST}:{PORT} - {exc}")
        print("    Set another port, e.g.  set NIGHTTRACE_PORT=5050  &&  python app.py")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
