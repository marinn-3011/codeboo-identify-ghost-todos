#!/usr/bin/env python3
"""CodeBoo: a local-first haunted code reviewer.

Give it a public GitHub link or a folder on this computer. It looks through the
code with simple, transparent rules (forgotten TODOs, secrets typed into code,
risky calls, quiet failures, possible leaks), ranks what it finds by urgency,
and asks a model running on your own machine (through Ollama) to explain the
most serious ones in everyday words.

Python standard library only, nothing to pip install. Code is scanned on this
computer. The only network call is the download of a GitHub archive.
"""

import io
import json
import os
import re
import shutil
import tempfile
import urllib.error
import urllib.request
import uuid
import zipfile
import zlib
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).parent
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MODEL = os.environ.get("HUNT_MODEL", "gemma4:e4b")
PORT = int(os.environ.get("PORT", "8766"))
ARCHIVE_URL = os.environ.get("ARCHIVE_URL", "https://github.com/{owner}/{repo}/archive/{ref}.zip")

MAX_FILES = 800
MAX_FILE_BYTES = 300_000
MAX_ZIP_BYTES = 80 * 1024 * 1024
MAX_UNZIPPED_BYTES = 400 * 1024 * 1024
MAX_GHOSTS = 60
MAX_PER_RULE_PER_FILE = 4
EXPLAIN_BATCH_LIMIT = 6

SKIP_DIRS = {
    "node_modules", "vendor", "dist", "build", "out", "target", "venv", "env",
    "__pycache__", "coverage", "bower_components", "third_party", "site-packages",
}
CODE_EXT = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".kt", ".c", ".h",
    ".cpp", ".cc", ".hpp", ".cs", ".go", ".rs", ".rb", ".php", ".swift", ".sh",
    ".bash", ".sql", ".html", ".vue", ".svelte", ".lua", ".pl", ".scala", ".dart",
}
PY = {".py"}
JS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"}
PHP = {".php"}
RB = {".rb"}
C_FAMILY = {".c", ".h", ".cpp", ".cc", ".hpp"}
CPP = {".cpp", ".cc", ".hpp"}


class HuntError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


# ------------------------------------------------------------------ the rules

INFO = {}   # rule id -> category, plain-language explanation, fix
RULES = []  # rules that are a single pattern on a single line

CAT_ORDER = {"secret": 0, "danger": 1, "weak": 2, "leak": 3, "sloppy": 4, "todo": 5}
CAT_LABEL = {
    "secret": "Leaked secret",
    "danger": "Risky code",
    "weak": "Weak spot",
    "leak": "Possible leak",
    "sloppy": "Quiet failure",
    "todo": "Forgotten promise",
}


def rule(rid, cat, sev, pattern, plain, fix, exts=None, unless=None, once=False):
    INFO[rid] = {"cat": cat, "plain": plain, "fix": fix}
    RULES.append({
        "id": rid, "cat": cat, "sev": sev, "rx": re.compile(pattern), "exts": exts,
        "unless": re.compile(unless) if unless else None, "once": once,
    })


INFO["todo"] = {
    "cat": "todo",
    "plain": "Someone left a note-to-self here and never came back: “{note}”. Small notes like this pile up over time.",
    "fix": "Finish it, turn it into a tracked task, or delete the note if it no longer matters.",
}
INFO["hardcoded-secret"] = {
    "cat": "secret",
    "plain": "A password or access key looks like it is typed straight into the code, where anyone who can read the project can see it.",
    "fix": "Move it out of the code into a private setting (such as an environment variable). If this project was ever public, change the password or key.",
}

rule("private-key", "secret", 5, r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
     "A private key is written directly in the code. Anyone who can read this project can use it.",
     "Treat it as stolen: replace the key, remove it from the code, and load keys from a safe private place instead.")
rule("cloud-token", "secret", 5, r"\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{36,}\b",
     "A real-looking access token for a cloud or code-hosting account is written in the code. Anyone who finds it can act as that account.",
     "Revoke the token right away, create a new one, and keep it out of the code.")
rule("eval", "danger", 4, r"(?<![\w.])eval\s*\(",
     "This line runs text as if it were code. If a stranger can influence that text, they can make your program do whatever they want.",
     "Use a safer way to do the same job, such as reading the data with a parser instead of running it.",
     exts=PY | JS | PHP | RB)
rule("exec", "danger", 4, r"(?<![\w.])exec\s*\(",
     "This line runs text as if it were code. If a stranger can influence that text, they can make your program do whatever they want.",
     "Replace it with a fixed, explicit piece of code, or parse the data instead of running it.",
     exts=PY | PHP)
rule("new-function", "danger", 4, r"\bnew\s+Function\s*\(",
     "This builds a function out of text at run time, which works like running whatever that text says.",
     "Write the function ahead of time instead of building it from text.",
     exts=JS)
rule("shell", "danger", 4,
     r"\bos\.system\s*\(|\bsubprocess\.\w+\([^)]*shell\s*=\s*True|\b(?:shell_exec|passthru|proc_open)\s*\(",
     "This runs a command through the system shell. If any part of the command comes from user input, it can be tricked into running something else.",
     "Pass the command as a list of separate parts without a shell, and check any piece that comes from a user.",
     exts=PY | PHP)
rule("shell-js", "danger", 3, r"child_process\.exec(?:Sync)?\s*\(|\bexecSync\s*\(",
     "This runs a command through the system shell. If any part of it comes from user input, it can be tricked into running something else.",
     "Use a version that takes the command and its arguments separately, and check anything a user provides.",
     exts=JS)
rule("deserialize", "danger", 4,
     r"\bpickle\.loads?\s*\(|\bmarshal\.loads?\s*\(|\bunserialize\s*\(|\byaml\.load\s*\((?![^)]*Loader)",
     "This turns saved data back into live objects in a way that can run code hidden inside the data.",
     "Only load data you created yourself, or switch to a plain format such as JSON.",
     exts=PY | PHP)
rule("sql", "danger", 4,
     r"""\.(?:execute|executemany|query|raw)\s*\(\s*(?:f["']|["'][^"']*["']\s*[%+]|`[^`]*\$\{|[^)]*\.format\s*\()""",
     "This builds a database question by gluing text together. Cleverly written input could change the question and expose or damage data.",
     "Use placeholders (parameters) so the database treats input as plain data, never as instructions.")
rule("tls-off", "weak", 3,
     r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|_create_unverified_context|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)",
     "Checks that make sure a secure connection is talking to the right party are switched off, so the program could be fooled by an impostor.",
     "Turn certificate checking back on.")
rule("weak-hash", "weak", 2,
     r"""hashlib\.(?:md5|sha1)\s*\(|createHash\(\s*["'](?:md5|sha1)["']|MessageDigest\.getInstance\(\s*"(?:MD5|SHA-?1)\"""",
     "This uses an old, weak fingerprinting method that can be forged. It is fine for simple checksums but not for passwords or security.",
     "Use a modern method such as SHA-256, and a dedicated password hasher for passwords.")
rule("debug-on", "weak", 2,
     r"""app\.run\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True\b|Access-Control-Allow-Origin["'\s:,=]+\*""",
     "A debug or wide-open setting is switched on. It is handy while building but unsafe in an app other people can reach.",
     "Turn it off, or make it depend on a setting that is off in the live version.")
rule("chmod-777", "weak", 3, r"chmod\s+(?:-R\s+)?0?777|os\.chmod\([^)]*0o?777",
     "A file or folder is made readable and changeable by everyone on the machine.",
     "Give it only the permissions it really needs.")
rule("swallow", "sloppy", 2,
     r"^\s*except\s*:|^\s*except\s+\w[\w.]*(?:\s+as\s+\w+)?\s*:\s*pass\b|catch\s*\(\s*\w*\s*\)\s*\{\s*\}",
     "Errors are caught and hidden here, so when something goes wrong it fails silently and is hard to find later.",
     "Catch only the specific errors you expect, and at least write them to a log.")
rule("open-leak", "leak", 2, r"^\s*[\w.\[\]]+\s*=\s*open\s*\(",
     "A file is opened here and nothing in this file seems to close it, which can slowly use up the computer's resources.",
     "Open it with a with-block so it closes itself.",
     exts=PY, unless=r"\.close\s*\(", once=True)
rule("timer-leak", "leak", 2, r"\bsetInterval\s*\(",
     "A repeating timer is started but nothing in this file ever stops it, so it may keep running and holding memory forever.",
     "Stop the timer (clearInterval) when it is no longer needed.",
     exts=JS, unless=r"clearInterval", once=True)
rule("malloc-leak", "leak", 3, r"\b(?:malloc|calloc|realloc)\s*\(",
     "Memory is reserved by hand here, but I could not find where it is given back, so it may leak.",
     "Make sure every piece of reserved memory is freed exactly once on every path.",
     exts=C_FAMILY, unless=r"\bfree\s*\(", once=True)
rule("new-leak", "leak", 2, r"\bnew\s+[A-Za-z_]\w*\s*[(\[]",
     "Memory is reserved here, but nothing in this file seems to release it, so it may leak.",
     "Use smart pointers, or make sure every allocation is deleted exactly once.",
     exts=CPP, unless=r"\bdelete\b|unique_ptr|shared_ptr|make_unique|make_shared", once=True)

TODO_RX = re.compile(r"(?:#|//|/\*|^\s*\*|--|<!--).*?\b(TODO|FIXME|HACK|XXX|BUG)\b")
TODO_BASE = {"TODO": 1, "FIXME": 2, "HACK": 2, "XXX": 2, "BUG": 3}
TODO_HOT = re.compile(r"(?i)secur|passw|auth|leak|vulnerab|injection|unsafe|crash|data loss|race")

SECRET_ASSIGN = re.compile(
    r"""(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret)\b(\s*[:=]\s*)(["'])([^"'\s]{6,})\3"""
)
PLACEHOLDER = re.compile(
    r"(?i)change.?me|example|your[_\- ]|x{4,}|\*{3,}|<[^>]+>|placeholder|dummy|\$\{|process\.env|os\.environ|getenv|env\[|^\.{3}$"
)
TOKEN_PATTERNS = [
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]
TESTY = re.compile(r"(^|/)(tests?|spec|__tests__|examples?|fixtures?|samples?|mocks?|docs?)(/|$)|(_test|\.test|\.spec)\.", re.I)
COMMENT_START = re.compile(r"^\s*(?:#|//|/\*|\*(?:\s|/|$)|--|<!--)")


def redact(line):
    """Hide secret values before anything is shown or sent to the model."""
    line = SECRET_ASSIGN.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{m.group(4)[:2]}•••{m.group(3)}", line)
    for rx in TOKEN_PATTERNS:
        line = rx.sub(lambda m: m.group(0)[:4] + "•••", line)
    return line


# ------------------------------------------------------------------- scanning

def scan_file(rel, text):
    ext = Path(rel).suffix.lower()
    lines = text.split("\n")
    testy = bool(TESTY.search(rel))
    found = []
    per_rule = {}
    flagged_once = set()

    def add(rid, sev, i, note=None):
        if rid != "todo" and testy:
            sev = max(1, sev - 1)
        info = INFO[rid]
        plain = info["plain"].replace("{note}", note) if note is not None else info["plain"]
        lo, hi = max(0, i - 3), min(len(lines), i + 4)
        context = [[n + 1, redact(lines[n].rstrip())[:160]] for n in range(lo, hi)]
        found.append({
            "rule": rid, "cat": info["cat"], "level": sev, "file": rel, "line": i + 1,
            "snippet": redact(lines[i].strip())[:180], "plain": plain, "fix": info["fix"],
            "context": context,
        })

    for i, line in enumerate(lines):
        if len(line) > 600:
            continue
        is_comment = bool(COMMENT_START.match(line))

        m = TODO_RX.search(line)
        if m and per_rule.get("todo", 0) < MAX_PER_RULE_PER_FILE:
            sev = TODO_BASE[m.group(1)]
            if TODO_HOT.search(line):
                sev = min(4, sev + 1)
            note = line[m.end():].strip(" :-*/#\t").replace("-->", "").strip()[:120] or "no details left"
            per_rule["todo"] = per_rule.get("todo", 0) + 1
            add("todo", sev, i, note)

        m = SECRET_ASSIGN.search(line)
        if m and not PLACEHOLDER.search(m.group(4)) and per_rule.get("hardcoded-secret", 0) < MAX_PER_RULE_PER_FILE:
            per_rule["hardcoded-secret"] = per_rule.get("hardcoded-secret", 0) + 1
            add("hardcoded-secret", 4, i)

        for r in RULES:
            if r["exts"] and ext not in r["exts"]:
                continue
            if is_comment and r["cat"] != "secret":
                continue
            if not r["rx"].search(line):
                continue
            if r["once"]:
                if r["id"] in flagged_once:
                    continue
                flagged_once.add(r["id"])
                if r["unless"] and r["unless"].search(text):
                    continue
            elif per_rule.get(r["id"], 0) >= MAX_PER_RULE_PER_FILE:
                continue
            per_rule[r["id"]] = per_rule.get(r["id"], 0) + 1
            add(r["id"], r["sev"], i)
    return found


def scan_tree(root):
    findings, files, total_lines, truncated = [], 0, 0, False
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith("."))
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.suffix.lower() not in CODE_EXT or name.endswith(".min.js"):
                continue
            try:
                size = path.stat().st_size
                if size == 0 or size > MAX_FILE_BYTES:
                    continue
                raw = path.read_bytes()
            except OSError:
                continue
            if b"\0" in raw[:2048]:
                continue
            if files >= MAX_FILES:
                truncated = True
                break
            text = raw.decode("utf-8", errors="replace")
            files += 1
            total_lines += text.count("\n") + 1
            rel = path.relative_to(root).as_posix()
            findings.extend(scan_file(rel, text))
        if truncated:
            break
    return findings, files, total_lines, truncated


GHOST_NAMES = {
    "cute": ["Pip", "Mallow", "Bean", "Wisp", "Floofy", "Peek", "Boo-bles", "Nimbus"],
    "mid": ["Murmur", "Shade", "Lurker", "Hush", "Drift", "Gloom"],
    "scary": ["Grim", "Morrow", "The Hollow One", "Dread", "Moros", "The Gaunt", "Banshee", "Revenant"],
}


def ghost_name(level, file, line):
    group = "cute" if level <= 2 else "mid" if level == 3 else "scary"
    names = GHOST_NAMES[group]
    return names[zlib.crc32(f"{file}:{line}".encode()) % len(names)]


# ------------------------------------------------------------ getting the code

GITHUB_RX = re.compile(
    r"^https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:/tree/([A-Za-z0-9_./-]+)|/blob/[A-Za-z0-9_./-]+)?/?$"
)


def download_zip(url):
    req = urllib.request.Request(url, headers={"User-Agent": "codeboo"})
    try:
        resp = urllib.request.urlopen(req, timeout=60)
    except urllib.error.HTTPError as err:
        if err.code == 404:
            raise HuntError("I couldn't find that repository. Is it public, and is the link right?")
        raise HuntError(f"GitHub answered with an error (HTTP {err.code}). Try again in a minute.", 502)
    except urllib.error.URLError:
        raise HuntError("I couldn't reach GitHub. Check your internet connection.", 502)
    data = bytearray()
    with resp:
        while True:
            chunk = resp.read(1 << 16)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > MAX_ZIP_BYTES:
                raise HuntError("That repository is too big for a quick hunt (over 80 MB).")
    return bytes(data)


def extract_zip(data, dest):
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise HuntError("GitHub sent something that isn't a zip file.", 502)
    dest = dest.resolve()
    total = 0
    with zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            target = (dest / info.filename).resolve()
            if dest not in target.parents:
                continue  # never write outside the folder
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                continue  # skip symlinks
            total += info.file_size
            if total > MAX_UNZIPPED_BYTES:
                raise HuntError("That repository is too big for a quick hunt.")
            if target.suffix.lower() not in CODE_EXT or info.file_size > MAX_FILE_BYTES:
                continue
            if any(part in SKIP_DIRS or part.startswith(".") for part in Path(info.filename).parts[1:-1]):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)


def get_source(source):
    """Return (folder to scan, label, temp folder to delete or None)."""
    source = (source or "").strip().strip('"')
    if not source:
        raise HuntError("Paste a GitHub link or a folder path first.")
    if source.lower().startswith(("github.com/", "www.github.com/")):
        source = "https://" + source
    m = GITHUB_RX.match(source)
    if m:
        owner, repo, branch = m.group(1), m.group(2), (m.group(3) or "").rstrip("/")
        ref = f"refs/heads/{branch}" if branch else "HEAD"
        tmp = Path(tempfile.mkdtemp(prefix="codeboo-"))
        try:
            extract_zip(download_zip(ARCHIVE_URL.format(owner=owner, repo=repo, ref=ref)), tmp)
        except Exception:
            shutil.rmtree(tmp, ignore_errors=True)
            raise
        children = [c for c in tmp.iterdir()]
        root = children[0] if len(children) == 1 and children[0].is_dir() else tmp
        return root, f"{owner}/{repo}", tmp
    if source.lower().startswith(("http://", "https://")):
        raise HuntError("I can only fetch public GitHub links (https://github.com/owner/repo), or you can give me a folder on this computer.")
    folder = Path(source).expanduser()
    if not folder.is_dir():
        raise HuntError("I couldn't find that folder. Check the path, or paste a GitHub link instead.")
    return folder, folder.name or str(folder), None


HUNTS = OrderedDict()  # hunt id -> {ghost id -> details kept for the explain step}


def hunt(source):
    root, label, tmp = get_source(source)
    try:
        findings, files, total_lines, truncated = scan_tree(root)
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)

    counts = {str(n): 0 for n in range(1, 6)}
    for f in findings:
        counts[str(f["level"])] += 1
    findings.sort(key=lambda f: (-f["level"], CAT_ORDER[f["cat"]], f["file"], f["line"]))
    shown = findings[:MAX_GHOSTS]

    hunt_id = uuid.uuid4().hex[:12]
    kept, ghosts = {}, []
    for n, f in enumerate(shown, start=1):
        gid = f"g{n}"
        kept[gid] = {k: f[k] for k in ("rule", "cat", "level", "file", "line", "context")}
        ghosts.append({
            "id": gid, "level": f["level"], "cat": f["cat"], "label": CAT_LABEL[f["cat"]],
            "name": ghost_name(f["level"], f["file"], f["line"]), "rule": f["rule"],
            "file": f["file"], "line": f["line"], "snippet": f["snippet"],
            "plain": f["plain"], "fix": f["fix"],
        })
    HUNTS[hunt_id] = kept
    while len(HUNTS) > 4:
        HUNTS.popitem(last=False)
    return {
        "hunt_id": hunt_id, "repo": label, "files": files, "lines": total_lines,
        "truncated": truncated, "total": len(findings), "shown": len(shown),
        "counts": counts, "ghosts": ghosts,
    }


# ------------------------------------------------------- explaining with a model

EXPLAIN_SYSTEM = """You explain automated code-scan findings to people who don't write code for a living.

For each finding you get the kind of problem the scanner suspects, how serious the scanner guessed it was (1 to 5), and a short code excerpt. The line marked >> is the one that was flagged. Secrets in the excerpt are hidden as •••.

For each finding decide:
- verdict: "real" if it looks like a genuine problem, "maybe" if the excerpt isn't enough to tell, "fine" if it is probably harmless (test code, a placeholder, safe usage).
- urgency: 1 to 5. 5 means fix today, 3 means plan it, 1 means tidy up someday.
- plain: one or two short sentences in everyday words saying what is wrong and why it matters. No jargon, no code, no function names.
- fix: one or two short sentences saying what to do about it, in everyday words.

Rules: judge only what the excerpt shows. Never invent code that isn't there. If you are unsure, say "maybe". Keep a calm, friendly tone. Reply with JSON only."""

EXPLAIN_SCHEMA = {
    "type": "object",
    "properties": {"results": {"type": "array", "items": {
        "type": "object",
        "properties": {
            "n": {"type": "integer"},
            "verdict": {"type": "string", "enum": ["real", "maybe", "fine"]},
            "urgency": {"type": "integer", "enum": [1, 2, 3, 4, 5]},
            "plain": {"type": "string"},
            "fix": {"type": "string"},
        },
        "required": ["n", "verdict", "urgency", "plain", "fix"],
    }}},
    "required": ["results"],
}


def call_ollama(system, user):
    body = {
        "model": MODEL,
        "stream": False,
        "format": EXPLAIN_SCHEMA,
        "think": False,  # skip long hidden reasoning, we want short answers fast
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        "options": {"temperature": 0.3, "num_ctx": 8192},
    }
    for attempt in range(2):
        req = urllib.request.Request(
            OLLAMA_URL + "/api/chat",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=600) as resp:
                return json.load(resp).get("message", {}).get("content", "")
        except urllib.error.HTTPError as err:
            if err.code == 400 and attempt == 0 and "think" in body:
                del body["think"]  # this model doesn't take the option, try without it
                continue
            if err.code == 404:
                raise HuntError(f"Model '{MODEL}' is not installed. Run: ollama pull {MODEL}", 502)
            raise HuntError(f"Ollama returned an error (HTTP {err.code}).", 502)
        except urllib.error.URLError:
            raise HuntError(f"Can't reach Ollama at {OLLAMA_URL}. Start it with: ollama serve", 502)
    raise HuntError("Ollama didn't answer.", 502)


def parse_json(text):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    raise HuntError("The model's reply wasn't readable. Try again.", 502)


def excerpt_text(entry):
    rows = []
    for num, text in entry["context"]:
        mark = ">>" if num == entry["line"] else "  "
        rows.append(f"{mark} {num:>4} | {text}")
    return "\n".join(rows)


def explain(hunt_id, ids):
    kept = HUNTS.get(hunt_id)
    if kept is None:
        raise HuntError("That hunt has expired. Start a new one.")
    ids = [i for i in ids if i in kept][:EXPLAIN_BATCH_LIMIT]
    if not ids:
        return []
    parts = ["Findings to review:\n"]
    for n, gid in enumerate(ids, start=1):
        e = kept[gid]
        parts.append(
            f"Finding {n}\nType: {CAT_LABEL[e['cat']]} (rule: {e['rule']})\n"
            f"Scanner's guess of seriousness: {e['level']} of 5\n"
            f"File: {e['file']}, line {e['line']}\n{excerpt_text(e)}\n"
        )
    data = parse_json(call_ollama(EXPLAIN_SYSTEM, "\n".join(parts)))
    results = []
    for item in data.get("results", []):
        try:
            n = int(item.get("n"))
            gid = ids[n - 1]
            if n < 1:
                continue
            urgency = int(item.get("urgency"))
        except (TypeError, ValueError, IndexError):
            continue
        base = kept[gid]["level"]
        urgency = max(base - 2, min(base + 1, max(1, min(5, urgency))))
        verdict = item.get("verdict") if item.get("verdict") in ("real", "maybe", "fine") else "maybe"
        if verdict == "fine":
            urgency = min(urgency, 2)
        plain = str(item.get("plain", "")).strip()[:400]
        fix = str(item.get("fix", "")).strip()[:400]
        if not plain:
            continue
        results.append({"id": gid, "verdict": verdict, "urgency": urgency, "plain": plain, "fix": fix})
    return results


def health():
    result = {"ollama": False, "model": MODEL, "model_present": False}
    try:
        with urllib.request.urlopen(OLLAMA_URL + "/api/tags", timeout=3) as resp:
            names = [m.get("name", "") for m in json.load(resp).get("models", [])]
        result["ollama"] = True
        result["model_present"] = any(n == MODEL or n.startswith(MODEL + ":") for n in names)
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------- http

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # keep paths and requests out of the terminal

    def send_bytes(self, body, content_type, status=200):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, payload, status=200):
        self.send_bytes(json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                        "application/json; charset=utf-8", status)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self.send_bytes((HERE / "index.html").read_bytes(), "text/html; charset=utf-8")
        elif self.path == "/api/health":
            self.send_json(health())
        else:
            self.send_json({"error": "Not found"}, 404)

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            self.send_json({"error": "Bad request."}, 400)
            return
        try:
            if self.path == "/api/hunt":
                self.send_json(hunt(str(payload.get("source", ""))))
            elif self.path == "/api/explain":
                ids = payload.get("ids", [])
                if not isinstance(ids, list):
                    raise HuntError("Bad request.")
                self.send_json({"results": explain(str(payload.get("hunt_id", "")), [str(i) for i in ids])})
            else:
                self.send_json({"error": "Not found"}, 404)
        except HuntError as err:
            self.send_json({"error": str(err)}, err.status)


def main():
    # Bind to localhost only, so nothing else on your network can reach it.
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"CodeBoo is running at http://127.0.0.1:{PORT}  (model: {MODEL})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nThe ghosts return to rest.")


if __name__ == "__main__":
    main()
