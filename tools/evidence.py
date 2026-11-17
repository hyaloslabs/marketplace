#!/usr/bin/env python3
"""Automated evidence on every release (S7.4, ADR-0100 in hyaloslabs/hyalos).

Each built skill archive is checked three ways, and any failure blocks publication:

- static analysis: what capabilities.json asks for is in Hyalos's vocabulary and never something
  the shipped policy refuses a job; no file is binary; a script fetches nothing unless the skill
  asks for egress, runs nothing it decodes or downloads, and reads no credential; every URL names a
  host the skill asks for; and shellcheck passes on every shell script.
- red-team items: no file matches an item in redteam/items.json, the prompt injections and hidden
  text a skill must not carry. Each item has a case in redteam/cases that it must catch, so an item
  that stops matching fails the tests.
- the capability diff: what each skill asks for, against the last release of it. Every name it
  adds must be listed for its name and version in capability-changes.json, which a code owner
  approves in a pull request, so no release widens a skill silently.

It reads the archives in the format pack.py writes, so it checks exactly what is signed. Nothing in
a skill reaches the report except names from the vocabulary, digests and rule ids.

    evidence.py <new-archives-dir> [<old-archives-dir>] [--report <file>] [--require-shellcheck]
"""

import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import pack  # noqa: E402

# Hyalos's capability vocabulary (core/types/src/capability.rs and manifest.rs, version 1).
ACTIONS = {"read", "push", "open_pr", "comment", "merge", "change_policy", "publish",
           "spend_over_cap", "export_credentials"}
# What the shipped policy never permits a job, so no skill may ask for it.
NEVER = {"change_policy", "publish", "spend_over_cap", "export_credentials"}
FLOWS = {"job->model", "job->forge", "job->web"}
FIELDS = ("actions", "egress_hosts", "tools", "data_flows")
HOST = re.compile(r"(?=.{1,253}\Z)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\Z")
TOOL = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")

# Static rules over a script's text: (id, what it finds, pattern). A script is a file that is
# executable, ends in .sh, .py or .bash, or starts with #!.
NETWORK = re.compile(r"\b(curl|wget|nc|ncat|socat|telnet|ftp|scp|rsync)\b|/dev/(tcp|udp)/|urllib|requests\.|http\.client|socket\.")
STATIC = [
    ("exec.decoded", "runs what it decodes or downloads",
     re.compile(r"\|\s*(ba|z|da)?sh\b|\beval\b|\bexec\s*\(|base64\s+(-d|--decode)|\bxxd\s+-r|\bsource\s+<\(")),
    ("secret.read", "reads a credential or the environment",
     re.compile(r"\.ssh/|\.aws/|\.netrc|\.git-credentials|\.docker/config|/etc/shadow|\bprintenv\b|"
                r"\benv\s*($|\||>)|os\.environ|GITHUB_TOKEN|GH_TOKEN|_API_KEY|AWS_SECRET", re.M)),
]
URL = re.compile(r"\bhttps?://([A-Za-z0-9.-]+)")
DOMAIN = pack.DOMAIN


class Refused(Exception):
    pass


def unpack(data):
    """{path: (executable, bytes)} from an archive pack.py wrote."""
    if not data.startswith(DOMAIN):
        raise Refused("not a skill archive")
    files, at = {}, len(DOMAIN)
    try:
        while at < len(data):
            (n,) = struct.unpack_from(">I", data, at)
            path = data[at + 4:at + 4 + n].decode()
            at += 4 + n
            executable = data[at] == 1
            (size,) = struct.unpack_from(">Q", data, at + 1)
            files[path] = (executable, data[at + 9:at + 9 + size])
            at += 9 + size
    except (struct.error, IndexError, UnicodeDecodeError):
        raise Refused("a truncated skill archive")
    if at != len(data):
        raise Refused("a truncated skill archive")
    return files


def asks(files):
    """What the skill asks for, {field: set}, or Refused if it is not a capabilities document."""
    if "capabilities.json" not in files:
        return {f: set() for f in FIELDS}
    try:
        doc = json.loads(files["capabilities.json"][1])
    except ValueError:
        raise Refused("capabilities.json is not JSON")
    if not isinstance(doc, dict) or doc.get("version") != 1 or set(doc) - {"version", *FIELDS}:
        raise Refused("capabilities.json is not a capabilities document of version 1")
    out = {}
    for field in FIELDS:
        names = doc.get(field, [])
        if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
            raise Refused(f"capabilities.json: {field} is not a list of names")
        out[field] = set(names)
    return out


def in_vocabulary(field, name):
    return {
        "actions": name in ACTIONS,
        "egress_hosts": bool(HOST.match(name)) and not name.rsplit(".", 1)[-1].isdigit(),
        "tools": bool(TOOL.match(name)),
        "data_flows": name in FLOWS,
    }[field]


def is_script(path, executable, data):
    return executable or path.endswith((".sh", ".bash", ".py")) or data.startswith(b"#!")


def static(files, wanted):
    """[(rule, path)] the static rules find."""
    found = []
    for field, names in wanted.items():
        for name in sorted(names):
            if not in_vocabulary(field, name):
                found.append(("capability.unknown", "capabilities.json"))
            elif field == "actions" and name in NEVER:
                found.append(("capability.never", "capabilities.json"))
    for path, (executable, data) in sorted(files.items()):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            found.append(("file.binary", path))
            continue
        if "\0" in text:
            found.append(("file.binary", path))
            continue
        for host in URL.findall(text):
            if host.lower() not in wanted["egress_hosts"]:
                found.append(("url.undeclared", path))
                break
        if not is_script(path, executable, data):
            continue
        if NETWORK.search(text) and not wanted["egress_hosts"]:
            found.append(("network.undeclared", path))
        for rule, _, pattern in STATIC:
            if pattern.search(text):
                found.append((rule, path))
    return found


def shellcheck(files, required):
    """[(rule, path)] for each shell script shellcheck faults, at warning or worse."""
    scripts = {p: d for p, (x, d) in files.items()
               if p.endswith((".sh", ".bash")) or re.match(rb"#!\s*/(usr/)?bin/(env\s+)?(ba|da)?sh\b", d)}
    if not scripts:
        return []
    if shutil.which("shellcheck") is None:
        if required:
            return [("shellcheck.missing", p) for p in sorted(scripts)]
        return []
    found = []
    with tempfile.TemporaryDirectory() as tmp:
        for i, (path, data) in enumerate(sorted(scripts.items())):
            local = os.path.join(tmp, f"{i}.sh")
            with open(local, "wb") as f:
                f.write(data)
            run = subprocess.run(["shellcheck", "--severity=warning", "--shell=sh", local],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if run.returncode != 0:
                found.append(("shellcheck", path))
    return found


def load_items(root=ROOT):
    with open(os.path.join(root, "redteam", "items.json")) as f:
        items = json.load(f)
    return [(i["id"], re.compile(i["pattern"], re.I | re.M)) for i in items["items"]]


def redteam(files, items):
    """[(item, path)] for each red-team item a file matches."""
    found = []
    for path, (_, data) in sorted(files.items()):
        text = data.decode("utf-8", errors="replace")
        for item, pattern in items:
            if pattern.search(text):
                found.append((item, path))
    return found


def diff(new, old):
    """{field: names added} by `new` over `old`."""
    return {f: sorted(new[f] - old[f]) for f in FIELDS if new[f] - old[f]}


def latest(archives):
    """{name: (version, asks)} of the newest archive of each skill in a directory, by file name order
    of version as build.py names them."""
    out = {}
    for name, version, files in archives:
        out[name] = (version, asks(files))
    return out


def read_dir(directory):
    """[(name, version, files)] for each .skill archive in `directory`, by file name."""
    if directory is None or not os.path.isdir(directory):
        return []
    out = []
    for entry in sorted(os.listdir(directory)):
        if not entry.endswith(".skill"):
            continue
        with open(os.path.join(directory, entry), "rb") as f:
            files = unpack(f.read())
        name = pack.name_of(files["SKILL.md"][1])
        version = entry[len(name) + 1:-len(".skill")] if entry.startswith(name + "-") else ""
        out.append((name, version, files))
    return out


def acknowledged(root=ROOT):
    path = os.path.join(root, "capability-changes.json")
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        doc = json.load(f)
    return {k: {f: set(v.get(f, [])) for f in FIELDS} for k, v in doc.items()}


def check(new_dir, old_dir=None, require_shellcheck=False, root=ROOT):
    """The evidence for each archive in `new_dir`, and whether all of it passed."""
    items = load_items(root)
    old = latest(read_dir(old_dir))
    acks = acknowledged(root)
    report, ok = [], True
    for name, version, files in read_dir(new_dir):
        digest = hashlib.sha256(pack.archive(files)).hexdigest()
        entry = {"skill": name, "version": version, "digest": digest}
        try:
            wanted = asks(files)
        except Refused:
            wanted = None
        entry["static"] = [{"rule": r, "path": p} for r, p in
                           ([("capability.malformed", "capabilities.json")] if wanted is None
                            else static(files, wanted) + shellcheck(files, require_shellcheck))]
        entry["redteam"] = [{"item": i, "path": p} for i, p in redteam(files, items)]
        before = old.get(name, (None, {f: set() for f in FIELDS}))
        added = diff(wanted, before[1]) if wanted is not None else {}
        ack = acks.get(f"{name} {version}", {f: set() for f in FIELDS})
        unacked = {f: n for f, ns in added.items() if (n := sorted(set(ns) - ack[f]))}
        entry["capabilities"] = {"against": before[0], "added": added, "unacknowledged": unacked}
        entry["passed"] = not entry["static"] and not entry["redteam"] and not unacked
        ok &= entry["passed"]
        report.append(entry)
    return report, ok


def markdown(report):
    lines = ["| skill | static analysis | red-team items | capability diff |", "| --- | --- | --- | --- |"]
    for e in report:
        st = ", ".join(f"{f['rule']} ({f['path']})" for f in e["static"]) or "pass"
        rt = ", ".join(f"{f['item']} ({f['path']})" for f in e["redteam"]) or "pass"
        caps = e["capabilities"]
        added = "; ".join(f"{f}: {', '.join(n)}" for f, n in caps["added"].items()) or "nothing added"
        if caps["unacknowledged"]:
            added += " (not in capability-changes.json)"
        lines.append(f"| {e['skill']} {e['version']} | {st} | {rt} | {added} vs {caps['against'] or 'no release'} |")
    return "\n".join(lines) + "\n"


def main(argv):
    args = argv[1:]
    report_path = None
    require = "--require-shellcheck" in args
    args = [a for a in args if a != "--require-shellcheck"]
    if "--report" in args:
        i = args.index("--report")
        report_path = args[i + 1]
        del args[i:i + 2]
    if len(args) not in (1, 2):
        print(__doc__.strip().splitlines()[-1].strip(), file=sys.stderr)
        return 2
    try:
        report, ok = check(args[0], args[1] if len(args) == 2 else None, require)
    except (Refused, pack.Refused, OSError, ValueError, KeyError) as e:
        print(f"evidence: {e}", file=sys.stderr)
        return 2
    table = markdown(report)
    print(table, end="")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write("## Evidence\n\n" + table)
    if report_path:
        with open(report_path, "x") as f:
            json.dump({"version": 1, "skills": report}, f, indent=1, sort_keys=True)
            f.write("\n")
    if not ok:
        print("evidence: a check failed, so nothing is published", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
