#!/usr/bin/env python3
"""
Cloudflare Transfer Tool
  Step 1: Analysis (htaccess, vhost configs)
  Step 2: Symlink discovery
  Step 3: Generate Cloudflare Worker index.js + deploy.sh
  Step 4: Deploy via Cloudflare API (no wrangler/Node.js required)
  Step 5: Verify redirects against old server and new Worker
  Step 6: Cloudflare setup (create R2 bucket + folders)
  Step 7: Sync content to R2 via rclone

Usage:
  python3 cf_transfer.py <journal_shortcut> [--json] [--generate] [--deploy]
                         [--verify] [--setup] [--sync]
  python3 cf_transfer.py acp               (interactive menu)

Environment variables required for --deploy / --setup / --sync:
  CF_ACCOUNT_ID               your Cloudflare account ID
  CF_API_TOKEN                API token with Workers:Edit + R2:Edit permissions
  CF_ZONE_ID_ARTICLES         zone ID for {sc}.copernicus.org
  CF_ZONE_ID_WEB              zone ID for the web/vhost domain
  CF_ZONE_ID_LEGACY           zone ID for the legacy/vhost domain
  CF_ZONE_ID_LEGACY_DISCUSS   zone ID for the optional legacy discuss domain
  CF_ZONE_ID                  backward-compatible fallback for articles only
"""

import sys
import re
import json
import os
import time
import io
import subprocess
import shutil
from pathlib import Path
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from urllib.parse import urlparse

# ── Configuration ─────────────────────────────────────────────────────────────

VERSION       = "1.3.0"

WEBROOT       = Path("/var/www")
SITES_ENABLED = Path("/etc/apache2/sites-enabled")
OUTPUT_BASE   = Path("./cf_worker_output")

KNOWN_ID_PREFIXES = {"C", "S"}

# Folder mapping: local subfolder name → R2 prefix
# Derived at runtime from shortcut; defined here for documentation.
# acp.copernicus.org → articles/
# acp_full           → web/
# acp                → legacy/
# acpd               → legacy_discuss/   (optional)
FOLDER_MAP_TEMPLATE = [
    ("{sc}.copernicus.org", "articles",       True),   # (local_name, r2_prefix, mandatory)
    ("{sc}_full",           "web",            True),
    ("{sc}",                "legacy",         True),
    ("{sc}d",               "legacy_discuss", False),  # optional
]

# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class SymlinkInfo:
    link_path:   str
    target_path: str
    resolved:    str | None
    kind:        str
    relative:    bool

@dataclass
class FolderInfo:
    name:               str
    path:               Path
    exists:             bool
    mandatory:          bool
    htaccess_redirects: list[dict]        = field(default_factory=list)
    htaccess_rewrites:  list[dict]        = field(default_factory=list)
    htaccess_raw:       list[str]         = field(default_factory=list)
    symlinks:           list[SymlinkInfo] = field(default_factory=list)

@dataclass
class VhostInfo:
    conf_file:     Path
    exists:        bool
    mandatory:     bool
    server_names:  list[str]  = field(default_factory=list)
    document_root: str | None = None
    redirects:     list[dict] = field(default_factory=list)
    rewrites:      list[dict] = field(default_factory=list)
    raw_lines:     list[str]  = field(default_factory=list)

@dataclass
class JournalAnalysis:
    shortcut:         str
    folders:          list[FolderInfo] = field(default_factory=list)
    vhosts:           list[VhostInfo]  = field(default_factory=list)
    errors:           list[str]        = field(default_factory=list)
    warnings:         list[str]        = field(default_factory=list)
    unknown_prefixes: list[str]        = field(default_factory=list)

# ── Regex patterns ────────────────────────────────────────────────────────────

RE_REDIRECT       = re.compile(r'^\s*Redirect\s+(\S+)\s+(\S+)\s+(\S+)',                 re.I)
RE_REDIRECT_MATCH = re.compile(r'^\s*RedirectMatch\s+(\S+)\s+(\S+)\s+(\S+)',            re.I)
RE_REWRITE_RULE   = re.compile(r'^\s*RewriteRule\s+(\S+)\s+(\S+)(?:\s+\[([^\]]*)\])?', re.I)
RE_REWRITE_COND   = re.compile(r'^\s*RewriteCond\s+(\S+)\s+(\S+)(?:\s+\[([^\]]*)\])?', re.I)
RE_REWRITE_ON     = re.compile(r'^\s*RewriteEngine\s+On',                                re.I)
RE_SERVER_NAME    = re.compile(r'^\s*ServerName\s+(\S+)',                                re.I)
RE_SERVER_ALIAS   = re.compile(r'^\s*ServerAlias\s+(.+)',                                re.I)
RE_DOC_ROOT       = re.compile(r'^\s*DocumentRoot\s+(\S+)',                              re.I)
RE_VHOST_REDIRECT = re.compile(r'^\s*Redirect(?:Match)?\s+(\S+)\s+(\S+)(?:\s+(\S+))?', re.I)
RE_COMMENT        = re.compile(r'^\s*#')
RE_BLANK          = re.compile(r'^\s*$')
RE_VHOST_OPEN  = re.compile(r'^\s*<VirtualHost\s+([^>]+)>',  re.I)
RE_VHOST_CLOSE = re.compile(r'^\s*</VirtualHost>',           re.I)

RE_MIRROR_NUMERIC = re.compile(
    r'^(?:\(\\d\+\)|\\d\+|\d+)/'         # one numeric segment
    r'(?:'
      r'(?:\(\\d\+\)|\\d\+|\d+)/'        # optional second
      r'(?:\(\\d\+\)|\\d\+|\d+)/)?'      # optional third
    r'(?:\(\.\*\)|\(\.\+\)|\(.*\))?$'
)
RE_ANY_LETTER_ID = re.compile(
    r'^[~^]?/?'
    r'(?:\(\\d\+\)|\\d\+|\d+)/'
    r'([A-Z])\d+/'
    r'(?:\(\.\+\))?$'
)

def _build_letter_id_re(prefixes: set[str]) -> re.Pattern:
    letter_class = "".join(sorted(prefixes))
    return re.compile(
        r'^[~^]?/?'
        rf'(?:\(\\d\+\)|\\d\+|\d+)/'
        rf'[{letter_class}]\d+/'
        r'(?:\(\.\+\))?$'
    )

RE_MIRROR_LETTER_ID = _build_letter_id_re(KNOWN_ID_PREFIXES)



def get_output_dir(shortcut: str) -> Path:
    """Return the per-journal output directory, e.g. ./cf_worker_output/acp/"""
    return OUTPUT_BASE / shortcut

# ── .htaccess parsing ─────────────────────────────────────────────────────────

def parse_htaccess(htaccess_path: Path) -> tuple[list[dict], list[dict], list[str]]:
    redirects     = []
    rewrites      = []
    raw_lines     = []
    pending_conds = []

    try:
        lines = htaccess_path.read_text(errors="replace").splitlines()
    except PermissionError:
        return [], [], [f"# ERROR: permission denied reading {htaccess_path}"]

    for line in lines:
        raw_lines.append(line)
        if RE_COMMENT.match(line) or RE_BLANK.match(line) or RE_REWRITE_ON.match(line):
            continue

        m = RE_REDIRECT.match(line)
        if m:
            redirects.append({"type": "Redirect", "status": m.group(1),
                               "from": m.group(2).strip('"').strip("'"),
                               "to":   m.group(3).strip('"').strip("'")})
            pending_conds = []
            continue

        m = RE_REDIRECT_MATCH.match(line)
        if m:
            redirects.append({"type": "RedirectMatch", "status": m.group(1),
                               "pattern": m.group(2).strip('"').strip("'"),
                               "to":      m.group(3).strip('"').strip("'")})
            pending_conds = []
            continue

        m = RE_REWRITE_COND.match(line)
        if m:
            pending_conds.append({"test_string": m.group(1), "condition": m.group(2),
                                   "flags": m.group(3) or ""})
            continue

        m = RE_REWRITE_RULE.match(line)
        if m:
            rewrites.append({"pattern": m.group(1), "substitution": m.group(2),
                              "flags": m.group(3) or "", "conditions": pending_conds})
            pending_conds = []
            continue

        pending_conds = []

    return redirects, rewrites, raw_lines


def parse_vhost_conf(conf_path: Path, mandatory: bool) -> VhostInfo:
    info = VhostInfo(conf_file=conf_path, exists=conf_path.is_file(), mandatory=mandatory)
    if not info.exists:
        return info

    try:
        lines = conf_path.read_text(errors="replace").splitlines()
    except PermissionError:
        info.raw_lines = [f"# ERROR: permission denied reading {conf_path}"]
        return info

    pending_conds = []
    in_vhost      = False
    skip_block    = False   # True while inside a port-80 block

    for line in lines:
        info.raw_lines.append(line)

        # ── VirtualHost block open ────────────────────────────────────────────
        m = RE_VHOST_OPEN.match(line)
        if m:
            in_vhost   = True
            addr       = m.group(1).strip()          # e.g. "*:80" or "*:443"
            # Skip blocks that are purely HTTP (port 80) — they only contain
            # a redirect to HTTPS and are irrelevant to the Cloudflare migration.
            skip_block = addr.endswith(":80") or addr == "*:80"
            continue

        # ── VirtualHost block close ───────────────────────────────────────────
        if RE_VHOST_CLOSE.match(line):
            in_vhost   = False
            skip_block = False
            continue

        # ── Skip entire port-80 block ─────────────────────────────────────────
        if skip_block:
            continue

        # ── Parse directives inside port-443 (or unblocked) sections ─────────
        if RE_COMMENT.match(line) or RE_BLANK.match(line) or RE_REWRITE_ON.match(line):
            continue

        m = RE_SERVER_NAME.match(line)
        if m: info.server_names.append(m.group(1)); continue

        m = RE_SERVER_ALIAS.match(line)
        if m: info.server_names.extend(m.group(1).split()); continue

        m = RE_DOC_ROOT.match(line)
        if m: info.document_root = m.group(1); continue

        m = RE_REWRITE_COND.match(line)
        if m:
            pending_conds.append({"test_string": m.group(1), "condition": m.group(2),
                                   "flags": m.group(3) or ""})
            continue

        m = RE_REWRITE_RULE.match(line)
        if m:
            info.rewrites.append({"pattern": m.group(1), "substitution": m.group(2),
                                   "flags": m.group(3) or "", "conditions": pending_conds})
            pending_conds = []
            continue

        m = RE_REDIRECT_MATCH.match(line)
        if m:
            info.redirects.append({"type": "RedirectMatch", "status": m.group(1),
                                    "pattern": m.group(2).strip('"').strip("'"),
                                    "to":      m.group(3).strip('"').strip("'")})
            pending_conds = []
            continue

        m = RE_VHOST_REDIRECT.match(line)
        if m:
            info.redirects.append({"type": "Redirect", "status": m.group(1),
                                    "from": m.group(2).strip('"').strip("'"), "to": (m.group(3) or "").strip('"').strip("'")})
            pending_conds = []
            continue

        pending_conds = []

    return info
    
# ── Step 2: Symlink discovery ─────────────────────────────────────────────────

def categorise_symlink(link_path: Path, raw_target: str) -> SymlinkInfo:
    is_relative = not os.path.isabs(raw_target)
    try:
        resolved = str(link_path.parent / raw_target) if is_relative else raw_target
        resolved = str(Path(resolved).resolve())
    except Exception:
        resolved = None

    if resolved is None or not Path(resolved).exists():
        return SymlinkInfo(link_path=str(link_path), target_path=raw_target,
                           resolved=resolved, kind="broken", relative=is_relative)

    resolved_path = Path(resolved)
    try:
        resolved_path.relative_to(WEBROOT)
        inside_webroot = True
    except ValueError:
        inside_webroot = False

    kind = "external"   if not inside_webroot      else \
           "dir_remap"  if resolved_path.is_dir()  else "file_alias"

    return SymlinkInfo(link_path=str(link_path), target_path=raw_target,
                       resolved=resolved, kind=kind, relative=is_relative)


def discover_symlinks(folder: FolderInfo) -> list[SymlinkInfo]:
    symlinks = []
    try:
        for entry in folder.path.rglob("*"):
            if entry.is_symlink():
                symlinks.append(categorise_symlink(entry, os.readlink(entry)))
    except PermissionError:
        pass
    return symlinks


def symlink_summary(symlinks: list[SymlinkInfo]) -> dict[str, list[SymlinkInfo]]:
    groups: dict[str, list[SymlinkInfo]] = defaultdict(list)
    for s in symlinks:
        groups[s.kind].append(s)
    return dict(groups)

# ── Discovery ─────────────────────────────────────────────────────────────────

def discover_folders(shortcut: str) -> list[FolderInfo]:
    candidates = [
        (shortcut,                     True),
        (f"{shortcut}_full",           True),
        (f"{shortcut}.copernicus.org", True),
        (f"{shortcut}d",               False),
    ]
    folders = []
    for name, mandatory in candidates:
        path   = WEBROOT / name
        folder = FolderInfo(name=name, path=path, exists=path.is_dir(), mandatory=mandatory)
        if folder.exists:
            htaccess = path / ".htaccess"
            if htaccess.is_file():
                folder.htaccess_redirects, folder.htaccess_rewrites, folder.htaccess_raw = \
                    parse_htaccess(htaccess)
            folder.symlinks = discover_symlinks(folder)
        folders.append(folder)
    return folders


def discover_vhosts(shortcut: str) -> list[VhostInfo]:
    candidates = [
        (f"{shortcut}.conf",      False),   # missing = warning only
        (f"{shortcut}_full.conf", False),   # missing = warning only
        (f"{shortcut}d.conf",     False),   # optional
    ]
    return [parse_vhost_conf(SITES_ENABLED / name, mandatory)
            for name, mandatory in candidates]


def get_folder_map(analysis: JournalAnalysis) -> list[tuple[str, str, bool]]:
    """
    Return the active folder map for this journal:
    [(local_folder_name, r2_prefix, mandatory), ...]
    Optional entry (acpd → legacy_discuss) only included if folder exists.
    """
    sc = analysis.shortcut
    result = []
    for tpl_name, r2_prefix, mandatory in FOLDER_MAP_TEMPLATE:
        local_name = tpl_name.replace("{sc}", sc)
        # Only include optional entries if the folder actually exists
        if not mandatory:
            folder_exists = any(
                f.name == local_name and f.exists for f in analysis.folders
            )
            if not folder_exists:
                continue
        result.append((local_name, r2_prefix, mandatory))
    return result

# ── Redirect classification ───────────────────────────────────────────────────

def get_letter_id_prefix(pattern: str) -> str | None:
    if not RE_MIRROR_LETTER_ID.match(pattern):
        return None
    clean = re.sub(r'^[~^]?/?', '', pattern)
    parts = clean.split('/')
    if len(parts) >= 2 and parts[1] and parts[1][0] in KNOWN_ID_PREFIXES:
        return parts[1][0]
    return None


def detect_unknown_prefix(pattern: str) -> str | None:
    m = RE_ANY_LETTER_ID.match(pattern)
    if m:
        letter = m.group(1)
        if letter not in KNOWN_ID_PREFIXES:
            return letter
    return None


def classify_redirects(redirects: list[dict]) -> dict:
    mirror_numeric   = []
    mirror_letter    = []
    irregular        = []
    unknown_prefixes = []

    for r in redirects:
        if r.get("type") != "RedirectMatch":
            irregular.append(r)
            continue
        pattern = r.get("pattern", "").strip('"').strip("'")
        # Normalise: strip anchors and leading slash for classification
        norm = pattern.lstrip("^").lstrip("/").rstrip("$")
        if RE_MIRROR_NUMERIC.match(norm):
            mirror_numeric.append({**r, "pattern": pattern})
        else:
            letter = get_letter_id_prefix(norm)
            if letter:
                mirror_letter.append({**r, "pattern": pattern, "prefix": letter})
            else:
                unknown = detect_unknown_prefix(norm)
                if unknown and unknown not in unknown_prefixes:
                    unknown_prefixes.append(unknown)
                irregular.append({**r, "pattern": pattern})

    return {"mirror_numeric":   mirror_numeric,
            "mirror_letter":    mirror_letter,
            "irregular":        irregular,
            "unknown_prefixes": unknown_prefixes}


def group_mirror_rules(rules: list[dict]) -> dict:
    groups = defaultdict(list)
    for r in rules:
        try:
            parsed    = urlparse(r["to"])
            prefix    = parsed.path.strip("/").split("/")[0]
            r2_prefix = r.get("r2_prefix", "")
            status    = int(r.get("status", 301))
            key       = (f"{parsed.scheme}://{parsed.netloc}", prefix, r2_prefix, status)
        except Exception:
            key = ("unknown", "unknown", "", int(r.get("status", 301)))
        groups[key].append(r)
    return dict(groups)


def group_letter_rules_by_prefix(mirror_letter: list[dict]) -> dict:
    groups = defaultdict(list)
    for r in mirror_letter:
        try:
            parsed    = urlparse(r["to"])
            prefix    = parsed.path.strip("/").split("/")[0]
            r2_prefix = r.get("r2_prefix", "")
            status    = int(r.get("status", 301))
            key       = (f"{parsed.scheme}://{parsed.netloc}", prefix, r["prefix"], r2_prefix, status)
        except Exception:
            key = ("unknown", "unknown", r.get("prefix", "?"), "", int(r.get("status", 301)))
        groups[key].append(r)
    return dict(groups)


def collapsed_rules_text_numeric(domain: str, prefix: str) -> list[str]:
    base = f"{domain}/{prefix}"
    return [
        f"301  ~/(\\d+)/(\\d+)/(\\d+)/(.+)  →  {base}/$1/$2/$3/$4",
        f"301  ~/(\\d+)/(\\d+)/(\\d+)/      →  {base}/$1/$2/$3/",
        f"301  ~/(\\d+)/(\\d+)/             →  {base}/$1/$2/",
    ]


def collapsed_rules_text_letter(domain: str, prefix: str, letter: str) -> list[str]:
    base = f"{domain}/{prefix}"
    return [
        f"301  ~/(\\d+)/({letter}\\d+)/(.+)  →  {base}/$1/$2/$3",
        f"301  ~/(\\d+)/({letter}\\d+)/      →  {base}/$1/$2/",
    ]

# ── Step 3: Worker file generation ───────────────────────────────────────────

def collect_all_redirects(
    analysis: JournalAnalysis,
    prefix_origin: dict[str, str] | None = None,
) -> tuple[dict, dict, list[dict]]:
    seen:          set[str]   = set()
    all_numeric:   list[dict] = []
    all_letter:    list[dict] = []
    all_irregular: list[dict] = []

    folder_map = get_folder_map(analysis)

    # Build sources tagged with their R2 prefix
    # folders: match by local folder name
    sources: list[tuple[str, any]] = []
    for f in analysis.folders:
        if not f.exists:
            continue
        # find r2_prefix for this folder
        r2_prefix = next(
            (r2 for local, r2, _ in folder_map if local == f.name),
            None
        )
        if r2_prefix:
            sources.append((r2_prefix, f.htaccess_redirects))

    # vhosts: match by document_root basename
    for v in analysis.vhosts:
        if not v.exists or not v.document_root:
            continue
        local_name = Path(v.document_root).name
        r2_prefix = next(
            (r2 for local, r2, _ in folder_map if local == local_name),
            None
        )
        if r2_prefix:
            # Resolve relative 'to' URLs using the vhost's primary server name
            # Prefer the www. server name for canonical redirects
            _sn = next((s for s in v.server_names if s.startswith("www.")), v.server_names[0] if v.server_names else "")
            vhost_origin = f"https://{_sn}" if _sn else ""
            resolved = []
            for r in v.redirects:
                to = r.get("to", "")
                if to.startswith("/") and vhost_origin:
                    r = {**r, "to": vhost_origin + to}
                resolved.append(r)
            sources.append((r2_prefix, resolved))

    _po = prefix_origin or {}
    for r2_prefix, redirect_list in sources:
        classified = classify_redirects(redirect_list)
        host = _host_for_prefix(r2_prefix, _po)
        for r in classified["mirror_numeric"]:
            key = r2_prefix + "|" + r.get("pattern", "") + "|" + r.get("to", "")
            if key not in seen:
                seen.add(key)
                all_numeric.append({**r, "r2_prefix": r2_prefix, "host": host})
        for r in classified["mirror_letter"]:
            key = r2_prefix + "|" + r.get("pattern", "") + "|" + r.get("to", "")
            if key not in seen:
                seen.add(key)
                all_letter.append({**r, "r2_prefix": r2_prefix, "host": host})
        for r in classified["irregular"]:
            key = r2_prefix + "|" + r.get("pattern", r.get("from", "")) + "|" + r.get("to", "")
            if key not in seen:
                seen.add(key)
                all_irregular.append({**r, "r2_prefix": r2_prefix, "host": host})

    return (
        group_mirror_rules(all_numeric),
        group_letter_rules_by_prefix(all_letter),
        all_irregular,
    )


def collect_all_symlinks(analysis: JournalAnalysis) -> list[SymlinkInfo]:
    seen:   set[str]         = set()
    result: list[SymlinkInfo] = []
    for folder in analysis.folders:
        for s in folder.symlinks:
            if s.link_path not in seen:
                seen.add(s.link_path); result.append(s)
    return result


def get_r2_prefix_for_path(path: Path, folder_map: list[tuple[str, str, bool]]) -> str | None:
    """Return the R2 prefix for a given absolute path, or None if not mappable."""
    for local_name, r2_prefix, _ in folder_map:
        try:
            path.relative_to(WEBROOT / local_name)
            return r2_prefix
        except ValueError:
            continue
    return None


def build_symlink_map(
    symlinks:   list[SymlinkInfo],
    folder_map: list[tuple[str, str, bool]],
    vhosts:     list | None = None,
) -> tuple[dict[str, str], list[dict], dict[str, str]]:
    """
    Returns:
      mapping       — R2-key→R2-key aliases for same-prefix symlinks
      cross_redirects — 301 redirect rules for symlinks that cross R2 prefixes
      prefix_origin — prefix→origin base URL inferred from vhost server names
    """
    mapping:          dict[str, str] = {}
    cross_redirects:  list[dict]     = []
    root_r2_prefix = next(
        (r2 for local_name, r2, _ in folder_map if local_name.endswith(".copernicus.org")),
        "",
    )

    # Build prefix → canonical origin lookup from vhosts
    prefix_origin: dict[str, str] = {}
    for vh in (vhosts or []):
        if vh.exists and vh.document_root and vh.server_names:
            vp = get_r2_prefix_for_path(Path(vh.document_root) / "_dummy", folder_map)
            if vp and vp not in prefix_origin:
                sn = next((s for s in vh.server_names if s.startswith("www.")), vh.server_names[0])
                prefix_origin[vp] = f"https://{sn}"

    for s in symlinks:
        if s.kind not in ("file_alias", "dir_remap") or not s.resolved:
            continue
        try:
            link_abs   = Path(s.link_path)
            target_abs = Path(s.resolved)

            link_rel   = "/" + str(link_abs.relative_to(WEBROOT))
            target_rel = "/" + str(target_abs.relative_to(WEBROOT))

            link_prefix   = get_r2_prefix_for_path(link_abs,   folder_map)
            target_prefix = get_r2_prefix_for_path(target_abs, folder_map)

            if link_prefix is None or target_prefix is None:
                # Can't map either end — skip
                continue

            if link_prefix == target_prefix:
                # Same R2 prefix — serve as internal path alias
                # path relative to local folder already contains the subfolder (e.g. articles/)
                # so we just root it at WEBROOT/local_name, no prefix prepend needed
                local_name_link   = _local_name_for_prefix(link_prefix,   folder_map)
                local_name_target = _local_name_for_prefix(target_prefix, folder_map)
                link_rel = str(link_abs.relative_to(WEBROOT / local_name_link)).replace("\\", "/")
                target_rel = str(target_abs.relative_to(WEBROOT / local_name_target)).replace("\\", "/")
                link_r2_key = f"/{link_prefix}/{link_rel}".rstrip("/")
                target_r2_key = f"/{target_prefix}/{target_rel}".rstrip("/")
                mapping[link_r2_key] = target_r2_key
            else:
                local_name_link   = _local_name_for_prefix(link_prefix,   folder_map)
                local_name_target = _local_name_for_prefix(target_prefix, folder_map)
                link_r2_path   = "/" + str(link_abs.relative_to(WEBROOT / local_name_link))
                target_r2_path = "/" + str(target_abs.relative_to(WEBROOT / local_name_target))
                target_origin = prefix_origin.get(target_prefix, "")
                target_url    = target_origin + target_r2_path if target_origin else target_r2_path
                cross_redirects.append({
                    "type":   "exact",
                    "scope":  None if link_prefix == root_r2_prefix else f"/{link_prefix}/",
                    "from":   link_r2_path,
                    "to":     target_url,
                    "status": 301,
                })

        except ValueError:
            pass

    return mapping, cross_redirects, prefix_origin


def infer_prefix_origin(
    analysis: JournalAnalysis,
    folder_map: list[tuple[str, str, bool]],
) -> dict[str, str]:
    """Infer prefix → origin base URL for all active prefixes."""
    _, _, prefix_origin = build_symlink_map([], folder_map, vhosts=analysis.vhosts)
    for local_name, r2_prefix, _ in folder_map:
        if r2_prefix not in prefix_origin:
            if "." in local_name:
                prefix_origin[r2_prefix] = f"https://{local_name}"
            else:
                prefix_origin[r2_prefix] = f"https://{analysis.shortcut}.copernicus.org"
    return prefix_origin


def collect_host_to_r2_prefix(
    analysis: JournalAnalysis,
    folder_map: list[tuple[str, str, bool]],
    prefix_origin: dict[str, str],
) -> dict[str, str]:
    """Collect all known hostnames per R2 prefix, including vhost aliases."""
    host_to_r2_prefix: dict[str, str] = {}
    for r2_prefix, origin_url in prefix_origin.items():
        host = urlparse(origin_url).hostname
        if host:
            host_to_r2_prefix[host] = r2_prefix

    for vh in analysis.vhosts:
        if not (vh.exists and vh.document_root and vh.server_names):
            continue
        vp = get_r2_prefix_for_path(Path(vh.document_root) / "_dummy", folder_map)
        if not vp:
            continue
        for server_name in vh.server_names:
            host_to_r2_prefix[server_name] = vp

    return host_to_r2_prefix


def _local_name_for_prefix(r2_prefix: str,
                            folder_map: list[tuple[str, str, bool]]) -> str:
    """Return the local folder name for a given R2 prefix."""
    for local_name, prefix, _ in folder_map:
        if prefix == r2_prefix:
            return local_name
    return r2_prefix


def _host_for_prefix(r2_prefix: str, prefix_origin: dict[str, str]) -> str:
    """Return the bare hostname for a given R2 prefix, or empty string if unknown."""
    url = prefix_origin.get(r2_prefix, "")
    return url.removeprefix("https://").removeprefix("http://").rstrip("/")


def collect_unmigrated_rewrite_rules(analysis: JournalAnalysis) -> list[str]:
    lines: list[str] = []
    for folder in analysis.folders:
        for rw in folder.htaccess_rewrites:
            flags = f" [{rw['flags']}]" if rw.get("flags") else ""
            for cond in rw.get("conditions", []):
                cflags = f" [{cond['flags']}]" if cond.get("flags") else ""
                lines.append(
                    f"{folder.name} (.htaccess): RewriteCond {cond['test_string']} {cond['condition']}{cflags}"
                )
            lines.append(
                f"{folder.name} (.htaccess): RewriteRule {rw['pattern']} {rw['substitution']}{flags}"
            )
    for vhost in analysis.vhosts:
        for rw in vhost.rewrites:
            flags = f" [{rw['flags']}]" if rw.get("flags") else ""
            for cond in rw.get("conditions", []):
                cflags = f" [{cond['flags']}]" if cond.get("flags") else ""
                lines.append(
                    f"{vhost.conf_file.name}: RewriteCond {cond['test_string']} {cond['condition']}{cflags}"
                )
            lines.append(
                f"{vhost.conf_file.name}: RewriteRule {rw['pattern']} {rw['substitution']}{flags}"
            )
    return lines


def generate_irregular_redirect_js(irregular: list[dict], root_r2_prefix: str = "") -> str:
    lines = []
    for r in irregular:
        if r.get("scope") is not None:
            scope = r.get("scope") or ""
        else:
            rp = r.get("r2_prefix")
            scope = "" if (not rp or rp == root_r2_prefix) else f"/{rp}/"
        scope_js = f'"{scope}"' if scope else "null"
        host = r.get("host", "")
        host_js = f'"{host}"' if host else "null"
        status   = int(r.get("status", 301))
        rtype    = r.get("type", "")

        if rtype == "RedirectMatch":
            # Apache RedirectMatch uses a regex pattern
            lines.append(
                f'  {{"type":"regex","scope":{scope_js},"host":{host_js},"pattern":{json.dumps(r["pattern"])},'
                f'"to":{json.dumps(r["to"])},"status":{status}}},'
            )
        elif rtype in ("Redirect", "exact"):
            # Apache Redirect uses an exact path match
            lines.append(
                f'  {{"type":"exact","scope":{scope_js},"host":{host_js},"from":{json.dumps(r.get("from",""))},'
                f'"to":{json.dumps(r["to"])},"status":{status}}},'
            )
        elif rtype == "regex":
            lines.append(
                f'  {{"type":"regex","scope":{scope_js},"host":{host_js},"pattern":{json.dumps(r["pattern"])},'
                f'"to":{json.dumps(r["to"])},"status":{status}}},'
            )
    return "\n".join(lines)


def generate_index_js(
    shortcut:       str,
    numeric_groups: dict,
    letter_groups:  dict,
    irregular:      list[dict],
    symlink_map:    dict[str, str],
    origin_map:     dict[str, str],
    folder_map:     list[tuple[str, str, bool]],
    symlink_shards: dict[str, dict[str, str]] | None = None,
    unmigrated_rewrites: list[str] | None = None,
    host_to_r2_prefix: dict[str, str] | None = None,
) -> str:
    sc = shortcut.upper()
    root_r2_prefix = next(
        (r2 for local_name, r2, _ in folder_map if local_name.endswith(".copernicus.org")),
        folder_map[0][1] if folder_map else "",
    )

    redirect_rules_lines = []
    for (domain, prefix, r2_prefix, status), entries in numeric_groups.items():
        base  = f"{domain}/{prefix}"
        scope = "null" if r2_prefix == root_r2_prefix else f"'/{r2_prefix}/'"
        scope_label = "/" if scope == "null" else f"/{r2_prefix}/"
        host = _host_for_prefix(r2_prefix, origin_map)
        host_js = f"'{host}'" if host else "null"
        redirect_rules_lines += [
            f"  // {len(entries)} rules (numeric) → {base}  [scope: {scope_label}]",
            "  [" + scope + ", /^\\/(\\d+)\\/(\\d+)\\/(\\d+)\\/(.+)$/, '" + base + f"/$1/$2/$3/$4', {status}, {host_js}],",
            "  [" + scope + ", /^\\/(\\d+)\\/(\\d+)\\/(\\d+)\\/$/, '" + base + f"/$1/$2/$3/', {status}, {host_js}],",
            "  [" + scope + ", /^\\/(\\d+)\\/(\\d+)\\/$/, '" + base + f"/$1/$2/', {status}, {host_js}],",
        ]
    for (domain, prefix, letter, r2_prefix, status), entries in letter_groups.items():
        base  = f"{domain}/{prefix}"
        scope = "null" if r2_prefix == root_r2_prefix else f"'/{r2_prefix}/'"
        scope_label = "/" if scope == "null" else f"/{r2_prefix}/"
        host = _host_for_prefix(r2_prefix, origin_map)
        host_js = f"'{host}'" if host else "null"
        redirect_rules_lines += [
            f"  // {len(entries)} rules ({letter}-id) → {base}  [scope: {scope_label}]",
            f"  [{scope}, /^\\/[\\d]+\\/({letter}[\\d]+)\\/(.+)$/, '{base}/$1/$2', {status}, {host_js}],",
            f"  [{scope}, /^\\/[\\d]+\\/({letter}[\\d]+)\\/$/, '{base}/$1/', {status}, {host_js}],",
        ]

    redirect_rules_block = "\n".join(redirect_rules_lines)
    irregular_block      = generate_irregular_redirect_js(irregular, root_r2_prefix=root_r2_prefix)

    # Build the JS ORIGIN_MAP literal:  { 'articles': 'https://...', ... }
    origin_map_js = ", ".join(
        f"'{r2_prefix}': '{origin_url.rstrip('/')}'"
        for r2_prefix, origin_url in origin_map.items()
    )
    # Fallback: use the articles/ origin, or first entry, or a safe default
    _fallback_url = (
        origin_map.get("articles") or
        next(iter(origin_map.values()), f"https://{shortcut}.copernicus.org")
    )
    fallback_origin = _fallback_url.rstrip("/")
    if host_to_r2_prefix is None:
        host_to_r2_prefix = {
            host: r2_prefix
            for r2_prefix, origin_url in origin_map.items()
            for host in [urlparse(origin_url).hostname]
            if host
        }
    host_to_r2_prefix_js = ", ".join(
        f"'{host}': '{r2_prefix}'"
        for host, r2_prefix in sorted(host_to_r2_prefix.items())
    )

    # Build PATH_TO_R2_PREFIX JS literal: { '': 'articles', 'supplements': 'supplements', ... }
    path_to_r2_prefix_js = ", ".join(
        f"'': '{r2_prefix}'" if local_name.endswith(".copernicus.org")
        else f"'{r2_prefix}': '{r2_prefix}'"
        for local_name, r2_prefix, _ in folder_map
    )

    # Build R2 prefix routing comment for the Worker
    prefix_routing = "\n".join(
        f"   *   /{r2_prefix}/  ←  /var/www/{local_name}/"
        for local_name, r2_prefix, _ in folder_map
    )

    rewrite_comment = ""
    if unmigrated_rewrites:
        rewrite_lines = "\n".join(
            f" *   - {line}" for line in unmigrated_rewrites
        )
        rewrite_comment = (
            "\n/*\n"
            " * WARNING: Apache RewriteRule/RewriteCond directives were detected but not migrated.\n"
            " * These rules require manual Worker implementation if still needed:\n"
            f"{rewrite_lines}\n"
            " */\n"
        )

    return f"""\
/**
 * Cloudflare Worker — {sc} journal
 * Auto-generated by cf_transfer.py
 *
 * R2 bucket layout:
{prefix_routing}
 */
{rewrite_comment}
const STRICT_R2 = false;

const REDIRECT_RULES = [
{redirect_rules_block}
];

const IRREGULAR_REDIRECTS = [
{irregular_block}
];

// Symlink map is loaded from R2 shards (_symlinks/{{prefix}}.json).
// The embedded default is intentionally empty — large journals cannot fit
// full symlink maps inside the Worker script size limits.
const SYMLINK_MAP_DEFAULT = {{}};

// Maps URL path prefix → R2 bucket prefix (generated from folder_map)
const PATH_TO_R2_PREFIX = {{{path_to_r2_prefix_js}}};
const HOST_TO_R2_PREFIX = {{{host_to_r2_prefix_js}}};
const NON_ROOT_PREFIXES = Object.keys(PATH_TO_R2_PREFIX).filter(p => p !== '');

function urlPathToR2Key(pathname, hostname) {{
  let bare = pathname.slice(1);
  for (const [urlPrefix] of Object.entries(PATH_TO_R2_PREFIX)) {{
    if (urlPrefix === '') continue;
    if (bare === urlPrefix || bare.startsWith(urlPrefix + '/')) {{
      return bare;
    }}
  }}
  const r2Prefix = (hostname && HOST_TO_R2_PREFIX[hostname]) || PATH_TO_R2_PREFIX[''] || '';
  if (r2Prefix) bare = r2Prefix + '/' + bare;
  return bare;
}}

function withDirectoryIndex(key) {{
  if (key.endsWith('/') || key === '') return key + 'index.html';
  if (!key.includes('.')) return key + '/index.html';
  return key;
}}

function keyToR2Prefix(key) {{
  const first = key.split('/')[0];
  if (NON_ROOT_PREFIXES.includes(first)) return first;
  return PATH_TO_R2_PREFIX[''] || first;
}}

const shardCache = {{}};
const SYMLINK_CACHE_TTL = 300_000;

async function getSymlinkShard(env, r2prefix) {{
  const now = Date.now();
  const cached = shardCache[r2prefix];
  if (cached && now - cached.ts < SYMLINK_CACHE_TTL) return cached.map;
  try {{
    const obj = await env.R2_BUCKET.get(`_symlinks/${{r2prefix}}.json`);
    if (obj) {{
      const map = await obj.json();
      shardCache[r2prefix] = {{ map, ts: now }};
      return map;
    }}
  }} catch (_) {{}}
  shardCache[r2prefix] = {{ map: SYMLINK_MAP_DEFAULT, ts: now }};
  return SYMLINK_MAP_DEFAULT;
}}

const CONTENT_TYPES = {{
  html: 'text/html; charset=utf-8', htm:  'text/html; charset=utf-8',
  pdf:  'application/pdf',          css:  'text/css',
  js:   'application/javascript',   json: 'application/json',
  xml:  'application/xml',          txt:  'text/plain',
  png:  'image/png',                jpg:  'image/jpeg',
  jpeg: 'image/jpeg',               gif:  'image/gif',
  svg:  'image/svg+xml',            ico:  'image/x-icon',
}};

function getContentType(key) {{
  const ext = key.split('.').pop().toLowerCase();
  return CONTENT_TYPES[ext] ?? 'application/octet-stream';
}}

const FRAGMENT_CACHE     = new Map();
const FRAGMENT_CACHE_TTL = 60_000; // 60 seconds — fragment changes propagate within 1 min

async function resolveSSI(html, env, r2prefix) {{
  const pat = /<!--#include\s+virtual="([^"]+)"\s*-->/g;
  const matches = [...html.matchAll(pat)];
  if (matches.length === 0) return html;

  // Fetch all unique fragments in parallel
  const needed = [...new Set(matches.map(m => m[1]))];
  await Promise.all(needed.map(async (virtualPath) => {{
    const cacheKey = r2prefix + ':' + virtualPath;
    const cached = FRAGMENT_CACHE.get(cacheKey);
    if (cached && Date.now() - cached.ts < FRAGMENT_CACHE_TTL) return;
    const fragKey = r2prefix + '/' + virtualPath.replace(/^\//, '');
    const obj = await env.R2_BUCKET.get(fragKey);
    const content = obj ? await obj.text() : `<!-- SSI missing: ${{virtualPath}} -->`;
    FRAGMENT_CACHE.set(cacheKey, {{ content, ts: Date.now() }});
  }}));

  return html.replace(pat, (match, virtualPath) => {{
    const cacheKey = r2prefix + ':' + virtualPath;
    const content = FRAGMENT_CACHE.get(cacheKey)?.content;
    return content !== undefined ? content : '<!-- SSI missing: ' + virtualPath + ' -->';
  }});
}}

export default {{
  async fetch(request, env) {{
    const url      = new URL(request.url);
    let   pathname = url.pathname;

    // 1. Collapsed redirect rules  [scope, pattern, template, status, host]
    for (const [scope, pattern, template, status, host] of REDIRECT_RULES) {{
      if (host && url.hostname !== host) continue;
      if (scope && !pathname.startsWith(scope)) continue;
      const scoped1 = scope ? pathname.slice(scope.length - 1) : pathname;
      const m = scoped1.match(pattern);
      if (m) {{
        const target = template.replace(/\\$(\\d+)/g, (_, i) => m[Number(i)]);
        return Response.redirect(target, status);
      }}
    }}

    // 2. Irregular redirects
    for (const rule of IRREGULAR_REDIRECTS) {{
      if (rule.host && url.hostname !== rule.host) continue;
      if (rule.scope && !pathname.startsWith(rule.scope)) continue;
      // Strip the scope prefix so Apache patterns (^/foo) match correctly
      const scoped = rule.scope ? pathname.slice(rule.scope.length - 1) : pathname;
      if (rule.type === 'exact' && scoped === rule.from)
        return Response.redirect(rule.to, rule.status);
      if (rule.type === 'regex') {{
        const m = scoped.match(new RegExp(rule.pattern));
        if (m) {{
          const target = rule.to.replace(/\\$(\\d+)/g, (_, i) => m[Number(i)]);
          return Response.redirect(target, rule.status);
        }}
      }}
    }}

    // 3. Resolve symlinks
    let key = urlPathToR2Key(pathname, url.hostname);
    const requestPrefix = keyToR2Prefix(key);
    const symlinkShard = await getSymlinkShard(env, requestPrefix);
    const symlinkTarget = symlinkShard['/' + key];
    if (symlinkTarget) key = symlinkTarget.replace(/^\/+/, '');
    key = withDirectoryIndex(key);

    // 5. Try R2
    const object = await env.R2_BUCKET.get(key);
    if (object) {{
      const ct = getContentType(key);
      if (ct.startsWith('text/html')) {{
        let body = await object.text();
        const r2prefix = keyToR2Prefix(key);
        body = await resolveSSI(body, env, r2prefix);
        return new Response(body, {{
          headers: {{
            'Content-Type':  ct,
            'Cache-Control': 'public, max-age=86400',
            'ETag':          object.httpEtag,
            'X-R2-Hit':      '1',
          }},
        }});
      }}
      return new Response(object.body, {{
        headers: {{
          'Content-Type':  ct,
          'Cache-Control': 'public, max-age=86400',
          'ETag':          object.httpEtag,
          'X-R2-Hit':      '1',
        }},
      }});
    }}

    // 6. Fallback to origin — route by R2 prefix
    const ORIGIN_MAP = {{{origin_map_js}}};
    if (STRICT_R2) return new Response('Not Found', {{ status: 404 }});
    const hostname = url.hostname;
    const _r2pfx = HOST_TO_R2_PREFIX[hostname] ?? keyToR2Prefix(key);
    const _originBase = ORIGIN_MAP[_r2pfx] ?? '{fallback_origin}';
    const originUrl = `${{_originBase}}${{url.pathname}}${{url.search}}`;
    try {{
      const originResp = await fetch(originUrl, {{
        headers: {{ 'X-Forwarded-From': 'cf-worker' }},
      }});
      const hdrs = new Headers(originResp.headers);
      hdrs.set('X-Origin-Fallback', '1');
      return new Response(originResp.body, {{
        status: originResp.status, headers: hdrs,
      }});
    }} catch (err) {{
      return new Response('Not Found', {{ status: 404 }});
    }}
  }},
}};
"""


def generate_deploy_sh(
    shortcut: str,
    custom_domain: str,
    bucket_name: str,
    origin_map: dict[str, str],
) -> str:
    script_name = f"{shortcut}-worker"
    route_specs = []
    for r2_prefix, origin_url in origin_map.items():
        domain = urlparse(origin_url).hostname
        if not domain:
            continue
        env_name = f"CF_ZONE_ID_{r2_prefix.upper().replace('-', '_')}"
        env_expr = f"${{{env_name}}}" if r2_prefix == "articles" else f"${{{env_name}:-}}"
        route_specs.append(f'  "{r2_prefix}|{domain}|{env_expr}"')
    route_specs_block = "\n".join(route_specs)
    return f"""\
#!/usr/bin/env bash
# deploy.sh — auto-generated by cf_transfer.py
set -euo pipefail
SCRIPT_NAME="{script_name}"
BUCKET_NAME="{bucket_name}"
CUSTOM_DOMAIN="{custom_domain}"
SCRIPT_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
: "${{CF_ACCOUNT_ID:?not set}}"
: "${{CF_API_TOKEN:?not set}}"
CF_ZONE_ID_ARTICLES="${{CF_ZONE_ID_ARTICLES:-${{CF_ZONE_ID:-}}}}"
: "${{CF_ZONE_ID_ARTICLES:?not set}}"
CF_API="https://api.cloudflare.com/client/v4"
AUTH="Authorization: Bearer ${{CF_API_TOKEN}}"
ROUTE_SPECS=(
{route_specs_block}
)
shopt -s nullglob
SHARD_FILES=("${{SCRIPT_DIR}}/symlinks/"*.json)
shopt -u nullglob
ROUTE_COUNT=0
for spec in "${{ROUTE_SPECS[@]}}"; do
  IFS='|' read -r _prefix _domain _zone_id <<< "${{spec}}"
  [ -n "${{_zone_id}}" ] && ROUTE_COUNT=$((ROUTE_COUNT + 1))
done
SYMLINK_UPLOAD_STEPS=0
if [ "${{#SHARD_FILES[@]}}" -gt 0 ]; then
  SYMLINK_UPLOAD_STEPS=${{#SHARD_FILES[@]}}
elif [ -f "${{SCRIPT_DIR}}/symlinks.json" ]; then
  SYMLINK_UPLOAD_STEPS=1
fi
TOTAL_STEPS=$((2 + ROUTE_COUNT + SYMLINK_UPLOAD_STEPS))
STEP=1

echo "==> [${{STEP}}/${{TOTAL_STEPS}}] Uploading Worker..."
METADATA='{{"main_module":"worker.js","bindings":[{{"type":"r2_bucket","name":"R2_BUCKET","bucket_name":"{bucket_name}"}}],"compatibility_date":"2024-01-01"}}'
RESP=$(curl -s -X PUT "${{CF_API}}/accounts/${{CF_ACCOUNT_ID}}/workers/scripts/${{SCRIPT_NAME}}" \
  -H "${{AUTH}}" \
  -F "metadata=${{METADATA}};type=application/json" \
  -F "worker.js=@${{SCRIPT_DIR}}/index.js;type=application/javascript+module")
echo "${{RESP}}" | grep -q '"success":true' || {{ echo "FAILED: ${{RESP}}"; exit 1; }}
echo "    OK"
STEP=$((STEP + 1))

for spec in "${{ROUTE_SPECS[@]}}"; do
  IFS='|' read -r PREFIX DOMAIN ZONE_ID <<< "${{spec}}"
  [ -n "${{ZONE_ID}}" ] || continue
  echo "==> [${{STEP}}/${{TOTAL_STEPS}}] Setting route ${{DOMAIN}}/*..."
  EXISTING_ID=$(curl -s "${{CF_API}}/zones/${{ZONE_ID}}/workers/routes" -H "${{AUTH}}" | \
    python3 -c "import sys,json;routes=json.load(sys.stdin).get('result',[]); [print(r['id']) for r in routes if r.get('pattern')=='${{DOMAIN}}/*']" 2>/dev/null||true)
  if [ -n "${{EXISTING_ID}}" ]; then
    curl -s -X PUT "${{CF_API}}/zones/${{ZONE_ID}}/workers/routes/${{EXISTING_ID}}" \
      -H "${{AUTH}}" -H "Content-Type: application/json" \
      --data '{{"pattern":"'"${{DOMAIN}}"'/*","script":"{script_name}"}}' >/dev/null
  else
    curl -s -X POST "${{CF_API}}/zones/${{ZONE_ID}}/workers/routes" \
      -H "${{AUTH}}" -H "Content-Type: application/json" \
      --data '{{"pattern":"'"${{DOMAIN}}"'/*","script":"{script_name}"}}' >/dev/null
  fi
  echo "    OK"
  STEP=$((STEP + 1))
done

if [ "${{#SHARD_FILES[@]}}" -gt 0 ]; then
  for shard in "${{SHARD_FILES[@]}}"; do
    prefix=$(basename "$shard" .json)
    echo "==> [${{STEP}}/${{TOTAL_STEPS}}] Uploading symlinks/${{prefix}}.json..."
    RESP=$(curl -s -w "\n%{{http_code}}" -X PUT \
      "${{CF_API}}/accounts/${{CF_ACCOUNT_ID}}/r2/buckets/${{BUCKET_NAME}}/objects/_symlinks/${{prefix}}.json" \
      -H "${{AUTH}}" -H "Content-Type: application/json" \
      --data-binary "@${{shard}}")
    HTTP_CODE=$(echo "$RESP" | tail -1)
    if [ "$HTTP_CODE" -lt 200 ] || [ "$HTTP_CODE" -ge 300 ]; then
      echo "FAILED uploading ${{prefix}} shard (HTTP $HTTP_CODE)"; exit 1
    fi
    echo "    OK: ${{prefix}}"
    STEP=$((STEP + 1))
  done
elif [ -f "${{SCRIPT_DIR}}/symlinks.json" ]; then
  echo "==> [${{STEP}}/${{TOTAL_STEPS}}] Uploading symlinks.json..."
  RESP=$(curl -s -w "\n%{{http_code}}" -X PUT "${{CF_API}}/accounts/${{CF_ACCOUNT_ID}}/r2/buckets/${{BUCKET_NAME}}/objects/_symlinks.json" \
    -H "${{AUTH}}" -H "Content-Type: application/json" \
    --data-binary "@${{SCRIPT_DIR}}/symlinks.json")
  HTTP_CODE=$(echo "$RESP" | tail -1)
  if [ "$HTTP_CODE" -lt 200 ] || [ "$HTTP_CODE" -ge 300 ]; then
    echo "FAILED (HTTP $HTTP_CODE)"; exit 1
  fi
  echo "    OK"
  STEP=$((STEP + 1))
else
  echo "==> [${{STEP}}/${{TOTAL_STEPS}}] No symlink files found — skipping upload."
fi

echo "==> [${{STEP}}/${{TOTAL_STEPS}}] Smoke test..."
sleep 2
HTTP=$(curl -s -o /dev/null -w "%{{http_code}}" "https://${{CUSTOM_DOMAIN}}/" --max-time 10 || echo "000")
echo "    HTTP ${{HTTP}}"
echo "✓ Done."
"""


def generate_deploy_readme(
    shortcut: str,
    custom_domain: str,
    bucket_name: str,
    origin_map: dict[str, str],
) -> str:
    sc         = shortcut.upper()
    output_dir = get_output_dir(shortcut)    # ← was bare OUTPUT_DIR
    zone_lines = []
    for r2_prefix, origin_url in origin_map.items():
        domain = urlparse(origin_url).hostname or origin_url.removeprefix("https://")
        env_name = f"CF_ZONE_ID_{r2_prefix.upper().replace('-', '_')}"
        suffix = "  # required primary domain" if r2_prefix == "articles" else "  # optional"
        zone_lines.append(f"  export {env_name}=zzz    # {domain}{suffix}")
    zone_vars = "\n".join(zone_lines)
    return f"""\
# {sc} Cloudflare Worker — Deployment Guide

## Quick start (interactive menu)
  python3 cf_transfer.py {shortcut}

## Required env vars for deploy/setup/sync:
  export CF_ACCOUNT_ID=xxx
  export CF_API_TOKEN=yyy    # Workers:Edit + R2:Edit + R2:Write
{zone_vars}
  # Backward compatibility: CF_ZONE_ID still works for articles only.

## Manual curl deploy
  bash {output_dir}/deploy.sh

## DNS at Schlund/IONOS
  {custom_domain.split('.')[0]:<20} CNAME  {shortcut}-worker.YOUR-ACCOUNT.workers.dev
"""


# ── Step 3 orchestration ──────────────────────────────────────────────────────


def run_generate(analysis: JournalAnalysis) -> bool:
    sc         = analysis.shortcut
    OUTPUT_DIR = get_output_dir(sc)          # ← add this line at the top
    custom_domain = f"{sc}.copernicus.org"   # default — always correct for this project
    for v in analysis.vhosts:
        if v.exists and v.server_names:
            match = next(
                (n for n in v.server_names if "copernicus.org" in n),
                None
            )
            if match:
                custom_domain = match
                break
            # don't use legacy domains (sci-dril.net etc.) as custom_domain

    bucket_name = get_bucket_name(sc)
    folder_map   = get_folder_map(analysis)
    all_symlinks = collect_all_symlinks(analysis)
    symlink_map, cross_redirects, prefix_origin = build_symlink_map(all_symlinks, folder_map, vhosts=analysis.vhosts)
    prefix_origin.update({
        r2_prefix: origin_url
        for r2_prefix, origin_url in infer_prefix_origin(analysis, folder_map).items()
        if r2_prefix not in prefix_origin
    })
    host_to_r2_prefix = collect_host_to_r2_prefix(analysis, folder_map, prefix_origin)

    # Pass cross_redirects into generate_index_js alongside irregular redirects:
    numeric_groups, letter_groups, irregular = collect_all_redirects(analysis, prefix_origin=prefix_origin)
    for cr in cross_redirects:
        if "host" not in cr:
            cr["host"] = _host_for_prefix((cr.get("scope") or "").strip("/"), prefix_origin)
    irregular_all = irregular + cross_redirects   # ← merge cross-folder redirects in
    symlink_shards: dict[str, dict[str, str]] = defaultdict(dict)
    for link_key, target_val in symlink_map.items():
        parts = link_key.lstrip("/").split("/", 1)
        shard_prefix = parts[0] if parts and parts[0] else "articles"
        symlink_shards[shard_prefix][link_key] = target_val

    unmigrated_rewrites = collect_unmigrated_rewrite_rules(analysis)
    if unmigrated_rewrites:
        print("\n  ⚠ WARNING: RewriteRule/RewriteCond directives were detected but are not migrated automatically.")
        for line in unmigrated_rewrites:
            print(f"    - {line}")
        print("    These rules are listed in generated index.js for manual follow-up.\n")

    index_js = generate_index_js(
        sc, numeric_groups, letter_groups,
        irregular_all, symlink_map, prefix_origin, folder_map,
        symlink_shards=symlink_shards,
        unmigrated_rewrites=unmigrated_rewrites,
        host_to_r2_prefix=host_to_r2_prefix,
    )
    symlinks_json = json.dumps(symlink_map, indent=2)
    deploy_sh     = generate_deploy_sh(sc, custom_domain, bucket_name, prefix_origin)
    readme        = generate_deploy_readme(sc, custom_domain, bucket_name, prefix_origin)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUTPUT_DIR / "index.js"     ).write_text(index_js)
    (OUTPUT_DIR / "symlinks.json").write_text(symlinks_json)
    symlinks_dir = OUTPUT_DIR / "symlinks"
    symlinks_dir.mkdir(parents=True, exist_ok=True)
    for shard_prefix, shard_map in sorted(symlink_shards.items()):
        shard_path = symlinks_dir / f"{shard_prefix}.json"
        shard_path.write_text(json.dumps(shard_map, indent=2))
    deploy_sh_path = OUTPUT_DIR / "deploy.sh"
    deploy_sh_path.write_text(deploy_sh)
    deploy_sh_path.chmod(0o755)
    (OUTPUT_DIR / "DEPLOY.md"    ).write_text(readme)

    total_num = sum(len(e) for e in numeric_groups.values())
    total_let = sum(len(e) for e in letter_groups.values())
    broken    = [s for s in all_symlinks if s.kind == "broken"]
    extern    = [s for s in all_symlinks if s.kind == "external"]

    print(f"\n{'═' * 70}")
    print(f"  Step 3 — Generated Worker files  →  {OUTPUT_DIR}/")
    print(f"{'═' * 70}")
    print(f"  index.js       — Worker logic")
    print(f"  symlinks.json  — Symlink map")
    print(f"  symlinks/      — Sharded symlink maps ({len(symlink_shards)} shards)")
    for shard_prefix, shard_map in sorted(symlink_shards.items()):
        print(f"    {shard_prefix}.json  ({len(shard_map)} entries)")
    print(f"  deploy.sh      — curl-only deploy script")
    print(f"  DEPLOY.md      — Deployment guide")
    print()
    print(f"  R2 bucket layout:")
    for local_name, r2_prefix, mandatory in folder_map:
        tag = "" if mandatory else "  (optional)"
        print(f"    /{r2_prefix:<20} ←  /var/www/{local_name}/{tag}")
    print()
    print(f"  Redirect summary:")
    print(f"    Collapsed numeric : {total_num} → {3 * len(numeric_groups)} Worker rules")
    print(f"    Collapsed letter  : {total_let} → {2 * len(letter_groups)} Worker rules")
    print(f"    Irregular         : {len(irregular)}  (emitted individually)")
    print(f"  Symlink map entries : {len(symlink_map)}")
    if broken: print(f"  ⚠ Broken symlinks   : {len(broken)}")
    if extern: print(f"  ⚠ External symlinks : {len(extern)}")
    print(f"{'═' * 70}\n")
    return True

# ── Step 4: Deploy ────────────────────────────────────────────────────────────

def cf_api(method: str, path: str, token: str, **kwargs) -> dict:
    try:
        import requests
    except ImportError:
        print("ERROR: pip install requests"); sys.exit(1)
    url  = f"https://api.cloudflare.com/client/v4{path}"
    hdrs = {"Authorization": f"Bearer {token}"}
    resp = requests.request(method, url, headers=hdrs, **kwargs)
    try:    return resp.json()
    except: return {"success": False, "errors": [{"message": resp.text}]}


def check_response(data: dict, action: str) -> None:
    if data.get("success"):
        print("OK")
    else:
        print("FAILED")
        for e in data.get("errors", []):
            print(f"          ERROR: {e.get('message', e)}")
        raise SystemExit(f"Aborted at: {action}")


# ── Credential helpers ────────────────────────────────────────────────────────

# In-memory cache so we only ask once per session
_cf_credentials: dict[str, str] = {}

def _prompt_credential(name: str, description: str,
                        secret: bool = False,
                        required: bool = True) -> str:
    if name in _cf_credentials:
        return _cf_credentials[name]

    value = os.environ.get(name, "").strip()
    if value:
        _cf_credentials[name] = value
        return value

    import getpass
    print(f"\n  {name} not set.")
    print(f"  {description}")
    if secret:
        value = getpass.getpass(f"  Enter {name}: ").strip()
    else:
        value = input(f"  Enter {name}: ").strip()

    if not value and required:
        raise ValueError(f"{name} is required but was not provided.")

    if value:
        _cf_credentials[name] = value
    return value


def clear_credentials() -> None:
    """Clear cached credentials (e.g. if a token turns out to be invalid)."""
    _cf_credentials.clear()


def get_cf_account() -> tuple[str, str] | None:
    """Account ID + API token — for Setup and Sync."""
    try:
        account_id = _prompt_credential(
            "CF_ACCOUNT_ID",
            "Cloudflare Account ID (32 hex chars) — found at:\n"
            "  https://dash.cloudflare.com → right sidebar → Account ID\n"
            "  Will be passed to wrangler as CLOUDFLARE_ACCOUNT_ID",
            secret=False,
        )
        api_token = _prompt_credential(
            "CF_API_TOKEN",
            "Account API Token — found at:\n"
            "  https://dash.cloudflare.com → Account API Tokens\n"
            "  Needs: R2 Storage:Edit  (+ Worker Scripts:Edit for Deploy)\n"
            "  Will be passed to wrangler as CLOUDFLARE_API_TOKEN",
            secret=True,
        )
        return account_id, api_token
    except ValueError as e:
        print(f"\n  ERROR: {e}"); return None
    except (KeyboardInterrupt, EOFError):
        print("\n  Cancelled."); return None


def get_cf_env() -> tuple[str, str, str | None] | None:
    """Account ID + API token + optional Zone ID — for Deploy."""
    try:
        account_id = _prompt_credential(
            "CF_ACCOUNT_ID",
            "Your Cloudflare Account ID — found at:\n"
            "  https://dash.cloudflare.com → right sidebar → Account ID",
            secret=False,
        )
        api_token = _prompt_credential(
            "CF_API_TOKEN",
            "API token with Workers:Edit + R2:Edit permissions.",
            secret=True,
        )
        # Zone ID is optional — only needed to bind the Worker to a custom domain route.
        # Leave blank to deploy to <script>.YOUR-ACCOUNT.workers.dev only.
        zone_id = _prompt_credential(
            "CF_ZONE_ID",
            "Zone ID for your custom domain (optional — press Enter to skip).\n"
            "  Found at: https://dash.cloudflare.com → select domain → right sidebar\n"
            "  Leave blank to deploy to workers.dev only.",
            secret=False,
            required=False,
        )
        return account_id, api_token, zone_id or None
    except ValueError as e:
        print(f"\n  ERROR: {e}"); return None
    except (KeyboardInterrupt, EOFError):
        print("\n  Cancelled."); return None


def get_cf_zone_ids(
    folder_map: list[tuple[str, str, bool]],
    prefix_origin: dict[str, str],
) -> dict[str, str]:
    """Prompt for per-prefix zone IDs used to bind Worker routes."""
    zone_ids: dict[str, str] = {}
    for _, r2_prefix, _ in folder_map:
        env_name = f"CF_ZONE_ID_{r2_prefix.upper().replace('-', '_')}"
        domain = urlparse(prefix_origin.get(r2_prefix, "")).hostname
        label = f"{domain} ({r2_prefix}/)" if domain else f"{r2_prefix}/"
        zone_id = _prompt_credential(
            env_name,
            f"Zone ID for {label}\n"
            "Found at: https://dash.cloudflare.com → select domain → right sidebar\n"
            "Press Enter to skip (Worker will not serve this domain):",
            secret=False,
            required=False,
        )
        if zone_id:
            zone_ids[r2_prefix] = zone_id

    if not zone_ids:
        legacy_zone_id = _prompt_credential(
            "CF_ZONE_ID",
            "Zone ID for your primary custom domain (articles, backward-compatible fallback).\n"
            "Found at: https://dash.cloudflare.com → select domain → right sidebar\n"
            "Press Enter to skip (Worker will be workers.dev only):",
            secret=False,
            required=False,
        )
        if legacy_zone_id:
            zone_ids["articles"] = legacy_zone_id

    return zone_ids


def parse_workers_dev_url(wrangler_stdout: str, script_name: str) -> str | None:
    """Extract the workers.dev URL from wrangler deploy output."""
    # wrangler prints: "https://sd-worker.aged-waterfall-d369.workers.dev"
    m = re.search(rf'https://{re.escape(script_name)}\.([^.\s]+)\.workers\.dev', wrangler_stdout)
    if m:
        return f"https://{script_name}.{m.group(1)}.workers.dev"
    return None

def run_deploy(analysis: JournalAnalysis) -> bool:
    env = get_cf_account()
    if not env:
        return False
    account_id, api_token = env

    sc          = analysis.shortcut
    OUTPUT_DIR  = get_output_dir(sc)
    script_name = f"{sc}-worker"
    bucket_name = get_bucket_name(sc)
    folder_map  = get_folder_map(analysis)
    prefix_origin = infer_prefix_origin(analysis, folder_map)

    # Pick custom_domain — prefer copernicus.org, fallback to constructed default
    custom_domain = urlparse(prefix_origin.get("articles", f"https://{sc}.copernicus.org")).hostname or f"{sc}.copernicus.org"

    zone_ids = get_cf_zone_ids(folder_map, prefix_origin)

    index_js_path      = OUTPUT_DIR / "index.js"
    symlinks_json_path = OUTPUT_DIR / "symlinks.json"
    symlinks_dir       = OUTPUT_DIR / "symlinks"

    if not index_js_path.exists():
        print("  ERROR: index.js not found — run Generate first (option 3).")
        return False

    index_js_content = index_js_path.read_text()

    try:
        import requests
    except ImportError:
        print("ERROR: pip install requests")
        return False

    route_specs = []
    for r2_prefix, zone_id in zone_ids.items():
        domain = urlparse(prefix_origin.get(r2_prefix, "")).hostname
        if domain:
            route_specs.append((r2_prefix, zone_id, domain))
    shard_files = sorted(symlinks_dir.glob("*.json")) if symlinks_dir.exists() else []
    has_legacy_symlink_file = symlinks_json_path.exists()
    symlink_upload_steps = len(shard_files) if shard_files else (1 if has_legacy_symlink_file else 0)
    STEPS = 2 + len(route_specs) + symlink_upload_steps

    # Load cached workers.dev URL if available (set after first deploy)
    workers_dev_url_path = OUTPUT_DIR / ".workers_dev_url"
    workers_dev_url = workers_dev_url_path.read_text().strip() \
                      if workers_dev_url_path.exists() \
                      else f"https://{script_name}.YOUR-ACCOUNT.workers.dev"

    print(f"\n{'═' * 70}")
    print(f"  Step 6 — Deploying  {script_name}")
    if route_specs:
        print(f"  Domains: {', '.join(domain for _, _, domain in route_specs)}")
    else:
        print(f"  Domain : {workers_dev_url}/  (no Zone ID)")
    print(f"{'═' * 70}")

        # ── [1] Upload Worker + R2 binding ────────────────────────────────────────
    print(f"  [1/{STEPS}] Uploading Worker + R2 binding...", end=" ", flush=True)
    cmd_prefix = ["wrangler"] if check_wrangler() else ["npx", "wrangler"]

    # wrangler deploy requires a wrangler.toml — write a temporary one
    import tempfile
    wrangler_toml = f"""\
name = "{script_name}"
main = "worker.js"
compatibility_date = "2024-01-01"

[[r2_buckets]]
binding = "R2_BUCKET"
bucket_name = "{bucket_name}"
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        (tmpdir / "wrangler.toml").write_text(wrangler_toml)
        (tmpdir / "worker.js").write_text(index_js_content)

        result = subprocess.run(
            cmd_prefix + ["deploy", "--config", str(tmpdir / "wrangler.toml")],
            env=wrangler_env(account_id, api_token),
            capture_output=True, text=True, timeout=120,
        )

    if not wrangler_ok(result, "Worker upload"):
        return False

    # Extract and cache the workers.dev URL from wrangler output
    workers_dev_url = parse_workers_dev_url(result.stdout, script_name)
    if workers_dev_url:
        (OUTPUT_DIR / ".workers_dev_url").write_text(workers_dev_url)
    else:
        workers_dev_url = f"https://{script_name}.YOUR-ACCOUNT.workers.dev"

    # ── [2..N] Set routes (optional) ───────────────────────────────────────────
    next_step = 2
    if route_specs:
        for _, zone_id, domain in route_specs:
            print(f"  [{next_step}/{STEPS}] Setting route {domain}/*...", end=" ", flush=True)
            route_pattern = f"{domain}/*"
            existing      = cf_api("GET", f"/zones/{zone_id}/workers/routes", api_token) or {}
            existing_id   = next((r["id"] for r in existing.get("result", [])
                                   if r.get("pattern") == route_pattern), None)
            route_payload = {"pattern": route_pattern, "script": script_name}
            if existing_id:
                data = cf_api("PUT", f"/zones/{zone_id}/workers/routes/{existing_id}",
                              api_token, json=route_payload) or {}
            else:
                data = cf_api("POST", f"/zones/{zone_id}/workers/routes",
                              api_token, json=route_payload) or {}
            try:
                check_response(data, f"Route setup ({domain})")
            except SystemExit:
                return False
            next_step += 1
    else:
        print("  Route setup skipped — no Zone IDs provided.")
        print(f"  Worker available at: https://{script_name}.YOUR-ACCOUNT.workers.dev")

    # ── [N] Upload symlink shards (or legacy fallback) ────────────────────────
    cmd_prefix = ["wrangler"] if check_wrangler() else ["npx", "wrangler"]
    if shard_files:
        for shard_path in shard_files:
            shard_prefix = shard_path.stem
            print(f"  [{next_step}/{STEPS}] Uploading symlinks/{shard_prefix}.json to R2...", end=" ", flush=True)
            result = subprocess.run(
                cmd_prefix + ["r2", "object", "put",
                              f"{bucket_name}/_symlinks/{shard_prefix}.json",
                              "--file", str(shard_path),
                              "--content-type", "application/json"],
                env=wrangler_env(account_id, api_token),
                capture_output=True, text=True, timeout=60,
            )
            if not wrangler_ok(result, f"R2 symlinks/{shard_prefix}.json upload"):
                return False
            next_step += 1
    elif has_legacy_symlink_file:
        print(f"  [{next_step}/{STEPS}] Uploading symlinks.json to R2...", end=" ", flush=True)
        result = subprocess.run(
            cmd_prefix + ["r2", "object", "put",
                          f"{bucket_name}/_symlinks.json",
                          "--file", str(symlinks_json_path),
                          "--content-type", "application/json"],
            env=wrangler_env(account_id, api_token),
            capture_output=True, text=True, timeout=60,
        )
        if not wrangler_ok(result, "R2 symlinks.json upload"):
            return False
        next_step += 1
    else:
        print("  No symlink shard files found — skipping symlink upload.")

    # ── [final] Smoke test ────────────────────────────────────────────────────
    print(f"  [{next_step}/{STEPS}] Smoke test...", end=" ", flush=True)
    if route_specs:
        smoke_url = f"https://{route_specs[0][2]}/"
    else:
        smoke_url = f"{workers_dev_url}/"
    time.sleep(2)
    try:
        r = requests.get(smoke_url, allow_redirects=False, timeout=10)
        print(f"HTTP {r.status_code}")
    except Exception as e:
        print(f"⚠ {e}")

    print(f"\n  ✓ Deployed.")
    if route_specs:
        print(f"  URL : https://{route_specs[0][2]}/")
        print(f"  Also: {workers_dev_url}/")
    else:
        print(f"  URL : {workers_dev_url}/")
        print("  To bind custom domains later, set CF_ZONE_ID_ARTICLES / CF_ZONE_ID_* and re-run Deploy.")
    print(f"{'═' * 70}\n")

    (OUTPUT_DIR / ".deploy_done").touch()
    return True

# ── Step 5: Verify ────────────────────────────────────────────────────────────

@dataclass
class VerifyResult:
    path:        str
    origin_code: int | None
    origin_loc:  str | None
    worker_code: int | None
    worker_loc:  str | None
    match:       bool
    note:        str = ""


def http_head(url: str, timeout: int = 10) -> tuple[int | None, str | None, dict[str, str]]:
    try:
        import requests
        r = requests.head(url, allow_redirects=False, timeout=timeout)
        return r.status_code, r.headers.get("Location"), dict(r.headers)
    except:
        return None, None, {}


def synthesise_test_paths(analysis: JournalAnalysis) -> list[str]:
    paths: list[str] = []
    seen:  set[str]  = set()

    def add(p: str) -> None:
        if p not in seen: seen.add(p); paths.append(p)

    add("/")
    add("/index.html")

    sources = (
        [f.htaccess_redirects for f in analysis.folders if f.exists] +
        [v.redirects          for v in analysis.vhosts  if v.exists]
    )
    for redirect_list in sources:
        classified = classify_redirects(redirect_list)
        for r in classified["mirror_numeric"][:1]:
            sample = re.sub(r'\(\.\+\)', 'sample.pdf',
                            re.sub(r'[~^\\]', '', r.get("pattern", "")))
            add("/" + sample.lstrip("/"))
        for r in classified["mirror_letter"][:1]:
            sample = re.sub(r'\(\.\+\)', 'sample.pdf',
                            re.sub(r'[~^\\]', '', r.get("pattern", "")))
            add("/" + sample.lstrip("/"))
        for r in classified["irregular"]:
            if r.get("type") == "RedirectMatch":
                sample = re.sub(r'\(\.\+\)', 'sample.pdf',
                                re.sub(r'[~^()+\\]', '', r.get("pattern", "")))
                add("/" + sample.lstrip("/"))
            elif r.get("from"):
                add(r["from"])

    folder_map = get_folder_map(analysis)
    root_local = next((local for local, _, _ in folder_map if local.endswith(".copernicus.org")), None)
    for folder in analysis.folders:
        if not folder.exists:
            continue
        r2_prefix = next((r2 for local, r2, _ in folder_map if local == folder.name), None)
        if not r2_prefix:
            continue
        url_prefix = "" if folder.name == root_local else f"/{r2_prefix}"
        try:
            first_entry = next((p for p in folder.path.rglob("*") if p.is_file() or p.is_dir()), None)
        except PermissionError:
            first_entry = None
        if not first_entry:
            continue
        rel = str(first_entry.relative_to(folder.path)).replace("\\", "/")
        if first_entry.is_dir():
            rel = rel.rstrip("/") + "/"
        add(f"{url_prefix}/{rel}".replace("//", "/"))
    return paths


def run_verify(analysis: JournalAnalysis) -> bool:
    sc         = analysis.shortcut
    OUTPUT_DIR = get_output_dir(sc)
    folder_map = get_folder_map(analysis)
    prefix_origin = infer_prefix_origin(analysis, folder_map)

    # Origin is always the real copernicus.org domain
    origin_domain = urlparse(prefix_origin.get("articles", f"https://{sc}.copernicus.org")).hostname or f"{sc}.copernicus.org"

    # Worker URL: use workers.dev if no zone ID
    env = get_cf_env()
    zone_id = env[2] if env else None
    workers_dev_url_path = OUTPUT_DIR / ".workers_dev_url"
    workers_dev_url = workers_dev_url_path.read_text().strip() \
                      if workers_dev_url_path.exists() else None

    if zone_id:
        worker_domain = origin_domain
        worker_base   = f"https://{worker_domain}"
    elif workers_dev_url:
        worker_domain = workers_dev_url.removeprefix("https://")
        worker_base   = workers_dev_url
    else:
        print("  ERROR: No Zone ID and no deployed workers.dev URL found. Run Deploy first.")
        return False

    print(f"\n{'═' * 70}")
    print(f"  Step 5 — Verify redirects")
    print(f"  Origin : https://{origin_domain}")
    print(f"  Worker : {worker_base}")
    print(f"{'═' * 70}\n")

    test_paths = synthesise_test_paths(analysis)
    if not test_paths:
        print("\n  No redirect/content paths found to verify.")
        return False

    print(f"\n  Found {len(test_paths)} test paths.")
    limit_input = input(f"  Max paths to test [all]: ").strip()
    try:    test_paths = test_paths[:int(limit_input)]
    except: pass

    print()
    col_url = 50
    print(f"  {'Origin URL':<{col_url}}  {'Worker URL':<{col_url}}  {'Origin':>6}  {'Worker':>6}  Result")
    print(f"  {'─'*col_url}  {'─'*col_url}  {'─'*6}  {'─'*6}  {'─'*10}")

    results = []
    passed = failed = skipped = 0
    symlink_passed = symlink_failed = 0

    def verify_path(path: str, origin_base: str, worker_base_for_path: str, domain_note: str = "") -> None:
        nonlocal passed, failed, skipped
        o_url = f"{origin_base}{path}"
        w_url = f"{worker_base_for_path}{path}"
        o_code, o_loc, _ = http_head(o_url)
        w_code, w_loc, w_headers = http_head(w_url)
        is_r2_hit = (w_headers.get("X-R2-Hit") or w_headers.get("x-r2-hit")) == "1"
        is_origin_fallback = (w_headers.get("X-Origin-Fallback") or w_headers.get("x-origin-fallback")) == "1"

        if o_code is None:
            match = w_code in (301, 302, 307, 308)
            note  = "origin unreachable"; skipped += 1
        else:
            if o_code == w_code and o_code in (301, 302, 307, 308):
                norm  = lambda s: (s or "").rstrip("/")
                match = norm(o_loc) == norm(w_loc)
                note  = "" if match else "Location differs"
            else:
                match = (o_code == w_code)
                note  = "" if match else f"expected {o_code}"

        if match:
            if is_r2_hit:
                note = (note + "; " if note else "") + "R2 hit"
            elif is_origin_fallback:
                note = (note + "; " if note else "") + "origin fallback"
            elif w_code == 200:
                note = (note + "; " if note else "") + "200 without R2/fallback header"
        elif w_code == 200 and not is_r2_hit and not is_origin_fallback:
            note = (note + "; " if note else "") + "mismatch without routing header"
        if domain_note:
            note = (note + "; " if note else "") + domain_note

        if match: passed += 1; flag = "✓"
        else:     failed += 1; flag = "✗"

        disp_o = o_url if len(o_url) <= col_url else o_url[:col_url-1] + "…"
        disp_w = w_url if len(w_url) <= col_url else w_url[:col_url-1] + "…"
        print(f"  {disp_o:<{col_url}}  {disp_w:<{col_url}}  {str(o_code) if o_code else '---':>6}  "
              f"{str(w_code) if w_code else '---':>6}  {flag} {note}")
        results.append(VerifyResult(path=path, origin_code=o_code, origin_loc=o_loc,
                                    worker_code=w_code, worker_loc=w_loc,
                                    match=match, note=note))

    for path in test_paths:
        verify_path(path, f"https://{origin_domain}", worker_base)

    for r2_prefix, origin_url in prefix_origin.items():
        if r2_prefix == "articles":
            continue
        domain = urlparse(origin_url).hostname
        if not domain:
            continue
        for path in ("/", "/index.html"):
            verify_path(path, f"https://{domain}", worker_base, f"domain={domain}")

    symlink_map: dict[str, str] = {}
    symlinks_json_path = OUTPUT_DIR / "symlinks.json"
    if symlinks_json_path.exists():
        try:
            loaded = json.loads(symlinks_json_path.read_text())
            if isinstance(loaded, dict):
                symlink_map = loaded
        except Exception:
            symlink_map = {}
    else:
        symlink_dir = OUTPUT_DIR / "symlinks"
        if symlink_dir.is_dir():
            for shard_path in sorted(symlink_dir.glob("*.json")):
                try:
                    loaded = json.loads(shard_path.read_text())
                except Exception:
                    continue
                if isinstance(loaded, dict):
                    symlink_map.update(loaded)

    if symlink_map:
        root_r2_prefix = next(
            (r2 for local, r2, _ in folder_map if local.endswith(".copernicus.org")),
            "articles",
        )
        symlink_items = list(symlink_map.items())
        print(f"\n  Found {len(symlink_items)} symlink entries.")
        limit_input = input("  Symlinks to verify [20]: ").strip()
        try:
            sym_limit = int(limit_input)
        except ValueError:
            sym_limit = 20
        sym_limit = max(0, min(sym_limit, len(symlink_items)))

        if sym_limit and sym_limit < len(symlink_items):
            step = max(1, len(symlink_items) // sym_limit)
            symlink_sample = symlink_items[::step][:sym_limit]
        else:
            symlink_sample = symlink_items if sym_limit or not limit_input else []

        print(f"\n  Verifying {len(symlink_sample)} symlinks...")
        print()

        for r2_key, r2_target in symlink_sample:
            stripped = r2_key.lstrip("/")
            parts = stripped.split("/", 1)
            if parts[0] == root_r2_prefix:
                suffix = parts[1] if len(parts) > 1 else ""
                url_path = "/" + suffix if suffix else "/"
            else:
                url_path = "/" + stripped

            w_code, w_loc, w_headers = http_head(f"{worker_base}{url_path}")
            is_r2_hit = (w_headers.get("X-R2-Hit") or w_headers.get("x-r2-hit")) == "1"
            match = (w_code == 200 and is_r2_hit)
            status = str(w_code) if w_code is not None else "---"
            note = "R2 hit" if match else (f"HTTP {status}" + (" no-R2-hit" if w_code == 200 else ""))

            if match:
                passed += 1
                symlink_passed += 1
                flag = "✓"
            else:
                failed += 1
                symlink_failed += 1
                flag = "✗"

            disp_o = "---"
            w_full = f"{worker_base}{url_path}"
            disp_w = w_full if len(w_full) <= col_url else w_full[:col_url-1] + "…"
            print(f"  {disp_o:<{col_url}}  {disp_w:<{col_url}}  {'---':>6}  {status:>6}  {flag} symlink; {note}")
            results.append(VerifyResult(
                path=url_path,
                origin_code=None,
                origin_loc=None,
                worker_code=w_code,
                worker_loc=w_loc,
                match=match,
                note=f"symlink→{r2_target}; {note}",
            ))

    print(f"\n  {'─'*70}")
    summary = f"  {passed} passed  /  {failed} failed  /  {skipped} skipped"
    if symlink_passed or symlink_failed:
        summary += f"  /  symlinks: {symlink_passed} passed, {symlink_failed} failed"
    print(summary)

    if failed:
        print(f"\n  Failed paths:")
        for r in results:
            if not r.match:
                print(f"    {r.path}")
                print(f"      Origin : {r.origin_code}  →  {r.origin_loc}")
                print(f"      Worker : {r.worker_code}  →  {r.worker_loc}")
                if r.note: print(f"      Note   : {r.note}")

    report_path = OUTPUT_DIR / "verify_report.json"
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps([asdict(r) for r in results], indent=2))
    print(f"\n  Report saved to {report_path}")
    print(f"{'═' * 70}\n")
    return failed == 0


# ── Wrangler helpers ──────────────────────────────────────────────────────────

def check_wrangler() -> bool:
    """Return True if wrangler is installed."""
    return shutil.which("wrangler") is not None


def wrangler_env(account_id: str, api_token: str) -> dict:
    """
    Build the environment dict for wrangler subprocess calls.
    Wrangler uses CLOUDFLARE_API_TOKEN + CLOUDFLARE_ACCOUNT_ID,
    not CF_API_TOKEN / CF_ACCOUNT_ID.
    """
    env = os.environ.copy()
    env["CLOUDFLARE_API_TOKEN"]  = api_token
    env["CLOUDFLARE_ACCOUNT_ID"] = account_id
    return env


def wrangler_ok(result: subprocess.CompletedProcess, action: str) -> bool:
    """Print result and return True on success."""
    if result.returncode == 0:
        print("OK")
        return True
    print("FAILED")
    # wrangler writes errors to stderr
    for line in (result.stderr or result.stdout or "").splitlines():
        line = line.strip()
        if line:
            print(f"          {line}")
    return False
    
def get_bucket_name(shortcut: str) -> str:
    """
    R2 bucket names must be 3–63 characters.
    Prefix with 'bucket-' to ensure minimum length and valid naming.
    e.g. 'acp' → 'bucket-acp', 'sp' → 'bucket-sp'
    """
    return f"bucket-{shortcut}"
    
def validate_cf_credentials(account_id: str, api_token: str) -> bool:
    """Quick sanity checks before hitting the API."""
    if len(account_id) != 32:
        print(f"\n  ERROR: CF_ACCOUNT_ID should be 32 characters, got {len(account_id)}.")
        print(f"  Make sure you're using the Account ID, not the R2 Access Key ID.")
        print(f"  Found at: https://dash.cloudflare.com → right sidebar → Account ID")
        _cf_credentials.pop("CF_ACCOUNT_ID", None)
        return False
    if len(api_token) < 20:
        print(f"\n  ERROR: CF_API_TOKEN looks too short ({len(api_token)} chars).")
        print(f"  Make sure you're copying the full token value.")
        _cf_credentials.pop("CF_API_TOKEN", None)
        return False
    return True

# ── Step 6: Cloudflare setup ──────────────────────────────────────────────────

def run_setup(analysis: JournalAnalysis) -> bool:
    env = get_cf_account()
    if not env:
        return False
    account_id, api_token = env

    if not validate_cf_credentials(account_id, api_token):
        return False

    sc          = analysis.shortcut
    bucket_name = get_bucket_name(sc)
    folder_map  = get_folder_map(analysis)
    OUTPUT_DIR = get_output_dir(sc)

    print(f"\n{'═' * 70}")
    print(f"  Step 6 — Cloudflare Setup")
    print(f"  Bucket : {bucket_name}")
    print(f"  Folders: {', '.join(r2_prefix + '/' for _, r2_prefix, _ in folder_map)}")
    print(f"{'═' * 70}")

    # ── Check wrangler ────────────────────────────────────────────────────────
    if not check_wrangler():
        print("\n  ERROR: wrangler not found.")
        print("  Install: npm install -g wrangler")
        print("  Or via npx (no install): the script will use npx automatically.")
        # Fallback to npx if available
        if not shutil.which("npx"):
            return False
        print("  Found npx — will use 'npx wrangler' instead.")

    cmd_prefix = ["wrangler"] if check_wrangler() else ["npx", "wrangler"]

    STEPS = 1 + len(folder_map)

    # ── 1. Create R2 bucket ───────────────────────────────────────────────────
    print(f"\n  [1/{STEPS}] Creating R2 bucket '{bucket_name}'...", end=" ", flush=True)

    # Check if it already exists
    list_result = subprocess.run(
        cmd_prefix + ["r2", "bucket", "list"],
        env=wrangler_env(account_id, api_token),
        capture_output=True, text=True, timeout=30,
    )

    existing_buckets = [line.strip() for line in (list_result.stdout or "").splitlines()]
    if bucket_name in existing_buckets:
        print("already exists — skipping")
    else:
        result = subprocess.run(
            cmd_prefix + ["r2", "bucket", "create", bucket_name],
            env=wrangler_env(account_id, api_token),
            capture_output=True, text=True, timeout=30,
        )
        output = (result.stdout or "") + (result.stderr or "")
        if result.returncode != 0:
            if "10004" in output or "already exists" in output.lower():
                print("already exists — skipping")
            else:
                print("FAILED")
                for line in output.splitlines():
                    line = line.strip()
                    if line:
                        print(f"          {line}")
                return False
        else:
            print("OK")

    # ── 2. Create folder markers ──────────────────────────────────────────────
    # R2 has no real directories — upload a zero-byte marker object per folder
    for i, (local_name, r2_prefix, mandatory) in enumerate(folder_map, start=2):
        marker_key = f"{r2_prefix}/.folder"
        print(f"  [{i}/{STEPS}] Creating folder marker '{r2_prefix}/'...",
              end=" ", flush=True)

        import tempfile
        # Write a small placeholder README so the folder is visible in the dashboard
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tmp:
            tmp.write(
                f"This folder is managed by cf_transfer.py\n"
                f"Journal  : {sc.upper()}\n"
                f"Prefix   : {r2_prefix}/\n"
                f"Source   : /var/www/{local_name}/\n"
            )
            tmp_path = tmp.name

        try:
            result = subprocess.run(
                cmd_prefix + ["r2", "object", "put",
                              f"{bucket_name}/{r2_prefix}/.folder",
                              "--file", tmp_path,
                              "--content-type", "text/plain"],
                env=wrangler_env(account_id, api_token),
                capture_output=True, text=True, timeout=30,
            )
            if not wrangler_ok(result, f"Create folder marker {r2_prefix}/"):
                return False
        finally:
            os.unlink(tmp_path)

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n  ✓ Bucket '{bucket_name}' ready with folders:")
    for local_name, r2_prefix, mandatory in folder_map:
        tag = "" if mandatory else "  (optional — acpd exists)"
        print(f"    r2://{bucket_name}/{r2_prefix}/{tag}")
    print()
    print(f"  Next steps:")
    print(f"    1. Run Sync  (menu option 7) to copy content from your server")
    print(f"    2. Run Deploy (menu option 4) to push the Worker")
    print(f"{'═' * 70}\n")

    (OUTPUT_DIR / ".setup_done").touch()
    return True

# ── Step 7: Sync via rclone ───────────────────────────────────────────────────

def check_rclone() -> bool:
    """Return True if rclone is installed and accessible."""
    return shutil.which("rclone") is not None


def check_rclone_remote(remote: str) -> bool:
    """Return True if the named rclone remote exists."""
    try:
        result = subprocess.run(
            ["rclone", "listremotes"],
            capture_output=True, text=True, timeout=10
        )
        return f"{remote}:" in result.stdout
    except Exception:
        return False


def generate_rclone_conf(bucket_name: str, account_id: str) -> str:
    """
    Generate an rclone config snippet for Cloudflare R2.
    Uses the S3-compatible R2 endpoint.
    Requires an R2 API token (not the same as CF API token —
    create one at dash.cloudflare.com → R2 → Manage R2 API Tokens).
    """
    return f"""\
# rclone config snippet for Cloudflare R2
# Add this to ~/.config/rclone/rclone.conf
# OR run: rclone config  and create a new remote named 'r2'
#
# NOTE: R2_ACCESS_KEY_ID and R2_SECRET_ACCESS_KEY are R2-specific tokens,
#       created at: Cloudflare Dashboard → R2 → Manage R2 API Tokens
#       They are NOT the same as CF_API_TOKEN.

[r2]
type = s3
provider = Cloudflare
access_key_id = YOUR_R2_ACCESS_KEY_ID
secret_access_key = YOUR_R2_SECRET_ACCESS_KEY
endpoint = https://{account_id}.r2.cloudflarestorage.com
acl = private
"""


def generate_sync_sh(
    shortcut:   str,
    folder_map: list[tuple[str, str, bool]],
    bucket_name: str,
    account_id: str,
) -> str:
    """Generate a standalone sync.sh script using rclone."""
    lines = [
        f"#!/usr/bin/env bash",
        f"# sync.sh — auto-generated by cf_transfer.py",
        f"# Syncs /var/www content to R2 bucket '{bucket_name}' via rclone.",
        f"#",
        f"# Requires rclone with an 'r2' remote configured.",
        f"# See rclone.conf in this directory for setup instructions.",
        f"#",
        f"# Usage:  bash sync.sh [--dry-run]",
        f"#",
        f"#   --dry-run         preview only, no transfers",
        f"#",
        f"# Performance flags used:",
        f"#   --transfers 32          parallel file transfers",
        f"#   --checkers 32           parallel stat checks",
        f"#   --multi-thread-streams 4  multi-threaded upload for large files",
        f"#   --multi-thread-cutoff 10M  apply multi-threading for files over 10 MB",
        f"#   --buffer-size 256M      read buffer per transfer",
        f"#   --s3-upload-concurrency 8  parallel chunks per multipart upload",
        f"#   --s3-chunk-size 64M     multipart chunk size",
        f"",
        f"set -euo pipefail",
        f"",
        f"DRY_RUN=\"\"",
        f"",
        f"for arg in \"$@\"; do",
        f"  case \"$arg\" in",
        f"    --dry-run)       DRY_RUN=\"--dry-run\" ;;",
        f"    *) echo \"Unknown option: $arg\"; exit 1 ;;",
        f"  esac",
        f"done",
        f"",
        f"[ -n \"$DRY_RUN\" ]       && echo \"==> DRY RUN mode — no files will be transferred\"",
        f"",
        f"REMOTE=\"r2:{bucket_name}\"",
        f"RCLONE_FLAGS=\"--transfers 32 --checkers 32 --multi-thread-streams 4 --multi-thread-cutoff 10M --buffer-size 256M --s3-upload-concurrency 8 --s3-chunk-size 64M --checksum --fast-list --progress $DRY_RUN\"",
        f"",
        f"# Exclude Apache control files from the sync",
        f'EXCLUDES="--exclude .htaccess --exclude .htpasswd --exclude .DS_Store"',
        f"",
    ]

    for i, (local_name, r2_prefix, mandatory) in enumerate(folder_map, start=1):
        local_path = f"/var/www/{local_name}"
        tag        = "" if mandatory else "  # optional"
        lines += [
                f"echo \"==> [{i}/{len(folder_map)}] Syncing {local_path}/ → ${{REMOTE}}/{r2_prefix}/\"{tag}",
                f"rclone sync {local_path}/ ${{REMOTE}}/{r2_prefix}/ ${{RCLONE_FLAGS}} ${{EXCLUDES}}",
                f"echo \"    Done\"",
                f"",
            ]

    lines += [
        f"echo \"\"",
        f"echo \"✓ Sync complete\"",
        f"echo \"  Bucket : https://dash.cloudflare.com/{account_id}/r2/default/buckets/{bucket_name}\"",
    ]

    return "\n".join(lines)


def run_sync(analysis: JournalAnalysis) -> bool:
    env = get_cf_account()
    if not env:
        return False
    account_id, api_token = env

    sc          = analysis.shortcut
    bucket_name = get_bucket_name(sc)
    folder_map  = get_folder_map(analysis)
    OUTPUT_DIR = get_output_dir(sc)

    print(f"\n{'═' * 70}")
    print(f"  Step 7 — Sync content to R2 via rclone")
    print(f"  Bucket : {bucket_name}")
    print(f"{'═' * 70}\n")

    # ── Check rclone ──────────────────────────────────────────────────────────
    if not check_rclone():
        print("  ERROR: rclone not found.")
        print("  Install: https://rclone.org/install/")
        print("  e.g.:    curl https://rclone.org/install.sh | sudo bash")
        return False

    rclone_version = subprocess.run(
        ["rclone", "version"], capture_output=True, text=True
    ).stdout.splitlines()[0]
    print(f"  rclone : {rclone_version}")

    # ── Check r2 remote ───────────────────────────────────────────────────────
    REMOTE_NAME = "r2"
    if not check_rclone_remote(REMOTE_NAME):
        print(f"\n  ⚠ rclone remote '{REMOTE_NAME}' not configured.")
        print(f"  Generating rclone.conf snippet...")

        conf_snippet = generate_rclone_conf(bucket_name, account_id)
        conf_path    = OUTPUT_DIR / "rclone.conf"
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        conf_path.write_text(conf_snippet)
        print(f"  Saved to {conf_path}")
        print()
        print(f"  To configure rclone:")
        print(f"    1. Create R2 API tokens at:")
        print(f"       https://dash.cloudflare.com/{account_id}/r2/api-tokens")
        print(f"    2. Edit {conf_path} and fill in access_key_id + secret_access_key")
        print(f"    3. Append to ~/.config/rclone/rclone.conf")
        print(f"    4. Re-run this step")
        print()

        # Also generate sync.sh for later use
        sync_sh      = generate_sync_sh(sc, folder_map, bucket_name, account_id)
        sync_sh_path = OUTPUT_DIR / "sync.sh"
        sync_sh_path.write_text(sync_sh)
        sync_sh_path.chmod(0o755)
        print(f"  sync.sh saved to {sync_sh_path} — run it once rclone is configured.")
        return False

    # ── Generate sync.sh ──────────────────────────────────────────────────────
    sync_sh      = generate_sync_sh(sc, folder_map, bucket_name, account_id)
    sync_sh_path = OUTPUT_DIR / "sync.sh"
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    sync_sh_path.write_text(sync_sh)
    sync_sh_path.chmod(0o755)

    # ── Show what will be synced ───────────────────────────────────────────────
    print(f"  Sync plan:")
    total_size_est = 0
    for local_name, r2_prefix, mandatory in folder_map:
        local_path = WEBROOT / local_name
        tag        = "" if mandatory else "  (optional)"
        # Estimate size with du if available
        try:
            result = subprocess.run(
                ["du", "-sh", str(local_path)],
                capture_output=True, text=True, timeout=30
            )
            size = result.stdout.split()[0] if result.returncode == 0 else "?"
        except Exception:
            size = "?"
        print(f"    /var/www/{local_name}/  ({size})  →  r2:{bucket_name}/{r2_prefix}/  {tag}")
    print()

    # ── Sync mode ────────────────────────────────────────────────────────────
    extra_flags = ["--checksum"]
    print()
    print("  Sync mode: checksum (always)")

    # ── Dry run first ─────────────────────────────────────────────────────────
    want_dry = input("  Run dry-run first to preview changes? [Y/n]: ").strip().lower()
    if want_dry != "n":
        print()
        all_ok = True
        for local_name, r2_prefix, mandatory in folder_map:
            local_path = str(WEBROOT / local_name)
            dest       = f"{REMOTE_NAME}:{bucket_name}/{r2_prefix}"
            print(f"  ── Dry run: {local_name}/ → {r2_prefix}/ ──")
            try:
                result = subprocess.run(
                    ["rclone", "sync", local_path, dest,
                     "--dry-run", "--fast-list", "--progress",
                     "--exclude", ".htaccess", "--exclude", ".htpasswd",
                     "--exclude", ".DS_Store"],
                    # Intentionally stream rclone output directly to terminal for live preview.
                    timeout=300
                )
                if result.returncode != 0:
                    print(f"  ⚠ rclone exited with code {result.returncode}")
                    all_ok = False
            except subprocess.TimeoutExpired:
                print(f"  ⚠ Timeout during dry run of {local_name}")
                all_ok = False
            print()

        if not all_ok:
            print("  ⚠ Dry run had errors. Fix before proceeding.")
            return False

    # ── Confirm real sync ─────────────────────────────────────────────────────
    print()
    confirm = input("  Proceed with live sync? [y/N]: ").strip().lower()
    if confirm != "y":
        print("  Sync cancelled.")
        print(f"  To sync manually later:  bash {sync_sh_path}")
        return False

    # ── Live sync ─────────────────────────────────────────────────────────────
    print()
    all_ok  = True
    t_start = time.time()

    for i, (local_name, r2_prefix, mandatory) in enumerate(folder_map, start=1):
        local_path = str(WEBROOT / local_name)
        dest       = f"{REMOTE_NAME}:{bucket_name}/{r2_prefix}"
        print(f"  [{i}/{len(folder_map)}] {local_name}/  →  {r2_prefix}/")

        try:
            result = subprocess.run(
                ["rclone", "sync", local_path, dest,
                 "--transfers", "32",
                 "--checkers", "32",
                 "--multi-thread-streams", "4",
                 "--multi-thread-cutoff", "10M",
                 "--buffer-size", "256M",
                 "--s3-upload-concurrency", "8",
                 "--s3-chunk-size", "64M",
                 "--fast-list", "--progress",
                 "--exclude", ".htaccess", "--exclude", ".htpasswd",
                 "--exclude", ".DS_Store"] + extra_flags,
                # Intentionally stream rclone output directly to terminal for progress visibility.
                timeout=21600
            )
            if result.returncode == 0:
                print(f"      ✓ Done")
            else:
                print(f"      ⚠ rclone exited {result.returncode}")
                all_ok = False
        except subprocess.TimeoutExpired:
            print(f"      ⚠ Timeout (>6h) — run manually: bash {sync_sh_path}")
            all_ok = False
        except FileNotFoundError:
            print(f"      ⚠ Source not found: {local_path}")
            all_ok = False

    elapsed = time.time() - t_start
    print()
    if all_ok:
        print(f"  ✓ Sync complete in {elapsed:.0f}s")
        (OUTPUT_DIR / ".sync_done").touch()        
    else:
        print(f"  ⚠ Sync finished with errors in {elapsed:.0f}s")
        print(f"    Re-run individually:  bash {sync_sh_path}")

    print(f"  Bucket: https://dash.cloudflare.com/{account_id}"
          f"/r2/default/buckets/{bucket_name}")
    print(f"{'═' * 70}\n")
    return all_ok

# ── Validation ────────────────────────────────────────────────────────────────

def validate(analysis: JournalAnalysis) -> None:
    for folder in analysis.folders:
        if folder.mandatory and not folder.exists:
            analysis.errors.append(f"Mandatory folder missing: {folder.path}")
        elif not folder.mandatory and not folder.exists:
            analysis.warnings.append(f"Optional folder not present: {folder.path}")
    for vhost in analysis.vhosts:
        if vhost.mandatory and not vhost.exists:
            analysis.errors.append(f"Mandatory vhost config missing: {vhost.conf_file}")
        elif not vhost.mandatory and not vhost.exists:
            analysis.warnings.append(f"Optional vhost config not present: {vhost.conf_file}")

# ── JSON export ───────────────────────────────────────────────────────────────

def analysis_to_dict(analysis: JournalAnalysis) -> dict:
    def folder_dict(f: FolderInfo) -> dict:
        classified = classify_redirects(f.htaccess_redirects)
        num_groups = group_mirror_rules(classified["mirror_numeric"])
        let_groups = group_letter_rules_by_prefix(classified["mirror_letter"])
        sym_groups = symlink_summary(f.symlinks)
        return {
            "name": f.name, "path": str(f.path),
            "exists": f.exists, "mandatory": f.mandatory,
            "htaccess": {
                "redirects": {
                    "total":            len(f.htaccess_redirects),
                    "mirror_numeric":   len(classified["mirror_numeric"]),
                    "mirror_letter":    len(classified["mirror_letter"]),
                    "irregular":        classified["irregular"],
                    "unknown_prefixes": classified["unknown_prefixes"],
                    "collapsed_numeric": {f"{d}/{p}": collapsed_rules_text_numeric(d, p)
                                          for (d, p, _r2, _status) in num_groups},
                    "collapsed_letter":  {f"{d}/{p}/{lt}": collapsed_rules_text_letter(d, p, lt)
                                          for (d, p, lt, _r2, _status) in let_groups},
                },
                "rewrites": f.htaccess_rewrites,
            },
            "symlinks": {
                "total":      len(f.symlinks),
                "file_alias": [asdict(s) for s in sym_groups.get("file_alias", [])],
                "dir_remap":  [asdict(s) for s in sym_groups.get("dir_remap",  [])],
                "external":   [asdict(s) for s in sym_groups.get("external",   [])],
                "broken":     [asdict(s) for s in sym_groups.get("broken",     [])],
            },
        }

    def vhost_dict(v: VhostInfo) -> dict:
        classified = classify_redirects(v.redirects)
        return {
            "conf_file": str(v.conf_file), "exists": v.exists, "mandatory": v.mandatory,
            "server_names": v.server_names, "document_root": v.document_root,
            "redirects": {
                "total":            len(v.redirects),
                "mirror_numeric":   len(classified["mirror_numeric"]),
                "mirror_letter":    len(classified["mirror_letter"]),
                "irregular":        classified["irregular"],
                "unknown_prefixes": classified["unknown_prefixes"],
            },
            "rewrites": v.rewrites,
        }

    return {
        "shortcut":          analysis.shortcut,
        "known_id_prefixes": sorted(KNOWN_ID_PREFIXES),
        "errors":            analysis.errors,
        "warnings":          analysis.warnings,
        "unknown_prefixes":  analysis.unknown_prefixes,
        "folder_map":        get_folder_map(analysis),
        "folders":           [folder_dict(f) for f in analysis.folders],
        "vhosts":            [vhost_dict(v)  for v in analysis.vhosts],
    }

# ── Reporting ─────────────────────────────────────────────────────────────────

def print_section(title: str) -> None:
    print(f"\n{'─' * 70}")
    print(f"  {title}")
    print(f"{'─' * 70}")


def report_rewrite_rules(rewrites: list[dict], indent: str = "    ") -> None:
    if not rewrites:
        print(f"{indent}RewriteRules : none"); return
    print(f"{indent}RewriteRules ({len(rewrites)}):")
    for rw in rewrites:
        flags = f"[{rw['flags']}]" if rw["flags"] else ""
        print(f"{indent}  {rw['pattern']}  →  {rw['substitution']}  {flags}")
        for cond in rw.get("conditions", []):
            print(f"{indent}    if {cond['test_string']} {cond['condition']}")


def report_redirect_analysis(redirects: list[dict], analysis: JournalAnalysis,
                              label: str = "") -> None:
    if not redirects:
        print(f"    Redirects    : none"); return

    classified    = classify_redirects(redirects)
    mirror_num    = classified["mirror_numeric"]
    mirror_letter = classified["mirror_letter"]
    irregular     = classified["irregular"]
    unknown       = classified["unknown_prefixes"]

    for p in unknown:
        if p not in analysis.unknown_prefixes:
            analysis.unknown_prefixes.append(p)

    num_groups    = group_mirror_rules(mirror_num)              if mirror_num    else {}
    letter_groups = group_letter_rules_by_prefix(mirror_letter) if mirror_letter else {}
    total_coll    = len(mirror_num) + len(mirror_letter)

    print(f"    Redirects    : {len(redirects)} total  "
          f"({total_coll} collapsible, {len(irregular)} need review)")

    if mirror_num:
        print(f"\n    ✓ Collapsible numeric-path rules : {len(mirror_num)}")
        for (domain, prefix, _r2, status), entries in num_groups.items():
            print(f"      Target: {domain}/{prefix}/  ({len(entries)} rules → 3 collapsed)")
            for t in collapsed_rules_text_numeric(domain, prefix):
                print(f"        {t.replace('301', str(status), 1)}")

    if mirror_letter:
        by_letter: dict[str, int] = defaultdict(int)
        for r in mirror_letter: by_letter[r["prefix"]] += 1
        summary = ", ".join(f"{c} {l}-id" for l, c in sorted(by_letter.items()))
        print(f"\n    ✓ Collapsible letter-id rules    : {len(mirror_letter)}  ({summary})")
        for (domain, prefix, letter, _r2, status), entries in sorted(letter_groups.items()):
            print(f"      [{letter}]  Target: {domain}/{prefix}/  "
                  f"({len(entries)} rules → 2 collapsed)")
            for t in collapsed_rules_text_letter(domain, prefix, letter):
                print(f"        {t.replace('301', str(status), 1)}")

    if unknown:
        print(f"\n    ⚠ Unknown letter-id prefixes: {', '.join(sorted(unknown))}")
        print(f"      Add to KNOWN_ID_PREFIXES to enable collapsing.")

    if irregular:
        print(f"\n    ⚠ Rules needing manual review    : {len(irregular)}")
        for r in irregular:
            if r.get("type") == "RedirectMatch":
                print(f"      {r.get('status'):>4}  ~{r.get('pattern')}  →  {r.get('to')}")
            else:
                print(f"      {r.get('status'):>4}  {r.get('from')}  →  {r.get('to')}")


def report_symlinks(symlinks: list[SymlinkInfo],
                    folder_map: list[tuple[str, str, bool]] | None = None) -> None:
    if not symlinks:
        print(f"    Symlinks     : none"); return

    groups       = symlink_summary(symlinks)
    file_aliases = groups.get("file_alias", [])
    dir_remaps   = groups.get("dir_remap",  [])
    externals    = groups.get("external",   [])
    broken       = groups.get("broken",     [])

    print(f"    Symlinks     : {len(symlinks)} total  "
          f"({len(file_aliases)} file-alias, {len(dir_remaps)} dir-remap, "
          f"{len(externals)} external, {len(broken)} broken)")

    # Classify same-prefix vs cross-prefix if folder_map provided
    if folder_map:
        _, cross, _ = build_symlink_map(file_aliases + dir_remaps, folder_map)
        if cross:
            print(f"\n    ↪ Cross-folder symlinks ({len(cross)})  → will become 301 redirects:")
            for r in cross:
                print(f"      {r['from']}  →  {r['to']}")

    if externals:
        print(f"\n    External targets ({len(externals)})  ← need case-by-case review:")
        for s in externals:
            print(f"      /{Path(s.link_path).relative_to(WEBROOT)}"
                  f"  →  {s.resolved or s.target_path}")

    if broken:
        print(f"\n    ⚠ Broken symlinks ({len(broken)}):")
        for s in broken:
            print(f"      /{Path(s.link_path).relative_to(WEBROOT)}"
                  f"  →  {s.target_path}  (unresolvable)")


def report_folder(folder: FolderInfo, analysis: JournalAnalysis) -> None:
    status = "✓" if folder.exists else ("✗ MISSING" if folder.mandatory else "– not present")
    label  = "mandatory" if folder.mandatory else "optional"
    print(f"\n  [{label}] {folder.path}  →  {status}")
    if not folder.exists: return
    htaccess = folder.path / ".htaccess"
    if not htaccess.is_file():
        print("    .htaccess    : not found")
    else:
        print(f"    .htaccess    : found")
        report_redirect_analysis(folder.htaccess_redirects, analysis, label=folder.name)
        report_rewrite_rules(folder.htaccess_rewrites)
    report_symlinks(folder.symlinks)


def report_vhost(vhost: VhostInfo, analysis: JournalAnalysis) -> None:
    status = "✓ found" if vhost.exists else \
             ("✗ MISSING" if vhost.mandatory else "– not present")
    print(f"\n  {vhost.conf_file.name}  →  {status}")
    if not vhost.exists: return
    if vhost.server_names: print(f"    ServerName   : {', '.join(vhost.server_names)}")
    if vhost.document_root: print(f"    DocumentRoot : {vhost.document_root}")
    report_redirect_analysis(vhost.redirects, analysis, label=vhost.conf_file.name)
    report_rewrite_rules(vhost.rewrites)


def print_report(analysis: JournalAnalysis) -> None:
    print(f"\n{'═' * 70}")
    print(f"  Cloudflare Transfer Analysis  —  journal: {analysis.shortcut.upper()}")
    print(f"{'═' * 70}")

    print_section("Web Root Folders  (/var/www)")
    for folder in analysis.folders: report_folder(folder, analysis)

    print_section("Apache Vhost Configs  (/etc/apache2/sites-enabled)")
    for vhost in analysis.vhosts: report_vhost(vhost, analysis)

    print_section("R2 Folder Mapping")
    for local_name, r2_prefix, mandatory in get_folder_map(analysis):
        tag = "" if mandatory else "  (optional)"
        print(f"  /var/www/{local_name}/  →  r2:{analysis.shortcut}/{r2_prefix}/{tag}")

    if analysis.unknown_prefixes:
        print_section("⚠ Unknown Letter-ID Prefixes Found")
        print(f"  Letters : {', '.join(sorted(analysis.unknown_prefixes))}")
        print(f"  Add them to KNOWN_ID_PREFIXES to enable collapsing.")

    if analysis.errors:
        print_section("ERRORS")
        for e in analysis.errors: print(f"  ✗  {e}")

    if analysis.warnings:
        print_section("Warnings")
        for w in analysis.warnings: print(f"  ⚠  {w}")

    unmigrated = collect_unmigrated_rewrite_rules(analysis)
    if unmigrated:
        print_section("⚠ Unmigrated Apache Rewrite rules")
        for line in unmigrated:
            print(f"  - {line}")
        print("  NOTE: RewriteRule/RewriteCond are parsed for visibility only and are not auto-migrated.")

    print(f"\n{'═' * 70}\n")

# ── Interactive menu ──────────────────────────────────────────────────────────

MENU_ITEMS = [
    ("1", "Analyse",     "Step 1+2: Analyse Apache config + discover symlinks"),
    ("2", "Export JSON", "Export full analysis as JSON"),
    ("3", "Generate",    "Step 3:   Generate index.js, symlinks.json, deploy.sh"),
    ("4", "CF Setup",    "Step 4:   Create R2 bucket + folder structure"),
    ("5", "Sync",        "Step 5:   Sync content to R2 via rclone"),
    ("6", "Deploy",      "Step 6:   Deploy Worker to Cloudflare via API"),
    ("7", "Verify",      "Step 7:   Verify redirects against origin + Worker"),
    ("8", "Run all",     "Steps 1–7 in sequence"),
    ("c", "Credentials", "Clear cached CF credentials (re-enter on next API call)"),
    ("q", "Quit",        ""),
]

def print_menu(analysis: JournalAnalysis | None, shortcut: str) -> None:
    OUTPUT_DIR  = get_output_dir(shortcut)
    sc          = shortcut.upper()
    generated   = (OUTPUT_DIR / "index.js").exists()
    setup_done  = (OUTPUT_DIR / ".setup_done").exists()   # written by run_setup()
    synced      = (OUTPUT_DIR / ".sync_done").exists()    # written by run_sync()
    deployed    = (OUTPUT_DIR / ".deploy_done").exists()  # written by run_deploy()
    verified    = (OUTPUT_DIR / "verify_report.json").exists()
    workers_dev_url_path = OUTPUT_DIR / ".workers_dev_url"
    workers_dev_url = workers_dev_url_path.read_text().strip() \
                      if workers_dev_url_path.exists() else None

    print(f"\n{'═' * 70}")
    print(f"  Cloudflare Transfer Tool v{VERSION}  —  journal: {sc}")
    print(f"{'═' * 70}")
    print(f"  Status:")
    print(f"    Analysis  : {'✓ done' if analysis else '– not run'}")
    if analysis:
        total_r = sum(len(f.htaccess_redirects) for f in analysis.folders if f.exists) \
                + sum(len(v.redirects)           for v in analysis.vhosts  if v.exists)
        total_s = sum(len(f.symlinks)            for f in analysis.folders if f.exists)
        print(f"    Redirects : {total_r}  |  Symlinks: {total_s}  |  "
              f"Errors: {len(analysis.errors)}  |  Warnings: {len(analysis.warnings)}")
        print(f"    R2 layout :", end="")
        for _, r2_prefix, _ in get_folder_map(analysis):
            print(f"  {r2_prefix}/", end="")
        print()
    print(f"    Generated : {'✓ done' if generated  else '– not run'}  ({OUTPUT_DIR}/)")
    print(f"    Setup     : {'✓ done' if setup_done else '– not run'}")
    print(f"    Synced    : {'✓ done' if synced     else '– not run'}")
    if deployed and workers_dev_url:
        print(f"    Deployed  : ✓ done  ({workers_dev_url})")
    else:
        print(f"    Deployed  : {'✓ done' if deployed else '– not run'}")
    print(f"    Verified  : {'✓ done' if verified   else '– not run'}")
    print()
    for key, label, desc in MENU_ITEMS:
        if desc: print(f"  [{key}]  {label:<14}  {desc}")
        else:    print(f"  [{key}]  {label}")
    print()


def run_menu(shortcut: str) -> None:
    # Auto-analyse on startup so all options are immediately available
    print(f"\n  Analysing {shortcut}...")
    analysis         = JournalAnalysis(shortcut=shortcut)
    analysis.folders = discover_folders(shortcut)
    analysis.vhosts  = discover_vhosts(shortcut)
    validate(analysis)
    print(f"  Done — {len(analysis.errors)} errors, {len(analysis.warnings)} warnings.")

    while True:
        print_menu(analysis, shortcut)
        choice    = input("  Choice: ").strip().lower()
        OUTPUT_DIR = get_output_dir(shortcut)          # ← must be inside the loop

        if choice in ("q", "quit", "exit"):
            print("  Bye.\n"); break

        elif choice == "1":
            analysis         = JournalAnalysis(shortcut=shortcut)
            analysis.folders = discover_folders(shortcut)
            analysis.vhosts  = discover_vhosts(shortcut)
            validate(analysis)
            print_report(analysis)
            input("  Press Enter to return to menu...")

        elif choice == "2":
            out_path = OUTPUT_DIR / f"{shortcut}_analysis.json"
            OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(analysis_to_dict(analysis), indent=2))
            print(f"\n  Saved to {out_path}")
            if input("  Also print to stdout? [y/N]: ").strip().lower() == "y":
                print(json.dumps(analysis_to_dict(analysis), indent=2))
            input("  Press Enter to return to menu...")

        elif choice == "3":
            run_generate(analysis)
            input("  Press Enter to return to menu...")

        elif choice == "4":
            run_setup(analysis)
            input("  Press Enter to return to menu...")

        elif choice == "5":
            run_sync(analysis)
            input("  Press Enter to return to menu...")

        elif choice == "6":
            if not (OUTPUT_DIR / "index.js").exists():
                print("  Run Generate first (option 3).")
                input("  Press Enter..."); continue
            run_deploy(analysis)
            input("  Press Enter to return to menu...")

        elif choice == "7":
            run_verify(analysis)
            input("  Press Enter to return to menu...")

        elif choice == "8":
            print("\n  Running all steps...\n")
            analysis         = JournalAnalysis(shortcut=shortcut)
            analysis.folders = discover_folders(shortcut)
            analysis.vhosts  = discover_vhosts(shortcut)
            validate(analysis)
            print_report(analysis)
            if not run_generate(analysis):
                print("  ✗ Generate failed — aborting.")
                input("  Press Enter to return to menu...")
                continue
            if not run_setup(analysis):
                print("  ✗ Setup failed — aborting.")
                input("  Press Enter to return to menu...")
                continue
            if not run_sync(analysis):
                print("  ✗ Sync failed — aborting.")
                input("  Press Enter to return to menu...")
                continue
            if not run_deploy(analysis):
                print("  ✗ Deploy failed — aborting.")
                input("  Press Enter to return to menu...")
                continue
            run_verify(analysis)
            input("  Press Enter to return to menu...")

        elif choice == "c":
            clear_credentials()
            print("  Credentials cleared — you will be prompted again on next API call.")
            time.sleep(1)

        else:
            print(f"  Unknown option '{choice}'.")
            time.sleep(0.5)

# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    args     = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags    = {a for a in sys.argv[1:] if a.startswith("--")}
    json_out = "--json"     in flags
    generate = "--generate" in flags
    deploy   = "--deploy"   in flags
    verify   = "--verify"   in flags
    setup    = "--setup"    in flags
    sync     = "--sync"     in flags

    if len(args) != 1:
        print(f"Usage: {sys.argv[0]} <journal_shortcut> [flags]")
        print(f"  (no flags)   interactive menu")
        print(f"  --json       export analysis as JSON")
        print(f"  --generate   generate Worker files")
        print(f"  --setup      create R2 bucket + folders")
        print(f"  --sync       sync content via rclone")
        print(f"  --deploy     deploy Worker via Cloudflare API")
        print(f"  --verify     verify redirects")
        print()
        print(f"  Env vars for API steps:")
        print("    CF_ACCOUNT_ID  CF_API_TOKEN  CF_ZONE_ID_ARTICLES  [CF_ZONE_ID_*]")
        sys.exit(1)

    shortcut = args[0].strip().lower()

    if not any([json_out, generate, deploy, verify, setup, sync]):
        run_menu(shortcut)
        return

    analysis         = JournalAnalysis(shortcut=shortcut)
    analysis.folders = discover_folders(shortcut)
    analysis.vhosts  = discover_vhosts(shortcut)
    validate(analysis)

    if json_out:  print(json.dumps(analysis_to_dict(analysis), indent=2))
    else:         print_report(analysis)

    if generate and not run_generate(analysis): return
    if setup and not run_setup(analysis): return
    if sync and not run_sync(analysis): return
    if deploy and not run_deploy(analysis): return
    if verify: run_verify(analysis)

    if analysis.errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
