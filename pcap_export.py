# -*- coding: utf-8 -*-
"""SOC-friendly exports: STIX 2.1 bundle (IOC indicators + MITRE attack-patterns) and Sigma-style rules."""
import hashlib
import json
import re
import time
import uuid

_NS = uuid.UUID("5b0e3c1e-6a0f-4a52-9f3a-7c5d1d6f0a11")


def _id(kind, key):
    return f"{kind}--{uuid.uuid5(_NS, kind + '|' + str(key))}"


def _q(v):
    return str(v).replace("\\", "\\\\").replace("'", "\\'")


_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_SHA = re.compile(r"^[0-9a-fA-F]{64}$")
_MD5 = re.compile(r"^[0-9a-fA-F]{32}$")


def _pattern(v):
    v = str(v).strip()
    if _IP.match(v):
        return f"[ipv4-addr:value = '{_q(v)}']"
    if _SHA.match(v):
        return f"[file:hashes.'SHA-256' = '{v.lower()}']"
    if _MD5.match(v):
        return f"[file:hashes.MD5 = '{v.lower()}']"
    if re.match(r"^[\w.-]+\.[A-Za-z]{2,}$", v):
        return f"[domain-name:value = '{_q(v.lower())}']"
    return None


def build_stix(findings, corr, source="pcap-analyzer"):
    now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    objs = [{"type": "identity", "spec_version": "2.1", "id": _id("identity", source), "created": now,
             "modified": now, "name": source, "identity_class": "system"}]
    ident = objs[0]["id"]
    seen = set()
    for kind, vals in (corr.get("iocs") or {}).items():
        if kind in ("credentials", "user_agents"):
            continue
        for v in vals:
            pat = _pattern(v)
            if not pat or pat in seen:
                continue
            seen.add(pat)
            objs.append({"type": "indicator", "spec_version": "2.1", "id": _id("indicator", pat), "created": now,
                         "modified": now, "created_by_ref": ident, "name": f"{kind}: {v}", "pattern": pat,
                         "pattern_type": "stix", "valid_from": now, "indicator_types": ["malicious-activity"]})
    techs = {}
    for f in findings:
        m = f.get("mitre")
        if m and m not in techs:
            techs[m] = {"type": "attack-pattern", "spec_version": "2.1", "id": _id("attack-pattern", m), "created": now,
                        "modified": now, "name": f.get("title", m),
                        "external_references": [{"source_name": "mitre-attack", "external_id": str(m).split()[0],
                                                 "url": "https://attack.mitre.org/techniques/" + str(m).split()[0].replace(".", "/") + "/"}]}
    objs.extend(techs.values())
    return {"type": "bundle", "id": f"bundle--{uuid.uuid5(_NS, json.dumps(sorted(seen)))}", "objects": objs}


def sigma_rules(corr):
    iocs = corr.get("iocs") or {}
    out = []
    doms = sorted({str(d).lower() for d in iocs.get("domains", []) if re.match(r"^[\w.-]+\.[A-Za-z]{2,}$", str(d))})[:200]
    ips = sorted({str(i) for i in iocs.get("ips", []) if _IP.match(str(i))})[:200]
    if doms:
        out.append("title: PCAP Analyzer - Malicious domains observed\nid: %s\nstatus: experimental\nlogsource:\n  category: dns\n"
                   "detection:\n  selection:\n    query|endswith:\n%s\n  condition: selection\nlevel: high\ntags:\n  - attack.command_and_control\n"
                   % (uuid.uuid5(_NS, "dom" + ",".join(doms)), "\n".join(f"      - '.{d}'" for d in doms)))
    if ips:
        out.append("title: PCAP Analyzer - Malicious IPs observed\nid: %s\nstatus: experimental\nlogsource:\n  category: firewall\n"
                   "detection:\n  selection:\n    dst_ip:\n%s\n  condition: selection\nlevel: high\ntags:\n  - attack.command_and_control\n"
                   % (uuid.uuid5(_NS, "ip" + ",".join(ips)), "\n".join(f"      - '{i}'" for i in ips)))
    return "\n---\n".join(out)
