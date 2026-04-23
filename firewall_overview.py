#!/usr/bin/env python3
"""
firewall_overview.py  –  Auto-detects iptables/nftables, picks the best parser,
and displays a color-coded firewall rule overview incl. NAT/DNAT.

Auto-detection logic:
  1. iptables-save  →  if it returns ≥3 -A rule lines, use iptables engine
     (covers iptables-legacy AND iptables-nft; gives full multiport/ctstate detail)
  2. nft -j list ruleset  →  fallback for pure nftables systems
Override with: --backend iptables | nft
"""

import subprocess, re, sys, json, socket, argparse
from collections import defaultdict

# ── Colors ────────────────────────────────────────────────────────────────────
R="\033[0m"; B="\033[1m"; RED="\033[31m"; GRN="\033[32m"
YEL="\033[33m"; CYN="\033[36m"; MGT="\033[35m"; GRY="\033[90m"

# ── Shared: output helpers ────────────────────────────────────────────────────
def strip_ansi(s):
    return re.sub(r"\x1b\[[0-9;]*m", "", s)

class Tee:
    def __init__(self, path):
        self.terminal = sys.stdout
        self.file = open(path, "w", encoding="utf-8")
    def write(self, msg):
        self.terminal.write(msg)
        self.file.write(strip_ansi(msg))
    def flush(self):
        self.terminal.flush(); self.file.flush()
    def close(self):
        self.file.close()

# ── Shared: port labels ───────────────────────────────────────────────────────
PORT_NAMES = {
    "22":"SSH","80":"HTTP","443":"HTTPS","53":"DNS",
    "67":"DHCP-srv","68":"DHCP-cli","8080":"HTTP-alt","8081":"HTTP-alt",
    "8443":"PCE-UI","8444":"PCE-Cluster","3306":"MySQL",
    "3389":"RDP","23":"Telnet","33434:33523":"Traceroute",
    "33434-33523":"Traceroute",
}

def port_label(p):
    if not p: return "any"
    for k, v in PORT_NAMES.items():
        if p == k: return f"{p} ({v})"
    return p

# ── Shared: table layout ──────────────────────────────────────────────────────
W = [4, 6, 20, 16, 26, 28, 8]
TOTAL_W = sum(W) + 2 * (len(W) - 1)

def hdr():
    cols = ["#","Proto","Src","Dst-IP","Port / Service","State / Condition","Action"]
    return (B + "  ".join(f"{c:<{w}}" for c, w in zip(cols, W)) + R
            + "\n" + "─" * TOTAL_W)

def fmt_action(action):
    if action == "ALLOW":   return f"{B}{GRN}ALLOW {R}"
    if action == "DROP":    return f"{B}{RED}DROP  {R}"
    if action == "->DNAT":  return f"{B}{MGT}->DNAT{R}"
    if action == "MASQ":    return f"{B}{MGT}MASQ  {R}"
    return f"{GRY}{str(action):<6}{R}"

def _col(v, w):
    """Fit string v into exactly w visible characters, truncating with … if needed."""
    visible = re.sub(r"\x1b\[[0-9;]*m", "", v)
    if len(visible) > w:
        v = visible[:w-1] + "…"
        visible = v
    return v + " " * (w - len(visible))

def fmt_row(n, r, row_type="rule"):
    dp    = port_label(r.get("dport","")) if r.get("dport") else ""
    sp    = f"src:{r['sport']}"           if r.get("sport") else ""
    port  = ", ".join(x for x in [dp, sp] if x) or "any"
    state = r.get("state") or "any"
    src   = r.get("src","any")
    dst   = r.get("dst","any")
    iface = r.get("iface","")
    neg_i = r.get("neg_iface", False)
    if iface and neg_i:
        state = f"! via {iface}" + (f"  ->  {state}" if r.get("state") else "")
    elif iface and row_type == "rule":
        src += f"[{iface}]"

    num_col = f"{GRY}NAT{R}" if row_type == "nat" else str(n)
    vals = [num_col, r.get("proto","any"), src, dst, port, state]
    line = "  ".join(_col(v, w) for v, w in zip(vals, W)) + "  "
    line += fmt_action(r.get("action",""))
    if r.get("note"):
        nc = MGT if row_type == "nat" else GRY
        line += f"\n      {nc}-> {r['note']}{R}"
    extra_ips = r.get("extra_ips", [])
    if extra_ips:
        col_idx = 2 if r.get("ipset_col") != "dst" else 3
        offset  = sum(W[:col_idx]) + 2 * col_idx
        for ip in extra_ips:
            line += f"\n{' ' * offset}{GRY}{ip}{R}"
    return line

def print_section(title, color, rows, direction):
    sep = color + "═" * TOTAL_W + R
    print(f"\n{B}{color}{sep}{R}")
    print(f"{B}{color}  {direction}  –  {title}{R}")
    print(f"{B}{color}{sep}{R}")
    print(hdr())
    seq = 0
    for r in rows:
        rt = r.get("row_type", "rule")
        if rt == "separator":
            print(f"\n  {B}{GRY}── {r['label']} ──{R}")
        elif rt == "nat":
            print(fmt_row("NAT", r, "nat"))
        else:
            seq += 1
            print(fmt_row(seq, r, "rule"))
    print("─" * TOTAL_W)

def separator(label):
    return dict(row_type="separator", label=label)

def static_row(state, action, note=""):
    return dict(proto="any", src="any", dst="any", dport="", sport="",
                state=state, iface="", neg_iface=False,
                action=action, note=note, row_type="rule")

def mk_nat(proto, src, dst, dport, state, action, note,
           neg_iface=False, iface="", dnat_to=""):
    return dict(proto=proto, src=src, dst=dst, dport=dport, sport="",
                state=state, iface=iface, neg_iface=neg_iface,
                action=action, note=note, dnat_to=dnat_to, row_type="nat")

# ══════════════════════════════════════════════════════════════════════════════
# iptables ENGINE  (reads iptables-save text)
# ══════════════════════════════════════════════════════════════════════════════

def load_ipsets():
    """Return {set_name: [ip, ...]} by parsing `sudo ipset list`."""
    result = {}
    try:
        r = subprocess.run(["sudo", "ipset", "list"],
                           capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return result
        name = None; in_members = False
        for line in r.stdout.splitlines():
            line = line.rstrip()
            if line.startswith("Name:"):
                name = line.split(":", 1)[1].strip()
                result[name] = []; in_members = False
            elif line == "Members:":
                in_members = True
            elif in_members:
                if line and re.match(r"[\d:a-fA-F./]", line):
                    result[name].append(line.strip())
                elif line:
                    in_members = False
    except Exception:
        pass
    return result

def ipt_parse(raw):
    chains = defaultdict(list); policies = {}
    all_chains = defaultdict(list); cur = None
    for line in raw.splitlines():
        s = line.strip()
        if s.startswith("*"):
            cur = s[1:]; continue
        if s.startswith(":"):
            m = re.match(r":(\S+)\s+(ACCEPT|DROP|REJECT)", s)
            if m: policies[m.group(1)] = m.group(2)
        elif s.startswith("-A "):
            m = re.match(r"-A (\S+)\s+(.*)", s)
            if m:
                all_chains[(cur, m.group(1))].append(m.group(2))
                if cur == "filter":
                    chains[m.group(1)].append(m.group(2))
    return chains, policies, all_chains

def ipt_chain_final(name, chains, seen=None):
    if seen is None: seen = set()
    if name in seen: return "ALLOW"
    seen.add(name)
    for rule in chains.get(name, []):
        if re.search(r"-j\s+(DROP|REJECT)\b", rule): return "DROP"
        m = re.search(r"-[jg]\s+(ILO-FILTER-ACTION-\S+)", rule)
        if m and ipt_chain_final(m.group(1), chains, seen.copy()) == "DROP":
            return "DROP"
    return "ALLOW"

def _ipset_short(name):
    """Abbreviated set name for the narrow Src/Dst column."""
    return ("{" + name[:11] + "..}") if len(name) > 13 else ("{" + name + "}")

def ipt_parse_rule(raw_rule, chains, ipsets=None):
    if ipsets is None: ipsets = {}
    def g(pat, default=""):
        m = re.search(pat, raw_rule); return m.group(1) if m else default
    proto  = g(r"(?<!\S)-p\s+(\S+)",  "any")
    src    = g(r"(?<!\S)-s\s+(\S+)",  "any")
    dst    = g(r"(?<!\S)-d\s+(\S+)",  "any")
    dport  = g(r"--dports?\s+(\S+)")
    sport  = g(r"--sports?\s+(\S+)")
    state  = g(r"--ctstate\s+(\S+)")
    iface  = g(r"(?<!\S)-[io]\s+(\S+)")
    target = g(r"(?:^|\s)-[jg]\s+(\S+)")

    if   re.search(r"\b(DROP|REJECT)\b", target): action = "DROP"
    elif target in ("ACCEPT", "RETURN"):          action = "ALLOW"
    elif target.startswith("ILO-FILTER-ACTION-"): action = ipt_chain_final(target, chains)
    elif target.startswith("ILO-FILTER-"):        action = None
    elif target == "":                            action = None
    else:                                         action = "ALLOW"

    extra_ips = []; ipset_col = ""
    ms = re.search(r"--match-set\s+(\S+)\s+(src|dst)", raw_rule)
    if ms:
        set_name, direction = ms.group(1), ms.group(2)
        ips = ipsets.get(set_name, [])
        if direction == "src":
            src = ips[0] if ips else "any"
        else:
            dst = ips[0] if ips else "any"
        extra_ips = ips[1:]
        ipset_col = direction

    return dict(proto=proto, src=src, dst=dst, dport=dport, sport=sport,
                state=state, iface=iface, neg_iface=False,
                action=action, note="", extra_ips=extra_ips, ipset_col=ipset_col, row_type="rule")

IPT_SKIP = [
    r"--ctstate\s+(RELATED,ESTABLISHED|UNTRACKED)",
    r"-[io]\s+lo\b",
    r"ILO-FILTER-NS-LOG",
]

def ipt_get_effective_chain(filter_chains, base):
    for rule in filter_chains.get(base, []):
        m = re.search(r"-[jg]\s+(\S+)", rule)
        if m and m.group(1) in filter_chains:
            return m.group(1)
    return base

def ipt_collect_raw(all_chains):
    rows = []
    for rule in all_chains.get(("raw","PREROUTING"), []):
        m_t = re.search(r"(?:^|\s)-j\s+(\S+)", rule)
        if not m_t or m_t.group(1) not in ("DROP","REJECT","ACCEPT","RETURN"): continue
        proto = re.search(r"(?<!\S)-p\s+(\S+)", rule)
        dst   = re.search(r"(?<!\S)-d\s+(\S+)", rule)
        dport = re.search(r"--dports?\s+(\S+)", rule)
        m_ni  = re.search(r"!\s*-i\s+(\S+)", rule)
        dst_v = dst.group(1) if dst else "any"
        note  = "Direct access to Docker container blocked" if dst and re.match(r"172\.", dst_v) else ""
        rows.append(mk_nat(
            proto.group(1) if proto else "any", "any", dst_v,
            dport.group(1) if dport else "any",
            f"! via {m_ni.group(1)}" if m_ni else "any",
            "DROP" if m_t.group(1) in ("DROP","REJECT") else "ALLOW",
            note
        ))
    return rows

def ipt_collect_dnat(all_chains, table, chain_name, seen=None):
    if seen is None: seen = set()
    if chain_name in seen: return []
    seen.add(chain_name); rows = []
    for rule in all_chains.get((table, chain_name), []):
        m_t = re.search(r"(?:^|\s)-j\s+(\S+)", rule)
        if not m_t: continue
        target = m_t.group(1)
        if target == "DNAT":
            proto  = re.search(r"(?<!\S)-p\s+(\S+)", rule)
            dport  = re.search(r"--dports?\s+(\S+)", rule)
            to_dst = re.search(r"--to-destination\s+(\S+)", rule)
            m_ni   = re.search(r"!\s*-i\s+(\S+)", rule)
            state_m= re.search(r"--ctstate\s+(\S+)", rule)
            conds  = []
            if m_ni:    conds.append(f"! via {m_ni.group(1)}")
            if state_m: conds.append(f"->  {state_m.group(1)} conn")
            dp = dport.group(1)  if dport  else ""
            to = to_dst.group(1) if to_dst else "?"
            rows.append(mk_nat(
                proto.group(1) if proto else "any", "any", "<server>", dp,
                "  ".join(conds) if conds else "any", "->DNAT",
                f"Forwarded to {to}  –  traffic continues via FORWARD (bypasses INPUT)",
                dnat_to=to
            ))
        elif (table, target) in all_chains:
            rows.extend(ipt_collect_dnat(all_chains, table, target, seen))
    return rows

def ipt_collect_ingress(filter_chains, all_chains, policies, ipsets=None):
    if ipsets is None: ipsets = {}
    rows = [separator("Step 1 – RAW PREROUTING (before DNAT)")]
    rows.extend(ipt_collect_raw(all_chains))

    dnat_rows = ipt_collect_dnat(all_chains, "nat", "PREROUTING")
    rows.append(separator("Step 2 – NAT PREROUTING (DNAT – before INPUT filter!)"))
    rows.extend(dnat_rows)
    dnat_ports = {r["dport"] for r in dnat_rows if r.get("dport")}

    input_chain = ipt_get_effective_chain(filter_chains, "INPUT")
    rows.append(separator(f"Step 3 – INPUT filter ({input_chain})"))
    rows.append(static_row("lo interface",        "ALLOW"))
    rows.append(static_row("RELATED,ESTABLISHED", "ALLOW"))

    added_default = False
    for raw_rule in filter_chains.get(input_chain, []):
        if any(re.search(p, raw_rule) for p in IPT_SKIP): continue
        m_t = re.search(r"-[jg]\s+(\S+)", raw_rule)
        if m_t:
            t = m_t.group(1)
            if t.endswith("-ENFORCE") or (t not in filter_chains and t not in
                    ("DROP","REJECT","ACCEPT","RETURN","MASQUERADE","DNAT","SNAT","LOG")):
                action = ipt_chain_final(t, filter_chains) if t in filter_chains \
                         else policies.get("INPUT", "ACCEPT")
                rows.append(static_row("DEFAULT (no match above)", action,
                                       "All connections not explicitly covered above"))
                added_default = True; continue
        r = ipt_parse_rule(raw_rule, filter_chains, ipsets)
        if r["action"] is not None:
            if r["action"] == "DROP" and r.get("dport") in dnat_ports:
                r["note"] = "Illumio enforcement – applies only to traffic NOT redirected via DNAT"
            rows.append(r)
    if not added_default:
        rows.append(static_row("DEFAULT (no match above)", policies.get("INPUT","ACCEPT"),
                               "All connections not explicitly covered above"))
    return rows, dnat_ports

def ipt_collect_egress(filter_chains, policies, ipsets=None):
    if ipsets is None: ipsets = {}
    output_chain = ipt_get_effective_chain(filter_chains, "OUTPUT")
    rows = [separator(f"Step – OUTPUT filter ({output_chain})")]
    rows.append(static_row("lo interface",        "ALLOW"))
    rows.append(static_row("RELATED,ESTABLISHED", "ALLOW"))

    added_default = False
    for raw_rule in filter_chains.get(output_chain, []):
        if any(re.search(p, raw_rule) for p in IPT_SKIP): continue
        m_t = re.search(r"-[jg]\s+(\S+)", raw_rule)
        if m_t:
            t = m_t.group(1)
            if t.endswith("-ENFORCE") or (t not in filter_chains and t not in
                    ("DROP","REJECT","ACCEPT","RETURN","MASQUERADE","DNAT","SNAT","LOG")):
                action = ipt_chain_final(t, filter_chains) if t in filter_chains \
                         else policies.get("OUTPUT", "ACCEPT")
                rows.append(static_row("DEFAULT (no match above)", action,
                                       "No explicit DROP for outbound traffic"))
                added_default = True; continue
        r = ipt_parse_rule(raw_rule, filter_chains, ipsets)
        if r["action"] is not None:
            rows.append(r)
    if not added_default:
        rows.append(static_row("DEFAULT (no match above)", policies.get("OUTPUT","ACCEPT"),
                               "No explicit DROP for outbound traffic"))
    return rows

def run_iptables(raw_text, hostname, outfile, backend_label):
    tee = Tee(outfile); sys.stdout = tee
    bar = "═" * TOTAL_W
    print(f"\n{B}{bar}{R}")
    print(f"{B}  Firewall Overview  –  {hostname}  [{backend_label}]{R}")
    print(f"{B}{bar}{R}")

    filter_chains, policies, all_chains = ipt_parse(raw_text)
    ipsets = load_ipsets()

    print(f"\n{B}Default Policies (*filter):{R}")
    for ch in ("INPUT","FORWARD","OUTPUT"):
        p = policies.get(ch,"ACCEPT"); c = GRN if p=="ACCEPT" else RED
        print(f"  {ch:<12}: {B}{c}{p}{R}")

    ingress, dnat_ports = ipt_collect_ingress(filter_chains, all_chains, policies, ipsets)
    egress              = ipt_collect_egress(filter_chains, policies, ipsets)

    print_section("INPUT chain",  CYN, ingress, "INGRESS")
    print_section("OUTPUT chain", YEL, egress,  "EGRESS")

    i_dnat = [r for r in ingress if r.get("action") == "->DNAT"]

    def has_dnat(dp):
        return any(p in dnat_ports for p in dp.split(","))

    i_allow = [r for r in ingress if r.get("row_type")=="rule" and r.get("action")=="ALLOW"
               and r.get("dport") and not has_dnat(r["dport"])]
    i_drop  = [r for r in ingress if r.get("row_type")=="rule" and r.get("action")=="DROP"
               and r.get("dport") and not has_dnat(r["dport"])]
    e_allow = [r for r in egress  if r.get("row_type")=="rule" and r.get("action")=="ALLOW"
               and r.get("dport")]
    e_drop  = [r for r in egress  if r.get("row_type")=="rule" and r.get("action")=="DROP"
               and r.get("dport")]

    print(f"\n{B}SUMMARY:{R}")
    print(f"  {GRN}+ INGRESS ALLOW:{R}  "
          + ", ".join(f"{port_label(r['dport'])} [{r['proto']}]" for r in i_allow)
          + ",  RELATED/ESTABLISHED")
    if i_drop:
        print(f"  {RED}- INGRESS DROP: {R}  "
              + ", ".join(f"{port_label(r['dport'])} [{r['proto']}]" for r in i_drop))
    if i_dnat:
        print(f"  {MGT}> NAT/DNAT:    {R}  "
              + ", ".join(f"{port_label(r['dport'])} -> {r.get('dnat_to','?')}" for r in i_dnat))
        print(f"  {GRY}               (DNAT ports bypass INPUT filter – traffic routed via FORWARD to container){R}")
    e_allow_str = ", ".join(f"{port_label(r['dport'])} [{r['proto']}]" for r in e_allow)
    print(f"  {YEL}+ EGRESS ALLOW: {R}  "
          + (e_allow_str + ",  " if e_allow_str else "")
          + "RELATED/ESTABLISHED,  DEFAULT ALLOW")
    if e_drop:
        print(f"  {RED}- EGRESS DROP:  {R}  "
              + ", ".join(f"{port_label(r['dport'])} [{r['proto']}]" for r in e_drop))

    tee.close(); sys.stdout = tee.terminal
    print(f"\n  Output written to: {outfile}\n")


# ══════════════════════════════════════════════════════════════════════════════
# nft ENGINE  (reads nft -j list ruleset JSON)
# ══════════════════════════════════════════════════════════════════════════════

def nft_load_sets(ruleset):
    """Return {set_name: [ip, ...]} from native nft set elements."""
    sets = {}
    for item in ruleset:
        if "set" in item:
            s = item["set"]
            name = s.get("name", "")
            elems = s.get("elem", [])
            sets[name] = [str(e) for e in elems if isinstance(e, str)]
    return sets

def nft_apply_sets(f, nft_sets):
    """Replace @SETNAME references in src/dst with the actual IPs."""
    f = dict(f)
    for col in ("src", "dst"):
        val = f.get(col, "")
        if isinstance(val, str) and val.startswith("@"):
            ips = nft_sets.get(val[1:], [])
            f[col]        = ips[0] if ips else "any"
            f["extra_ips"] = ips[1:]
            f["ipset_col"] = col
    return f

def nft_load_ipt_dnat():
    """Supplement DNAT destinations from iptables-save (xt DNAT targets are opaque in nft JSON)."""
    try:
        r = subprocess.run(["sudo","iptables-save","-t","nat"],
                           capture_output=True, text=True, timeout=10)
        dmap = {}
        for line in r.stdout.splitlines():
            m = re.search(r"--dports?\s+(\S+).*--to-destination\s+(\S+)", line)
            if m: dmap[m.group(1)] = m.group(2)
        return dmap
    except Exception:
        return {}

def nft_build_index(ruleset):
    chains = defaultdict(list); policies = {}; hook_chains = []
    for item in ruleset:
        if "chain" in item:
            c = item["chain"]
            key = (c["family"], c["table"], c["name"])
            if "hook" in c:
                hook_chains.append(c)
                policies[key] = c.get("policy","accept")
        elif "rule" in item:
            r = item["rule"]
            chains[(r["family"], r["table"], r["chain"])].append(r)
    return chains, policies, hook_chains

def _fmt_port_val(val):
    if val is None: return ""
    if isinstance(val, int): return str(val)
    if isinstance(val, dict):
        if "range" in val:
            lo, hi = val["range"]; return f"{lo}-{hi}"
        if "set" in val:
            return ",".join(_fmt_port_val(x) for x in val["set"])
    return str(val)

def _fmt_set(val):
    if isinstance(val, dict) and "set" in val:
        return ",".join(str(x) for x in val["set"])
    return str(val) if val else ""

def nft_extract_fields(exprs):
    f = dict(proto="any", src="any", dst="any", dport="", sport="",
             state="", iface="", neg_iface=False, action="", dnat_to="",
             note="", extra_ips=[], ipset_col="", _xt_conntrack=False)

    for expr in exprs:
        if not isinstance(expr, dict): continue

        # verdicts
        for vk in ("accept","drop","return"):
            if vk in expr: f["action"] = vk.upper()
        if "jump" in expr: f["action"] = f"jump:{expr['jump'].get('target','')}"
        if "goto" in expr: f["action"] = f"goto:{expr['goto'].get('target','')}"
        if "dnat" in expr:
            addr = expr["dnat"].get("addr",""); port = expr["dnat"].get("port","")
            f["action"] = "->DNAT"
            f["dnat_to"] = f"{addr}:{port}" if port else str(addr)

        # xtables extensions (iptables-nft compatibility)
        if "xt" in expr:
            xt = expr["xt"]
            if xt.get("type") == "target" and xt.get("name") == "DNAT":
                f["action"] = "->DNAT"
            elif xt.get("type") == "match" and xt.get("name") == "conntrack":
                f["_xt_conntrack"] = True
            elif xt.get("type") == "match" and xt.get("name") == "multiport":
                if not f["dport"]: f["dport"] = "(multiport)"

        # match expressions
        if "match" in expr:
            m    = expr["match"]; op = m.get("op","==")
            left = m.get("left",{}); right = m.get("right")

            # Protocol: meta l4proto
            if isinstance(left, dict) and left.get("meta",{}).get("key") == "l4proto":
                f["proto"] = ",".join(str(x) for x in right["set"]) \
                             if isinstance(right, dict) and "set" in right else str(right)

            # Protocol: ip.protocol (iptables-nft style)
            if isinstance(left, dict) and "payload" in left:
                pl = left["payload"]
                if pl.get("protocol") == "ip" and pl.get("field") == "protocol":
                    f["proto"] = str(right)

            # src/dst IP  (right may be "@SETNAME" for named set lookups)
            if isinstance(left, dict) and "payload" in left:
                pl = left["payload"]
                if pl.get("protocol") in ("ip","ip6"):
                    if pl.get("field") == "saddr":
                        f["src"] = str(right) if op == "==" else f"!{right}"
                    elif pl.get("field") == "daddr":
                        f["dst"] = str(right) if op == "==" else f"!{right}"

            # interface (iifname/oifname = name match; iif/oif = index match)
            if isinstance(left, dict) and "meta" in left:
                key = left["meta"].get("key","")
                if key in ("iifname","oifname","iif","oif"):
                    f["iface"] = str(right); f["neg_iface"] = (op == "!=")

            # ports
            if isinstance(left, dict) and "payload" in left:
                pl = left["payload"]
                if pl.get("protocol") in ("tcp","udp"):
                    if pl.get("field") == "dport":
                        f["proto"] = pl["protocol"]; f["dport"] = _fmt_port_val(right)
                    elif pl.get("field") == "sport":
                        f["sport"] = _fmt_port_val(right)

            # connection state
            if isinstance(left, dict) and left.get("ct",{}).get("key") == "state":
                f["state"] = _fmt_set(right)

    return f

NFT_SKIP_CHAINS = {"ILO-FILTER-NS-LOG","ILO-FILTER-CONNTRACK"}

def nft_should_skip(f):
    action = f["action"]
    if action.startswith(("jump:","goto:")):
        if action.split(":",1)[1] in NFT_SKIP_CHAINS: return True
    state = f["state"]
    if state and all(s.lower() in ("related","established","untracked")
                     for s in re.split(r"[,\s]+", state)):
        return True
    if f["iface"] and not f["neg_iface"] and f["iface"] in ("lo","lo0"): return True
    if f.get("_xt_conntrack") and action in ("RETURN","return"): return True
    return False

def nft_chain_final(table, chain, chains, family="ip", seen=None):
    if seen is None: seen = set()
    key = (family, table, chain)
    if key in seen: return "ALLOW"
    seen.add(key)
    for rule in chains.get(key, []):
        f = nft_extract_fields(rule.get("expr",[]))
        if f["action"] in ("DROP","REJECT"): return "DROP"
        if f["action"] in ("ACCEPT",):       return "ALLOW"
        if f["action"].startswith(("jump:","goto:")):
            t = f["action"].split(":",1)[1]
            if nft_chain_final(table, t, chains, family, seen.copy()) == "DROP":
                return "DROP"
    return "ALLOW"

def nft_resolve_action(f, table, chains, family="ip"):
    action = f["action"]
    if action in ("ACCEPT","RETURN"): return "ALLOW"
    if action in ("DROP","REJECT"):   return "DROP"
    if action == "->DNAT":            return "->DNAT"
    if action.startswith(("jump:","goto:")):
        t = action.split(":",1)[1]
        if t in NFT_SKIP_CHAINS:           return None
        if t.startswith("ILO-FILTER-"):
            return nft_chain_final(table, t, chains, family)
        return "ALLOW"
    return None

def nft_collect_raw_drops(chains, family="ip", table="raw", chain_name="PREROUTING"):
    rows = []
    for rule in chains.get((family, table, chain_name), []):
        f = nft_extract_fields(rule.get("expr",[]))
        if f["action"] in ("DROP","REJECT"):
            note = "Direct access to Docker container blocked" if f["dst"].startswith("172.") else ""
            rows.append({**f, "row_type":"nat", "note":note})
    return rows

def nft_collect_dnat(chains, ipt_dnat_map=None, table="nat", chain_name="PREROUTING",
                     family="ip", seen=None):
    if seen is None: seen = set()
    if ipt_dnat_map is None: ipt_dnat_map = {}
    key = (family, table, chain_name)
    if key in seen: return []
    seen.add(key); rows = []
    for rule in chains.get(key, []):
        f = nft_extract_fields(rule.get("expr",[]))
        if f["action"] == "->DNAT":
            if not f["dnat_to"] and f["dport"] and f["dport"] in ipt_dnat_map:
                f = {**f, "dnat_to": ipt_dnat_map[f["dport"]]}
            rows.append(f)
        elif f["action"].startswith(("jump:","goto:")):
            rows.extend(nft_collect_dnat(chains, ipt_dnat_map, table,
                                         f["action"].split(":",1)[1], family, seen))
    return rows

def nft_get_effective_chain(chains, table, base, family="ip"):
    for rule in chains.get((family, table, base), []):
        f = nft_extract_fields(rule.get("expr",[]))
        action = f["action"]
        if action.startswith(("jump:","goto:")):
            t = action.split(":",1)[1]
            if (family, table, t) in chains: return t
    return base

def nft_collect_ingress(chains, policies, nft_sets=None, family="ip", table="filter",
                        input_base="INPUT", raw_base=None, nat_base=None, ipt_dnat_map=None):
    if nft_sets is None: nft_sets = {}
    rows = []

    rows.append(separator("Step 1 – RAW PREROUTING (before DNAT)"))
    if raw_base:
        rows.extend(nft_collect_raw_drops(chains, family, table, raw_base))

    nat_tbl = table if nat_base else "nat"
    nat_chn = nat_base or "PREROUTING"
    dnat_rules = nft_collect_dnat(chains, ipt_dnat_map, nat_tbl, nat_chn, family)
    dnat_ports = {f["dport"] for f in dnat_rules if f.get("dport")}
    rows.append(separator("Step 2 – NAT PREROUTING (DNAT – before INPUT filter!)"))
    for f in dnat_rules:
        note = (f"Forwarded to {f['dnat_to']}  –  traffic continues via FORWARD (bypasses INPUT)"
                if f.get("dnat_to") else "DNAT – traffic continues via FORWARD (bypasses INPUT)")
        rows.append({**f, "dst":"<server>", "row_type":"nat", "note":note})

    input_chain = nft_get_effective_chain(chains, table, input_base, family)
    rows.append(separator(f"Step 3 – INPUT filter ({input_chain})"))
    rows.append(static_row("lo interface",        "ALLOW"))
    rows.append(static_row("RELATED,ESTABLISHED", "ALLOW"))

    added_default = False
    for rule in chains.get((family, table, input_chain), []):
        f = nft_extract_fields(rule.get("expr",[]))
        f = nft_apply_sets(f, nft_sets)
        if nft_should_skip(f): continue
        action = nft_resolve_action(f, table, chains, family)

        raw_action = f["action"]
        if raw_action.startswith(("jump:","goto:")):
            t = raw_action.split(":",1)[1]
            if t.endswith("-ENFORCE") or \
               (not t.startswith("ILO-FILTER-") and (family,table,t) not in chains):
                pol = nft_chain_final(table, t, chains, family) \
                      if (family,table,t) in chains \
                      else policies.get((family,table,input_base),"accept").upper()
                rows.append(static_row("DEFAULT (no match above)", pol,
                                       "All connections not explicitly covered above"))
                added_default = True; continue

        if action is None: continue
        note = ""
        if action == "DROP" and f.get("dport") and \
                any(p in dnat_ports for p in f["dport"].split(",")):
            note = "Illumio enforcement – applies only to traffic NOT redirected via DNAT"
        rows.append({**f, "action":action, "note":note, "row_type":"rule"})

    if not added_default:
        pol = policies.get((family,table,input_base),"accept").upper()
        rows.append(static_row("DEFAULT (no match above)", pol,
                               "All connections not explicitly covered above"))
    return rows, dnat_ports

def nft_collect_egress(chains, policies, nft_sets=None, family="ip", table="filter", output_base="OUTPUT"):
    if nft_sets is None: nft_sets = {}
    output_chain = nft_get_effective_chain(chains, table, output_base, family)
    rows = [separator(f"Step – OUTPUT filter ({output_chain})")]
    rows.append(static_row("lo interface",        "ALLOW"))
    rows.append(static_row("RELATED,ESTABLISHED", "ALLOW"))

    added_default = False
    for rule in chains.get((family, table, output_chain), []):
        f = nft_extract_fields(rule.get("expr",[]))
        f = nft_apply_sets(f, nft_sets)
        if nft_should_skip(f): continue
        action = nft_resolve_action(f, table, chains, family)

        raw_action = f["action"]
        if raw_action.startswith(("jump:","goto:")):
            t = raw_action.split(":",1)[1]
            if t.endswith("-ENFORCE") or \
               (not t.startswith("ILO-FILTER-") and (family,table,t) not in chains):
                pol = nft_chain_final(table, t, chains, family) \
                      if (family,table,t) in chains \
                      else policies.get((family,table,output_base),"accept").upper()
                rows.append(static_row("DEFAULT (no match above)", pol,
                                       "No explicit DROP for outbound traffic"))
                added_default = True; continue

        if action is None: continue
        rows.append({**f, "action":action, "note":"", "row_type":"rule"})

    if not added_default:
        pol = policies.get((family,table,output_base),"accept").upper()
        rows.append(static_row("DEFAULT (no match above)", pol,
                               "No explicit DROP for outbound traffic"))
    return rows

def run_nft(ruleset, ipt_dnat_map, hostname, outfile, backend_label):
    tee = Tee(outfile); sys.stdout = tee
    bar = "═" * TOTAL_W
    print(f"\n{B}{bar}{R}")
    print(f"{B}  Firewall Overview  –  {hostname}  [{backend_label}]{R}")
    print(f"{B}{bar}{R}")

    chains, policies, hook_chains = nft_build_index(ruleset)
    nft_sets = nft_load_sets(ruleset)

    # Detect the family and table that contains the ILO enforcement chains
    family, ilo_table = "ip", "filter"
    for c in hook_chains:
        if "ILO" in c.get("table","") and c.get("hook"):
            family = c["family"]; ilo_table = c["table"]; break

    def _hook_chain(hook, hint=""):
        for c in hook_chains:
            if c["family"]==family and c["table"]==ilo_table and c.get("hook")==hook:
                if not hint or hint in c["name"]: return c["name"]
        return None

    input_base  = _hook_chain("input")  or "INPUT"
    output_base = _hook_chain("output") or "OUTPUT"
    raw_base    = _hook_chain("prerouting", "RAW")
    nat_base    = _hook_chain("prerouting", "NAT")

    print(f"\n{B}Default Policies ({family} {ilo_table}):{R}")
    seen_hooks = set()
    for hook in ("input","forward","output"):
        for c in hook_chains:
            if c["family"] != family or c["table"] != ilo_table or c.get("hook") != hook: continue
            hk = (family, ilo_table, hook)
            if hk in seen_hooks: continue
            seen_hooks.add(hk)
            pol = c.get("policy","accept").upper()
            col = GRN if pol == "ACCEPT" else RED
            print(f"  {c['name']:<12}: {B}{col}{pol}{R}")

    ingress, dnat_ports = nft_collect_ingress(
        chains, policies, nft_sets, family, ilo_table,
        input_base, raw_base, nat_base, ipt_dnat_map)
    egress     = nft_collect_egress(chains, policies, nft_sets, family, ilo_table, output_base)
    dnat_rules = nft_collect_dnat(chains, ipt_dnat_map, ilo_table, nat_base or "PREROUTING", family)

    print_section("INPUT chain",  CYN, ingress, "INGRESS")
    print_section("OUTPUT chain", YEL, egress,  "EGRESS")

    has_multiport = any(r.get("dport") == "(multiport)"
                        for r in ingress + egress if r.get("row_type") == "rule")

    def _is_real(r):
        dp = r.get("dport",""); return dp and dp != "(multiport)" and not dp.startswith("(")

    i_allow = [r for r in ingress if r.get("action")=="ALLOW" and _is_real(r)
               and not any(p in dnat_ports for p in r["dport"].split(","))]
    i_drop  = [r for r in ingress if r.get("action")=="DROP"  and _is_real(r)
               and not any(p in dnat_ports for p in r["dport"].split(","))]
    e_allow = [r for r in egress  if r.get("action")=="ALLOW" and _is_real(r)]
    e_drop  = [r for r in egress  if r.get("action")=="DROP"  and _is_real(r)]

    print(f"\n{B}SUMMARY:{R}")
    if has_multiport:
        print(f"  {GRY}  Note: Port details for xt-multiport rules (iptables-nft) are opaque in nft JSON.{R}")
        print(f"  {GRY}        Use --backend iptables for full per-port details on this system.{R}")
    print(f"  {GRN}+ INGRESS ALLOW:{R}  "
          + (", ".join(f"{port_label(r['dport'])} [{r['proto']}]" for r in i_allow)
             or "(see xt-multiport rules above)")
          + ",  RELATED/ESTABLISHED")
    if i_drop:
        print(f"  {RED}- INGRESS DROP: {R}  "
              + ", ".join(f"{port_label(r['dport'])} [{r['proto']}]" for r in i_drop))
    if dnat_rules:
        print(f"  {MGT}> NAT/DNAT:    {R}  "
              + ", ".join(f"{port_label(r['dport'])} -> {r['dnat_to']}" for r in dnat_rules))
        print(f"  {GRY}               (DNAT ports bypass INPUT filter – traffic routed via FORWARD to container){R}")
    e_allow_str = ", ".join(f"{port_label(r['dport'])} [{r['proto']}]" for r in e_allow)
    print(f"  {YEL}+ EGRESS ALLOW: {R}  "
          + (e_allow_str + ",  " if e_allow_str else "")
          + "RELATED/ESTABLISHED,  DEFAULT ALLOW")
    if e_drop:
        print(f"  {RED}- EGRESS DROP:  {R}  "
              + ", ".join(f"{port_label(r['dport'])} [{r['proto']}]" for r in e_drop))

    tee.close(); sys.stdout = tee.terminal
    print(f"\n  Output written to: {outfile}\n")


# ══════════════════════════════════════════════════════════════════════════════
# Auto-detection + main
# ══════════════════════════════════════════════════════════════════════════════

def detect_backend():
    """
    Returns (backend_name, data, label).
    Prefers iptables-save when it has actual rules (gives full port detail for
    iptables-nft setups). Falls back to nft JSON for pure nftables systems.
    """
    # 1. Try iptables-save
    ipt_raw = None
    try:
        r = subprocess.run(["sudo","iptables-save"],
                           capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            ipt_raw = r.stdout
            rule_count = sum(1 for l in ipt_raw.splitlines() if l.startswith("-A "))
            if rule_count >= 3:
                # Detect iptables variant for the label
                try:
                    v = subprocess.run(["iptables","--version"],
                                       capture_output=True, text=True, timeout=5)
                    variant = "iptables-nft" if "nf_tables" in v.stdout else "iptables-legacy"
                except Exception:
                    variant = "iptables"
                return "iptables", ipt_raw, f"iptables / {variant} – auto-detected"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # 2. Try nft
    try:
        r = subprocess.run(["sudo","nft","-j","list","ruleset"],
                           capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            data = json.loads(r.stdout)["nftables"]
            rule_count = sum(1 for item in data if "rule" in item)
            if rule_count >= 1:
                return "nft", data, "nftables – auto-detected"
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        pass

    # 3. Fallback: iptables-save had something but very few rules
    if ipt_raw:
        return "iptables", ipt_raw, "iptables – auto-detected (few rules)"

    sys.exit("Error: No firewall backend available (iptables-save and nft both failed).")


def main():
    parser = argparse.ArgumentParser(
        description="Firewall overview – auto-detects iptables/nftables")
    parser.add_argument("-o","--output", metavar="FILE",
                        help="write plain-text output to FILE "
                             "(default: firewall-overview-<hostname>.txt)")
    parser.add_argument("--backend", choices=["auto","iptables","nft"], default="auto",
                        help="force a specific backend (default: auto)")
    args = parser.parse_args()

    hostname = socket.getfqdn()
    outfile  = args.output or f"firewall-overview-{hostname}.txt"

    if args.backend == "auto":
        backend, data, label = detect_backend()
    elif args.backend == "iptables":
        r = subprocess.run(["sudo","iptables-save"], capture_output=True, text=True)
        if r.returncode != 0: sys.exit(f"iptables-save failed: {r.stderr}")
        backend, data, label = "iptables", r.stdout, "iptables – forced"
    else:  # nft
        r = subprocess.run(["sudo","nft","-j","list","ruleset"],
                           capture_output=True, text=True)
        if r.returncode != 0: sys.exit(f"nft failed: {r.stderr}")
        backend, data, label = "nft", json.loads(r.stdout)["nftables"], "nftables – forced"

    if backend == "iptables":
        run_iptables(data, hostname, outfile, label)
    else:
        ipt_dnat_map = nft_load_ipt_dnat()
        run_nft(data, ipt_dnat_map, hostname, outfile, label)


if __name__ == "__main__":
    main()
