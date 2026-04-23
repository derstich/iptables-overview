#!/usr/bin/env python3
"""
nft-overview.py  –  Generic nftables firewall rule overview incl. NAT/DNAT
Reads rules directly via: sudo nft -j list ruleset
Processing order: raw PREROUTING -> NAT PREROUTING (DNAT) -> filter INPUT / FORWARD
"""

import subprocess, sys, json, socket, argparse, re
from collections import defaultdict

R="\033[0m"; B="\033[1m"; RED="\033[31m"; GRN="\033[32m"
YEL="\033[33m"; CYN="\033[36m"; MGT="\033[35m"; GRY="\033[90m"

# ── Load ruleset ──────────────────────────────────────────────────────────────
def load_ruleset():
    r = subprocess.run(["sudo", "nft", "-j", "list", "ruleset"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"Error: nft failed: {r.stderr}")
    return json.loads(r.stdout)["nftables"]

def load_iptables_dnat():
    """Read DNAT destinations from iptables-save (fallback for xt DNAT rules)."""
    try:
        r = subprocess.run(["sudo", "iptables-save", "-t", "nat"],
                           capture_output=True, text=True)
        dnat_map = {}   # dport_str -> dnat_to
        for line in r.stdout.splitlines():
            # -A DOCKER ! -i docker0 -p tcp -m tcp --dport 8081 -j DNAT --to-destination 172.17.0.2:80
            m = re.search(r"--dports?\s+(\S+).*--to-destination\s+(\S+)", line)
            if m:
                dnat_map[m.group(1)] = m.group(2)
        return dnat_map
    except Exception:
        return {}

# ── Build lookup structures ───────────────────────────────────────────────────
def build_index(ruleset):
    """Returns: chains dict keyed (family,table,chain), hook_chains list."""
    chains   = defaultdict(list)   # (family,table,chain) -> [rule, ...]
    policies = {}                  # (family,table,chain) -> accept|drop
    hook_chains = []               # chains with a hook (entry points)

    for item in ruleset:
        if "chain" in item:
            c = item["chain"]
            key = (c["family"], c["table"], c["name"])
            if "hook" in c:
                hook_chains.append(c)
                policies[key] = c.get("policy", "accept")
        elif "rule" in item:
            r = item["rule"]
            key = (r["family"], r["table"], r["chain"])
            chains[key].append(r)

    return chains, policies, hook_chains

# ── nft expression helpers ────────────────────────────────────────────────────
def _match_val(expr, match_key):
    """Extract value from a match expression like {match: {left: {meta/payload/...}, right: val}}"""
    if not isinstance(expr, dict): return None
    m = expr.get("match", {})
    left = m.get("left", {})
    right = m.get("right")
    if isinstance(left, dict) and match_key in str(left):
        return right
    return None

def extract_rule_fields(exprs):
    """Parse a list of nft expressions into a field dict."""
    fields = dict(proto="any", src="any", dst="any", dport="",
                  sport="", state="", iface="", neg_iface=False,
                  action="", dnat_to="", note="", _xt_conntrack=False)

    for expr in exprs:
        if not isinstance(expr, dict):
            continue

        # ── verdict (accept / drop / return / jump / goto / dnat) ────────────
        for verdict_key in ("accept", "drop", "return"):
            if verdict_key in expr:
                fields["action"] = verdict_key.upper()

        if "jump" in expr:
            fields["action"] = f"jump:{expr['jump'].get('target','')}"
        if "goto" in expr:
            fields["action"] = f"goto:{expr['goto'].get('target','')}"
        if "dnat" in expr:
            addr = expr["dnat"].get("addr", "")
            port = expr["dnat"].get("port", "")
            fields["action"]  = "->DNAT"
            fields["dnat_to"] = f"{addr}:{port}" if port else str(addr)

        # ── xtables extensions (iptables-nft compatibility) ───────────────────
        if "xt" in expr:
            xt = expr["xt"]
            if xt.get("type") == "target" and xt.get("name") == "DNAT":
                fields["action"] = "->DNAT"  # destination filled in later
            elif xt.get("type") == "match" and xt.get("name") == "conntrack":
                fields["_xt_conntrack"] = True   # state params opaque; skip if action==RETURN
            elif xt.get("type") == "match" and xt.get("name") == "multiport":
                if not fields["dport"]:
                    fields["dport"] = "(multiport)"

        # ── match expressions ─────────────────────────────────────────────────
        if "match" in expr:
            m    = expr["match"]
            op   = m.get("op", "==")
            left = m.get("left", {})
            right= m.get("right")

            # Protocol (meta l4proto)
            if isinstance(left, dict) and left.get("meta", {}).get("key") == "l4proto":
                if isinstance(right, str):
                    fields["proto"] = right
                elif isinstance(right, dict) and "set" in right:
                    fields["proto"] = ",".join(str(x) for x in right["set"])

            # Protocol (ip.protocol payload field – used by iptables-nft)
            if isinstance(left, dict) and "payload" in left:
                pl = left["payload"]
                if pl.get("protocol") == "ip" and pl.get("field") == "protocol":
                    fields["proto"] = str(right)

            # Source / dest IP
            if isinstance(left, dict) and "payload" in left:
                pl = left["payload"]
                if pl.get("protocol") in ("ip", "ip6"):
                    if pl.get("field") == "saddr":
                        fields["src"] = str(right) if op == "==" else f"!{right}"
                    elif pl.get("field") == "daddr":
                        fields["dst"] = str(right) if op == "==" else f"!{right}"

            # Interface (iifname / oifname)
            if isinstance(left, dict) and "meta" in left:
                key = left["meta"].get("key", "")
                if key in ("iifname", "oifname"):
                    iface = str(right) if isinstance(right, str) else str(right)
                    fields["iface"]     = iface
                    fields["neg_iface"] = (op == "!=")

            # Ports (tcp/udp dport / sport)
            if isinstance(left, dict) and "payload" in left:
                pl = left["payload"]
                if pl.get("protocol") in ("tcp", "udp"):
                    if pl.get("field") == "dport":
                        fields["proto"] = pl["protocol"]
                        fields["dport"] = _fmt_port_val(right)
                    elif pl.get("field") == "sport":
                        fields["sport"] = _fmt_port_val(right)

            # Connection tracking state
            if isinstance(left, dict) and left.get("ct", {}).get("key") == "state":
                fields["state"] = _fmt_set(right)

        # ── counter (ignore) ──────────────────────────────────────────────────
        # ── log, limit (ignore) ──────────────────────────────────────────────

    return fields

def _fmt_port_val(val):
    """Format a port value: int, range dict, or set."""
    if val is None:
        return ""
    if isinstance(val, int):
        return str(val)
    if isinstance(val, dict):
        if "range" in val:
            lo, hi = val["range"]
            return f"{lo}-{hi}"
        if "set" in val:
            return ",".join(_fmt_port_val(x) for x in val["set"])
    return str(val)

def _fmt_set(val):
    if isinstance(val, dict) and "set" in val:
        return ",".join(str(x) for x in val["set"])
    return str(val) if val else ""

# ── Port label ────────────────────────────────────────────────────────────────
PORT_NAMES = {
    "22":"SSH","80":"HTTP","443":"HTTPS","53":"DNS",
    "67":"DHCP-srv","68":"DHCP-cli","8080":"HTTP-alt","8081":"HTTP-alt",
    "8443":"PCE-UI","8444":"PCE-Cluster","3306":"MySQL",
    "3389":"RDP","23":"Telnet","33434-33523":"Traceroute",
}

def port_label(p):
    if not p: return "any"
    for k, v in PORT_NAMES.items():
        if p == k: return f"{p} ({v})"
    return p

# ── Chain action resolver (recursive) ────────────────────────────────────────
def chain_final_action(table, chain_name, chains,
                       family="ip", seen=None):
    if seen is None: seen = set()
    key = (family, table, chain_name)
    if key in seen: return "ALLOW"
    seen.add(key)

    for rule in chains.get(key, []):
        fields = extract_rule_fields(rule.get("expr", []))
        action = fields["action"]
        if action in ("DROP", "REJECT"):
            return "DROP"
        if action.startswith(("jump:", "goto:")):
            target = action.split(":", 1)[1]
            if chain_final_action(table, target, chains, family, seen.copy()) == "DROP":
                return "DROP"
    return "ALLOW"

def resolve_action(fields, table, chains, family="ip"):
    action = fields["action"]
    if action in ("ACCEPT", "RETURN"):
        return "ALLOW"
    if action in ("DROP", "REJECT"):
        return "DROP"
    if action == "->DNAT":
        return "->DNAT"
    if action.startswith(("jump:", "goto:")):
        target = action.split(":", 1)[1]
        if target.startswith("ILO-FILTER-ACTION-"):
            return chain_final_action(table, target, chains, family)
        if target.startswith("ILO-FILTER-"):
            return None  # internal chain, skip
        return "ALLOW"   # unknown jump = implicit allow
    return None

# ── Skip filter ───────────────────────────────────────────────────────────────
SKIP_CHAINS = {"ILO-FILTER-NS-LOG", "ILO-FILTER-CONNTRACK"}

def should_skip(fields):
    action = fields["action"]
    if action.startswith(("jump:", "goto:")):
        target = action.split(":", 1)[1]
        if target in SKIP_CHAINS:
            return True
    state = fields["state"]
    if state and all(s.lower() in ("related", "established", "untracked")
                     for s in re.split(r"[,\s]+", state)):
        return True
    if fields["iface"] and not fields["neg_iface"]:   # specific (non-negated) interface → lo passthrough
        return True
    # xt conntrack RETURN rules = the RELATED/ESTABLISHED passthrough (already shown as static row)
    if fields.get("_xt_conntrack") and action in ("RETURN", "return"):
        return True
    return False

# ── Collect NAT DNAT rules ────────────────────────────────────────────────────
def collect_dnat(chains, ipt_dnat_map=None, table="nat", chain_name="PREROUTING",
                 family="ip", seen=None):
    if seen is None: seen = set()
    if ipt_dnat_map is None: ipt_dnat_map = {}
    key = (family, table, chain_name)
    if key in seen: return []
    seen.add(key)
    rows = []
    for rule in chains.get(key, []):
        fields = extract_rule_fields(rule.get("expr", []))
        if fields["action"] == "->DNAT":
            # Supplement destination from iptables-save if not in native nft expr
            if not fields["dnat_to"] and fields["dport"] and fields["dport"] in ipt_dnat_map:
                fields = {**fields, "dnat_to": ipt_dnat_map[fields["dport"]]}
            rows.append(fields)
        elif fields["action"].startswith(("jump:", "goto:")):
            target = fields["action"].split(":", 1)[1]
            rows.extend(collect_dnat(chains, ipt_dnat_map, table, target, family, seen))
    return rows

# ── Collect RAW PREROUTING drops ──────────────────────────────────────────────
def collect_raw_drops(chains, family="ip"):
    rows = []
    for rule in chains.get((family, "raw", "PREROUTING"), []):
        fields = extract_rule_fields(rule.get("expr", []))
        if fields["action"] in ("DROP", "REJECT"):
            rows.append(fields)
    return rows

# ── Get effective INPUT/OUTPUT chain ─────────────────────────────────────────
def get_effective_chain(chains, table, base, family="ip"):
    for rule in chains.get((family, table, base), []):
        fields = extract_rule_fields(rule.get("expr", []))
        action = fields["action"]
        if action.startswith(("jump:", "goto:")):
            target = action.split(":", 1)[1]
            if (family, table, target) in chains:
                return target
    return base

# ── Formatting ────────────────────────────────────────────────────────────────
W = [4, 6, 14, 20, 26, 30, 8]
TOTAL_W = sum(W) + 2 * (len(W) - 1)

def strip_ansi(s):
    return re.sub(r"\x1b\[[0-9;]*m", "", s)

class Tee:
    def __init__(self, path):
        self.terminal = sys.stdout
        self.file     = open(path, "w", encoding="utf-8")
    def write(self, msg):
        self.terminal.write(msg)
        self.file.write(strip_ansi(msg))
    def flush(self):
        self.terminal.flush()
        self.file.flush()
    def close(self):
        self.file.close()

def hdr():
    cols = ["#", "Proto", "Src", "Dst-IP", "Port / Service", "State / Condition", "Action"]
    return (B + "  ".join(f"{c:<{w}}" for c, w in zip(cols, W)) + R
            + "\n" + "─" * TOTAL_W)

def fmt_action(action):
    if action == "ALLOW":   return f"{B}{GRN}ALLOW {R}"
    if action == "DROP":    return f"{B}{RED}DROP  {R}"
    if action == "->DNAT":  return f"{B}{MGT}->DNAT{R}"
    return f"{GRY}{str(action):<6}{R}"

def fmt_row(n, f, row_type="rule"):
    dp    = port_label(f["dport"])
    sp    = f"src:{f['sport']}" if f["sport"] else ""
    port  = ", ".join(x for x in [dp, sp] if x) or "any"
    state = f["state"] or "any"
    src   = f["src"]
    dst   = f["dst"]
    if f["iface"] and f["neg_iface"]:
        state = f"! via {f['iface']}"
        if f["state"]:
            state += f"  ->  {f['state']}"

    num_col = f"{GRY}NAT{R}" if row_type == "nat" else str(n)
    vals = [num_col, f["proto"], src, dst, port, state]
    line = ""
    for v, w in zip(vals, W):
        visible = re.sub(r"\x1b\[[0-9;]*m", "", v)
        line += v + " " * max(0, w - len(visible)) + "  "
    line += fmt_action(f["action"])
    if f.get("note"):
        nc = MGT if row_type == "nat" else GRY
        line += f"\n      {nc}-> {f['note']}{R}"
    return line

def static_row(state, action, note=""):
    return dict(proto="any", src="any", dst="any", dport="", sport="",
                state=state, iface="", neg_iface=False,
                action=action, dnat_to="", note=note)

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

def nat_entry(f, note=""):
    return {**f, "row_type": "nat", "note": note}

# ── Collect INGRESS rows ──────────────────────────────────────────────────────
def collect_ingress(chains, policies, family="ip", ipt_dnat_map=None):
    table = "filter"
    rows  = []

    # Step 1: RAW PREROUTING drops
    rows.append(separator("Step 1 – raw PREROUTING (before DNAT)"))
    for f in collect_raw_drops(chains, family):
        note = "Direct access to Docker container blocked" if f["dst"].startswith("172.") else ""
        rows.append(nat_entry(f, note))

    # Step 2: NAT DNAT rules
    dnat_rules = collect_dnat(chains, ipt_dnat_map, "nat", "PREROUTING", family)
    dnat_ports = {f["dport"] for f in dnat_rules if f["dport"]}
    rows.append(separator("Step 2 – nat PREROUTING (DNAT – before INPUT filter!)"))
    for f in dnat_rules:
        f = {**f, "dst": "<server>"}
        note = (f"Forwarded to {f['dnat_to']}  –  traffic continues via FORWARD (bypasses INPUT)"
                if f["dnat_to"] else "DNAT – traffic continues via FORWARD (bypasses INPUT)")
        rows.append(nat_entry(f, note))

    # Step 3: INPUT filter chain
    input_chain = get_effective_chain(chains, table, "INPUT", family)
    rows.append(separator(f"Step 3 – INPUT filter ({input_chain})"))
    rows.append({**static_row("lo interface",        "ALLOW"), "row_type": "rule"})
    rows.append({**static_row("RELATED,ESTABLISHED", "ALLOW"), "row_type": "rule"})

    added_default = False
    for rule in chains.get((family, table, input_chain), []):
        f = extract_rule_fields(rule.get("expr", []))
        if should_skip(f):
            continue
        action = resolve_action(f, table, chains, family)

        # Detect end-of-chain (ENFORCE jump)
        raw_action = f["action"]
        if raw_action.startswith(("jump:", "goto:")):
            target = raw_action.split(":", 1)[1]
            if target.endswith("-ENFORCE") or \
               (not target.startswith("ILO-FILTER-") and
                    (family, table, target) not in chains):
                pol = chain_final_action(table, target, chains, family) \
                      if (family, table, target) in chains \
                      else policies.get((family, table, "INPUT"), "ACCEPT").upper()
                rows.append({**static_row("DEFAULT (no match above)", pol,
                                          "All connections not explicitly covered above"),
                             "row_type": "rule"})
                added_default = True
                continue

        if action is None:
            continue

        note = ""
        if action == "DROP" and f["dport"] and any(
                p in dnat_ports for p in f["dport"].split(",")):
            note = "Illumio enforcement – applies only to traffic NOT redirected via DNAT"

        rows.append({**f, "action": action, "note": note, "row_type": "rule"})

    if not added_default:
        pol = policies.get((family, table, "INPUT"), "accept").upper()
        rows.append({**static_row("DEFAULT (no match above)", pol,
                                  "All connections not explicitly covered above"),
                     "row_type": "rule"})
    return rows, dnat_ports

# ── Collect EGRESS rows ───────────────────────────────────────────────────────
def collect_egress(chains, policies, family="ip"):
    table        = "filter"
    output_chain = get_effective_chain(chains, table, "OUTPUT", family)
    rows = [separator(f"Step – OUTPUT filter ({output_chain})")]
    rows.append({**static_row("lo interface",        "ALLOW"), "row_type": "rule"})
    rows.append({**static_row("RELATED,ESTABLISHED", "ALLOW"), "row_type": "rule"})

    added_default = False
    for rule in chains.get((family, table, output_chain), []):
        f = extract_rule_fields(rule.get("expr", []))
        if should_skip(f):
            continue
        action = resolve_action(f, table, chains, family)

        raw_action = f["action"]
        if raw_action.startswith(("jump:", "goto:")):
            target = raw_action.split(":", 1)[1]
            if target.endswith("-ENFORCE") or \
               (not target.startswith("ILO-FILTER-") and
                    (family, table, target) not in chains):
                pol = chain_final_action(table, target, chains, family) \
                      if (family, table, target) in chains \
                      else policies.get((family, table, "OUTPUT"), "ACCEPT").upper()
                rows.append({**static_row("DEFAULT (no match above)", pol,
                                          "No explicit DROP for outbound traffic"),
                             "row_type": "rule"})
                added_default = True
                continue

        if action is None:
            continue
        rows.append({**f, "action": action, "note": "", "row_type": "rule"})

    if not added_default:
        pol = policies.get((family, table, "OUTPUT"), "accept").upper()
        rows.append({**static_row("DEFAULT (no match above)", pol,
                                  "No explicit DROP for outbound traffic"),
                     "row_type": "rule"})
    return rows

# ── Summary ───────────────────────────────────────────────────────────────────
def print_summary(ingress, egress, dnat_rules, dnat_ports):
    has_multiport = any(r.get("dport") == "(multiport)"
                        for r in ingress + egress if r.get("row_type") == "rule")

    def _is_real_port(r):
        dp = r.get("dport", "")
        return dp and dp != "(multiport)" and not dp.startswith("(")

    i_allow = [r for r in ingress if r.get("action") == "ALLOW" and _is_real_port(r)
               and not any(p in dnat_ports for p in r["dport"].split(","))]
    i_drop  = [r for r in ingress if r.get("action") == "DROP"  and _is_real_port(r)
               and not any(p in dnat_ports for p in r["dport"].split(","))]
    e_allow = [r for r in egress  if r.get("action") == "ALLOW" and _is_real_port(r)]
    e_drop  = [r for r in egress  if r.get("action") == "DROP"  and _is_real_port(r)]

    print(f"\n{B}SUMMARY:{R}")
    if has_multiport:
        print(f"  {GRY}  Note: Port details for xt-multiport rules (iptables-nft) are opaque in nft JSON.{R}")
        print(f"  {GRY}        Use iptables_overview.py for full per-port details on this system.{R}")
    print(f"  {GRN}+ INGRESS ALLOW:{R}  "
          + (", ".join(f"{port_label(r['dport'])} [{r['proto']}]" for r in i_allow)
             or "(see xt-multiport rules above)")
          + ",  RELATED/ESTABLISHED")
    if i_drop:
        print(f"  {RED}- INGRESS DROP: {R}  "
              + ", ".join(f"{port_label(r['dport'])} [{r['proto']}]" for r in i_drop))
    if dnat_rules:
        print(f"  {MGT}> NAT/DNAT:    {R}  "
              + ", ".join(f"{port_label(r['dport'])} -> {r['dnat_to']}"
                          for r in dnat_rules))
        print(f"  {GRY}               "
              "(DNAT ports bypass INPUT filter – traffic routed via FORWARD to container)"
              f"{R}")
    e_allow_str = ", ".join(f"{port_label(r['dport'])} [{r['proto']}]" for r in e_allow)
    print(f"  {YEL}+ EGRESS ALLOW: {R}  "
          + (e_allow_str + ",  " if e_allow_str else "")
          + "RELATED/ESTABLISHED,  DEFAULT ALLOW")
    if e_drop:
        print(f"  {RED}- EGRESS DROP:  {R}  "
              + ", ".join(f"{port_label(r['dport'])} [{r['proto']}]" for r in e_drop))

# ── main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="nftables firewall overview")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="write plain-text output to FILE "
                             "(default: nft-overview-<hostname>.txt)")
    args = parser.parse_args()

    hostname = socket.getfqdn()
    outfile  = args.output if args.output else f"nft-overview-{hostname}.txt"

    tee = Tee(outfile)
    sys.stdout = tee

    bar = "═" * TOTAL_W
    print(f"\n{B}{bar}{R}")
    print(f"{B}  nftables Firewall Overview  –  {hostname}{R}")
    print(f"{B}{bar}{R}")

    ruleset = load_ruleset()
    chains, policies, hook_chains = build_index(ruleset)
    ipt_dnat_map = load_iptables_dnat()

    # Default policies for filter INPUT / FORWARD / OUTPUT (ip family only)
    print(f"\n{B}Default Policies (table ip filter):{R}")
    seen_hooks = set()
    for hook in ("input", "forward", "output"):
        matching = [c for c in hook_chains
                    if c["family"] == "ip" and c["table"] == "filter"
                    and c.get("hook") == hook]
        for c in matching:
            hook_key = (c["family"], c["table"], hook)
            if hook_key in seen_hooks:
                continue
            seen_hooks.add(hook_key)
            pol = c.get("policy", "accept").upper()
            col = GRN if pol == "ACCEPT" else RED
            print(f"  {c['name']:<12}: {B}{col}{pol}{R}")

    ingress, dnat_ports = collect_ingress(chains, policies, ipt_dnat_map=ipt_dnat_map)
    egress              = collect_egress(chains, policies)
    dnat_rules          = collect_dnat(chains, ipt_dnat_map, "nat", "PREROUTING")

    print_section("INPUT chain",  CYN, ingress, "INGRESS")
    print_section("OUTPUT chain", YEL, egress,  "EGRESS")
    print_summary(ingress, egress, dnat_rules, dnat_ports)

    tee.close()
    sys.stdout = tee.terminal
    print(f"\n  Output written to: {outfile}\n")

if __name__ == "__main__":
    main()
