#!/usr/bin/env bash
# iptables-overview.sh  –  Generic iptables firewall rule overview incl. NAT/DNAT
# Processing order: RAW PREROUTING -> CONNTRACK -> NAT PREROUTING (DNAT) -> INPUT / FORWARD
#
# Requirements: bash 4+, sudo, iptables-save, grep with PCRE (-P)

set -uo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
R=$'\033[0m'; B=$'\033[1m'
RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'
CYN=$'\033[36m'; MGT=$'\033[35m'; GRY=$'\033[90m'

# ── Column widths: # Proto Src Dst Port State Action ─────────────────────────
W=(4 6 14 20 26 30 8)
TOTAL_W=120
SEP_H=$(printf '%.0s─' $(seq 1 $TOTAL_W))
SEP_D=$(printf '%.0s═' $(seq 1 $TOTAL_W))

# ── Arguments ─────────────────────────────────────────────────────────────────
OUTFILE=""
while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output) OUTFILE="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [-o FILE]"
            echo "  -o, --output FILE   Write plain-text output to FILE"
            echo "                      (default: iptables-overview-<hostname>.txt)"
            exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

FQDN=$(hostname -f 2>/dev/null || hostname)
[[ -z "$OUTFILE" ]] && OUTFILE="iptables-overview-${FQDN}.txt"

# Tee: stdout gets color, file gets plain text (ANSI stripped)
exec > >(tee >(sed 's/\x1b\[[0-9;]*m//g' > "$OUTFILE"))

# ── Load iptables-save ────────────────────────────────────────────────────────
IPTS=$(sudo iptables-save) || { echo "Error: iptables-save failed" >&2; exit 1; }

# ── Parse into per-chain temp files ──────────────────────────────────────────
TMPD=$(mktemp -d)
trap 'rm -rf "$TMPD"' EXIT

declare -A POLICIES=()
cur_table=""

while IFS= read -r line; do
    s="${line#"${line%%[! ]*}"}"
    case "$s" in
        \**) cur_table="${s:1}" ;;
        :*)
            ch="${s%%[ ]*}"; ch="${ch:1}"
            pol=$(awk '{print $2}' <<< "$s")
            [[ "$pol" =~ ^(ACCEPT|DROP|REJECT)$ ]] && POLICIES["$ch"]="$pol"
            ;;
        -A\ *)
            ch=$(awk '{print $2}' <<< "$s")
            rule=$(cut -d' ' -f3- <<< "$s")
            key="${cur_table}__${ch//[^a-zA-Z0-9_]/_}"
            echo "$rule" >> "$TMPD/chain_${key}"
            ;;
    esac
done <<< "$IPTS"

# ── Chain file path ───────────────────────────────────────────────────────────
chain_file() {
    echo "$TMPD/chain_${1}__${2//[^a-zA-Z0-9_]/_}"
}

# ── Field extractors (using \K to avoid variable-length lookbehind) ───────────
gP() { echo "$1" | grep -oP -- "$2" | head -1 || true; }

rule_proto()  { gP "$1" '(?:^| )-p \K\S+'; }
rule_src()    { gP "$1" '(?:^| )-s \K\S+'; }
rule_dst()    { gP "$1" '(?:^| )-d \K\S+'; }
rule_dport()  { gP "$1" '--dports? \K\S+'; }
rule_sport()  { gP "$1" '--sports? \K\S+'; }
rule_state()  { gP "$1" '--ctstate \K\S+'; }
rule_iface()  { gP "$1" '(?:^| )-[io] \K\S+'; }
rule_target() { gP "$1" '(?:^| )-[jg] \K\S+'; }
rule_neg_i()  { gP "$1" '! -i \K\S+'; }
rule_to_dst() { gP "$1" '--to-destination \K\S+'; }

# ── Chain action resolver (recursive) ────────────────────────────────────────
chain_final_action() {
    local chain="$1" depth="${2:-0}"
    [[ $depth -gt 15 ]] && echo "ALLOW" && return
    local f; f=$(chain_file "filter" "$chain")
    [[ ! -f "$f" ]] && echo "ALLOW" && return
    while IFS= read -r rule; do
        [[ -z "$rule" ]] && continue
        local tgt; tgt=$(rule_target "$rule")
        case "$tgt" in
            DROP|REJECT) echo "DROP"; return ;;
            ILO-FILTER-ACTION-*)
                [[ "$(chain_final_action "$tgt" $((depth+1)))" == "DROP" ]] \
                    && echo "DROP" && return ;;
        esac
    done < "$f"
    echo "ALLOW"
}

rule_action() {
    local tgt; tgt=$(rule_target "$1")
    case "$tgt" in
        DROP|REJECT)         echo "DROP" ;;
        ACCEPT|RETURN)       echo "ALLOW" ;;
        ILO-FILTER-ACTION-*) chain_final_action "$tgt" ;;
        ILO-FILTER-*|"")     echo "" ;;
        *)                   echo "ALLOW" ;;
    esac
}

# ── Effective chain (follow first jump from INPUT/OUTPUT) ─────────────────────
get_effective_chain() {
    local f; f=$(chain_file "filter" "$1")
    [[ ! -f "$f" ]] && echo "$1" && return
    while IFS= read -r rule; do
        local tgt; tgt=$(rule_target "$rule")
        [[ -n "$tgt" && -f "$(chain_file "filter" "$tgt")" ]] && echo "$tgt" && return
    done < "$f"
    echo "$1"
}

# ── Port label ────────────────────────────────────────────────────────────────
port_label() {
    [[ -z "${1:-}" ]] && echo "any" && return
    case "$1" in
        22)           echo "22 (SSH)" ;;
        80)           echo "80 (HTTP)" ;;
        443)          echo "443 (HTTPS)" ;;
        53)           echo "53 (DNS)" ;;
        67)           echo "67 (DHCP-srv)" ;;
        68)           echo "68 (DHCP-cli)" ;;
        8080|8081)    echo "$1 (HTTP-alt)" ;;
        8443)         echo "8443 (PCE-UI)" ;;
        8444)         echo "8444 (PCE-Cluster)" ;;
        3306)         echo "3306 (MySQL)" ;;
        3389)         echo "3389 (RDP)" ;;
        23)           echo "23 (Telnet)" ;;
        33434:33523)  echo "33434:33523 (Traceroute)" ;;
        *)            echo "$1" ;;
    esac
}

# ── Skip filter ───────────────────────────────────────────────────────────────
should_skip() {
    echo "$1" | grep -qP \
        '(--ctstate (RELATED,ESTABLISHED|UNTRACKED)|(?:^| )-[io] lo\b|ILO-FILTER-NS-LOG)' \
        && return 0 || return 1
}

# ── DNAT collection (recursive chain traversal) ───────────────────────────────
declare -A DNAT_PORTS=()

collect_dnat_chain() {
    local table="$1" chain="$2" depth="${3:-0}"
    [[ $depth -gt 10 ]] && return
    local f; f=$(chain_file "$table" "$chain")
    [[ ! -f "$f" ]] && return
    while IFS= read -r rule; do
        [[ -z "$rule" ]] && continue
        local tgt; tgt=$(rule_target "$rule")
        case "$tgt" in
            DNAT)
                local dp to
                dp=$(rule_dport "$rule")
                to=$(rule_to_dst "$rule")
                [[ -n "$dp" ]] && DNAT_PORTS["$dp"]="${to:-?}"
                ;;
            ""|ACCEPT|DROP|REJECT|MASQUERADE) ;;
            *)
                [[ -f "$(chain_file "$table" "$tgt")" ]] \
                    && collect_dnat_chain "$table" "$tgt" $((depth+1))
                ;;
        esac
    done < "$f"
}

collect_dnat_chain "nat" "PREROUTING"

# ── Check if a dport string contains a DNAT'd port ───────────────────────────
is_dnat_port() {
    local dport="${1:-}"
    [[ -z "$dport" ]] && return 1
    local part
    while IFS= read -r part; do
        [[ -v "DNAT_PORTS[$part]" ]] && return 0
    done < <(tr ',' '\n' <<< "$dport")
    return 1
}

# ── Formatting ────────────────────────────────────────────────────────────────
visible_len() {
    echo "$1" | sed 's/\x1b\[[0-9;]*m//g' | awk '{print length}'
}

pad_to() {
    local text="$1" width="$2"
    local vlen; vlen=$(visible_len "$text")
    local spaces=$(( width - vlen ))
    [[ $spaces -lt 0 ]] && spaces=0
    printf '%s%*s' "$text" "$spaces" ""
}

fmt_action() {
    case "$1" in
        ALLOW)    printf "${B}${GRN}ALLOW ${R}" ;;
        DROP)     printf "${B}${RED}DROP  ${R}" ;;
        "->DNAT") printf "${B}${MGT}->DNAT${R}" ;;
        MASQ)     printf "${B}${MGT}MASQ  ${R}" ;;
        *)        printf "${GRY}%-6s${R}" "$1" ;;
    esac
}

print_hdr() {
    printf "${B}%-${W[0]}s  %-${W[1]}s  %-${W[2]}s  %-${W[3]}s  %-${W[4]}s  %-${W[5]}s  %s${R}\n" \
        "#" "Proto" "Src" "Dst-IP" "Port / Service" "State / Condition" "Action"
    echo "$SEP_H"
}

print_row() {
    # args: num proto src dst port state action note row_type
    local num="${1}" proto="${2}" src="${3}" dst="${4}"
    local port="${5}" state="${6}" action="${7}"
    local note="${8:-}" row_type="${9:-rule}"

    local num_col
    [[ "$row_type" == "nat" ]] && num_col="${GRY}NAT${R}" || num_col="$num"

    pad_to "$num_col" "${W[0]}"; printf "  "
    pad_to "$proto"   "${W[1]}"; printf "  "
    pad_to "$src"     "${W[2]}"; printf "  "
    pad_to "$dst"     "${W[3]}"; printf "  "
    pad_to "$port"    "${W[4]}"; printf "  "
    pad_to "$state"   "${W[5]}"; printf "  "
    fmt_action "$action"; echo

    if [[ -n "$note" ]]; then
        local nc; [[ "$row_type" == "nat" ]] && nc="$MGT" || nc="$GRY"
        echo "      ${nc}-> ${note}${R}"
    fi
}

print_separator() { echo; printf "  ${B}${GRY}-- %s --${R}\n" "$*"; }

print_section_hdr() {
    echo
    printf "${B}${2}%s${R}\n" "$SEP_D"
    printf "${B}${2}  %s  -  %s${R}\n" "$3" "$1"
    printf "${B}${2}%s${R}\n" "$SEP_D"
    print_hdr
}

# ── INGRESS ───────────────────────────────────────────────────────────────────
print_ingress() {
    local INPUT_CHAIN; INPUT_CHAIN=$(get_effective_chain "INPUT")
    print_section_hdr "INPUT chain" "$CYN" "INGRESS"

    # Step 1: RAW PREROUTING
    print_separator "Step 1 - RAW PREROUTING (before DNAT)"
    local f_raw; f_raw=$(chain_file "raw" "PREROUTING")
    if [[ -f "$f_raw" ]]; then
        while IFS= read -r rule; do
            [[ -z "$rule" ]] && continue
            local tgt; tgt=$(rule_target "$rule")
            [[ ! "$tgt" =~ ^(DROP|REJECT|ACCEPT|RETURN)$ ]] && continue
            local proto src dst dp cond action note neg_i
            proto=$(rule_proto "$rule"); [[ -z "$proto" ]] && proto="any"
            src=$(rule_src   "$rule");   [[ -z "$src"   ]] && src="any"
            dst=$(rule_dst   "$rule");   [[ -z "$dst"   ]] && dst="any"
            dp=$(rule_dport  "$rule");   [[ -z "$dp"    ]] && dp="any"
            neg_i=$(rule_neg_i "$rule")
            [[ -n "$neg_i" ]] && cond="! via $neg_i" || cond="any"
            [[ "$tgt" =~ ^(DROP|REJECT)$ ]] && action="DROP" || action="ALLOW"
            note=""; [[ "$dst" =~ ^172\. ]] && note="Direct access to Docker container blocked"
            print_row "NAT" "$proto" "$src" "$dst" \
                "$(port_label "$dp")" "$cond" "$action" "$note" "nat"
        done < "$f_raw"
    fi

    # Step 2: NAT / DNAT
    print_separator "Step 2 - NAT PREROUTING (DNAT - before INPUT filter!)"
    if [[ ${#DNAT_PORTS[@]} -gt 0 ]]; then
        for dp in "${!DNAT_PORTS[@]}"; do
            local to="${DNAT_PORTS[$dp]}"
            print_row "NAT" "any" "any" "<server>" \
                "$(port_label "$dp")" "! via docker0" "->DNAT" \
                "Forwarded to ${to}  -  traffic continues via FORWARD (bypasses INPUT)" "nat"
        done
    fi

    # Step 3: INPUT filter
    print_separator "Step 3 - INPUT filter (${INPUT_CHAIN})"
    print_row "1" "any" "any" "any" "any" "lo interface"        "ALLOW" "" "rule"
    print_row "2" "any" "any" "any" "any" "RELATED,ESTABLISHED" "ALLOW" "" "rule"

    local seq=2 added_default=0
    local f_in; f_in=$(chain_file "filter" "$INPUT_CHAIN")
    if [[ -f "$f_in" ]]; then
        while IFS= read -r rule; do
            [[ -z "$rule" ]] && continue
            should_skip "$rule" && continue
            local tgt; tgt=$(rule_target "$rule")

            if [[ "$tgt" == *ENFORCE* ]] || \
               { [[ -n "$tgt" ]] && \
                 [[ ! -f "$(chain_file "filter" "$tgt")" ]] && \
                 [[ ! "$tgt" =~ ^(DROP|REJECT|ACCEPT|RETURN|MASQUERADE|DNAT|SNAT|LOG)$ ]]; }
            then
                local pol
                if [[ -f "$(chain_file "filter" "$tgt")" ]]; then
                    pol=$(chain_final_action "$tgt")
                else
                    pol="${POLICIES[INPUT]:-ACCEPT}"
                fi
                seq=$((seq+1))
                print_row "$seq" "any" "any" "any" "any" \
                    "DEFAULT (no match above)" "$pol" \
                    "All connections not explicitly covered above" "rule"
                added_default=1; continue
            fi

            local action; action=$(rule_action "$rule")
            [[ -z "$action" ]] && continue

            local proto src dst dp sp state iface port_str state_str src_str note
            proto=$(rule_proto  "$rule"); [[ -z "$proto" ]] && proto="any"
            src=$(rule_src      "$rule"); [[ -z "$src"   ]] && src="any"
            dst=$(rule_dst      "$rule"); [[ -z "$dst"   ]] && dst="any"
            dp=$(rule_dport     "$rule")
            sp=$(rule_sport     "$rule")
            state=$(rule_state  "$rule")
            iface=$(rule_iface  "$rule")

            port_str=$(port_label "$dp")
            [[ -n "$sp" ]] && port_str="${port_str:+$port_str, }src:$sp"
            [[ -z "$port_str" ]] && port_str="any"
            [[ -z "$state" ]] && state_str="any" || state_str="$state"
            [[ -n "$iface" ]] && src_str="${src}[${iface}]" || src_str="$src"

            note=""
            if [[ "$action" == "DROP" && -n "$dp" ]] && is_dnat_port "$dp"; then
                note="Illumio enforcement - applies only to traffic NOT redirected via DNAT"
            fi

            seq=$((seq+1))
            print_row "$seq" "$proto" "$src_str" "$dst" \
                "$port_str" "$state_str" "$action" "$note" "rule"
        done < "$f_in"
    fi

    if [[ $added_default -eq 0 ]]; then
        seq=$((seq+1))
        print_row "$seq" "any" "any" "any" "any" "DEFAULT (no match above)" \
            "${POLICIES[INPUT]:-ACCEPT}" \
            "All connections not explicitly covered above" "rule"
    fi
    echo "$SEP_H"
}

# ── EGRESS ────────────────────────────────────────────────────────────────────
print_egress() {
    local OUTPUT_CHAIN; OUTPUT_CHAIN=$(get_effective_chain "OUTPUT")
    print_section_hdr "OUTPUT chain" "$YEL" "EGRESS"
    print_separator "Step - OUTPUT filter (${OUTPUT_CHAIN})"
    print_row "1" "any" "any" "any" "any" "lo interface"        "ALLOW" "" "rule"
    print_row "2" "any" "any" "any" "any" "RELATED,ESTABLISHED" "ALLOW" "" "rule"

    local seq=2 added_default=0
    local f_out; f_out=$(chain_file "filter" "$OUTPUT_CHAIN")
    if [[ -f "$f_out" ]]; then
        while IFS= read -r rule; do
            [[ -z "$rule" ]] && continue
            should_skip "$rule" && continue
            local tgt; tgt=$(rule_target "$rule")

            if [[ "$tgt" == *ENFORCE* ]] || \
               { [[ -n "$tgt" ]] && \
                 [[ ! -f "$(chain_file "filter" "$tgt")" ]] && \
                 [[ ! "$tgt" =~ ^(DROP|REJECT|ACCEPT|RETURN|MASQUERADE|DNAT|SNAT|LOG)$ ]]; }
            then
                local pol
                if [[ -f "$(chain_file "filter" "$tgt")" ]]; then
                    pol=$(chain_final_action "$tgt")
                else
                    pol="${POLICIES[OUTPUT]:-ACCEPT}"
                fi
                seq=$((seq+1))
                print_row "$seq" "any" "any" "any" "any" \
                    "DEFAULT (no match above)" "$pol" \
                    "No explicit DROP for outbound traffic" "rule"
                added_default=1; continue
            fi

            local action; action=$(rule_action "$rule")
            [[ -z "$action" ]] && continue

            local proto src dst dp sp state iface port_str state_str src_str
            proto=$(rule_proto  "$rule"); [[ -z "$proto" ]] && proto="any"
            src=$(rule_src      "$rule"); [[ -z "$src"   ]] && src="any"
            dst=$(rule_dst      "$rule"); [[ -z "$dst"   ]] && dst="any"
            dp=$(rule_dport     "$rule")
            sp=$(rule_sport     "$rule")
            state=$(rule_state  "$rule")
            iface=$(rule_iface  "$rule")

            port_str=$(port_label "$dp")
            [[ -n "$sp" ]] && port_str="${port_str:+$port_str, }src:$sp"
            [[ -z "$port_str" ]] && port_str="any"
            [[ -z "$state" ]] && state_str="any" || state_str="$state"
            [[ -n "$iface" ]] && src_str="${src}[${iface}]" || src_str="$src"

            seq=$((seq+1))
            print_row "$seq" "$proto" "$src_str" "$dst" \
                "$port_str" "$state_str" "$action" "" "rule"
        done < "$f_out"
    fi

    if [[ $added_default -eq 0 ]]; then
        seq=$((seq+1))
        print_row "$seq" "any" "any" "any" "any" "DEFAULT (no match above)" \
            "${POLICIES[OUTPUT]:-ACCEPT}" \
            "No explicit DROP for outbound traffic" "rule"
    fi
    echo "$SEP_H"
}

# ── SUMMARY ───────────────────────────────────────────────────────────────────
print_summary() {
    local INPUT_CHAIN;  INPUT_CHAIN=$(get_effective_chain  "INPUT")
    local OUTPUT_CHAIN; OUTPUT_CHAIN=$(get_effective_chain "OUTPUT")

    local allow_parts=() drop_parts=() e_allow_parts=() e_drop_parts=()

    local f_in; f_in=$(chain_file "filter" "$INPUT_CHAIN")
    if [[ -f "$f_in" ]]; then
        while IFS= read -r rule; do
            [[ -z "$rule" ]] && continue
            should_skip "$rule" && continue
            local action dp proto
            action=$(rule_action "$rule"); [[ -z "$action" ]] && continue
            dp=$(rule_dport "$rule");      [[ -z "$dp"     ]] && continue
            is_dnat_port "$dp" && continue
            proto=$(rule_proto "$rule");   [[ -z "$proto"  ]] && proto="any"
            local lbl; lbl="$(port_label "$dp") [$proto]"
            [[ "$action" == "ALLOW" ]] && allow_parts+=("$lbl")
            [[ "$action" == "DROP"  ]] && drop_parts+=("$lbl")
        done < "$f_in"
    fi

    local f_out; f_out=$(chain_file "filter" "$OUTPUT_CHAIN")
    if [[ -f "$f_out" ]]; then
        while IFS= read -r rule; do
            [[ -z "$rule" ]] && continue
            should_skip "$rule" && continue
            local action dp proto
            action=$(rule_action "$rule"); [[ -z "$action" ]] && continue
            dp=$(rule_dport "$rule");      [[ -z "$dp"     ]] && continue
            proto=$(rule_proto "$rule");   [[ -z "$proto"  ]] && proto="any"
            local lbl; lbl="$(port_label "$dp") [$proto]"
            [[ "$action" == "ALLOW" ]] && e_allow_parts+=("$lbl")
            [[ "$action" == "DROP"  ]] && e_drop_parts+=("$lbl")
        done < "$f_out"
    fi

    echo
    echo "${B}SUMMARY:${R}"

    local allow_str=""
    [[ ${#allow_parts[@]} -gt 0 ]] && allow_str=$(IFS=', '; echo "${allow_parts[*]}")
    printf "  ${GRN}+ INGRESS ALLOW:${R}  %s,  RELATED/ESTABLISHED\n" "${allow_str:-(none)}"

    if [[ ${#drop_parts[@]} -gt 0 ]]; then
        local drop_str; drop_str=$(IFS=', '; echo "${drop_parts[*]}")
        printf "  ${RED}- INGRESS DROP: ${R}  %s\n" "$drop_str"
    fi

    if [[ ${#DNAT_PORTS[@]} -gt 0 ]]; then
        local dnat_parts=()
        for dp in "${!DNAT_PORTS[@]}"; do
            dnat_parts+=("$(port_label "$dp") -> ${DNAT_PORTS[$dp]}")
        done
        local dnat_str; dnat_str=$(IFS=', '; echo "${dnat_parts[*]}")
        printf "  ${MGT}> NAT/DNAT:    ${R}  %s\n" "$dnat_str"
        printf "  ${GRY}               (DNAT ports bypass INPUT filter - traffic routed via FORWARD to container)${R}\n"
    fi

    local e_allow_str=""
    [[ ${#e_allow_parts[@]} -gt 0 ]] && e_allow_str=$(IFS=', '; echo "${e_allow_parts[*]}")
    printf "  ${YEL}+ EGRESS ALLOW: ${R}  %s,  RELATED/ESTABLISHED,  DEFAULT ALLOW\n" \
        "${e_allow_str:-(none)}"

    if [[ ${#e_drop_parts[@]} -gt 0 ]]; then
        local e_drop_str; e_drop_str=$(IFS=', '; echo "${e_drop_parts[*]}")
        printf "  ${RED}- EGRESS DROP:  ${R}  %s\n" "$e_drop_str"
    fi
}

# ── MAIN ──────────────────────────────────────────────────────────────────────
echo
printf "${B}%s${R}\n" "$SEP_D"
printf "${B}  iptables Firewall Overview  -  %s${R}\n" "$FQDN"
printf "${B}%s${R}\n" "$SEP_D"

echo
echo "${B}Default Policies (*filter):${R}"
for ch in INPUT FORWARD OUTPUT; do
    pol="${POLICIES[$ch]:-ACCEPT}"
    [[ "$pol" == "ACCEPT" ]] && c="$GRN" || c="$RED"
    printf "  %-12s: ${B}${c}%s${R}\n" "$ch" "$pol"
done

print_ingress
print_egress
print_summary

echo
printf "  Output written to: %s\n" "$OUTFILE"
echo
