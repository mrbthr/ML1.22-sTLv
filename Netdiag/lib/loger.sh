#!/usr/bin/env bash

init_colors() {
    local json_mode="$1"
    if [[ -t 1 && "$json_mode" == false ]]; then
        RED='\033[0;31m'
        GREEN='\033[0;32m'
        YELLOW='\033[1;33m'
        CYAN='\033[0;36m'
        BOLD='\033[1m'
        NC='\033[0m'
    else
        RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; NC=''
    fi
}

die() {
    echo -e "ERROR: $*" >&2
    exit 1
}

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    printf '%s' "$s"
}

render_json() {
    local timestamp="$1" host="$2" target="$3" port="$4"
    local iface="$5" gw_ip="$6" gw_ping="$7"
    local tcp_estab="$8" tcp_retrans="$9" ip_discards="${10}"
    local resolved_ip="${11}" dns_ms="${12}" ping_avg="${13}" ping_loss="${14}"
    local tcp_ms="${15}" tls_ms="${16}" ttfb_ms="${17}" http_code="${18}" warnings="${19}"

    cat <<EOF
{
  "meta": {
    "timestamp": "$(json_escape "$timestamp")",
    "hostname": "$(json_escape "$host")",
    "target": "$(json_escape "$target")",
    "port": $port
  },
  "routing": {
    "interface": "$(json_escape "$iface")",
    "gateway_ip": "$(json_escape "$gw_ip")",
    "gateway_ping_ms": "$(json_escape "$gw_ping")"
  },
  "kernel_counters": {
    "tcp_established": $tcp_estab,
    "tcp_retrans_segments": $tcp_retrans,
    "ip_in_discards": $ip_discards
  },
  "probes": {
    "resolved_ip": "$(json_escape "$resolved_ip")",
    "dns_ms": "$dns_ms",
    "icmp_avg_ms": "$(json_escape "$ping_avg")",
    "icmp_loss": "$(json_escape "$ping_loss")",
    "tcp_handshake_ms": "$(json_escape "$tcp_ms")",
    "tls_handshake_ms": "$(json_escape "$tls_ms")",
    "ttfb_ms": "$(json_escape "$ttfb_ms")",
    "http_status": "$(json_escape "$http_code")"
  },
  "anomaly_warning": "$(json_escape "$warnings")"
}
EOF
}

render_report() {
    local timestamp="$1" host="$2" target="$3" port="$4"
    local iface="$5" gw_ip="$6" gw_ping="$7"
    local tcp_estab="$8" tcp_retrans="$9" ip_discards="${10}"
    local resolved_ip="${11}" dns_ms="${12}" ping_avg="${13}" ping_loss="${14}"
    local tcp_ms="${15}" tls_ms="${16}" ttfb_ms="${17}" http_code="${18}" warnings="${19}"

    echo -e "${BOLD}====================================================================${NC}"
    echo -e "${BOLD} LINUX NETWORK DIAGNOSTICS | Host: ${CYAN}${host}${NC}"
    echo -e " Timestamp: ${timestamp} | Target: ${CYAN}${target}:${port}${NC}"
    echo -e "${BOLD}====================================================================${NC}\n"

    echo -e "${BOLD}[1] INTERFACES & ROUTING${NC}"
    ip -brief addr show up 2>/dev/null | awk '{printf "  %-14s %-8s %s\n", $1, $2, $3}'
    echo -e "  Default GW     : ${gw_ip} (dev: ${iface}) | GW RTT: ${gw_ping} ms"

    echo -e "\n${BOLD}[2] KERNEL SNMP COUNTERS (/proc/net/snmp)${NC}"
    echo -e "  TCP Established: ${tcp_estab}"
    echo -e "  TCP Retransmits: ${tcp_retrans} segments"
    echo -e "  IP InDiscards  : ${ip_discards} packets"

    echo -e "\n${BOLD}[3] LAYER-BY-LAYER PROBE LATENCY (${target}:${port})${NC}"
    echo -e "  DNS Resolution : ${resolved_ip} (${dns_ms} ms)"
    echo -e "  ICMP Echo Avg  : ${ping_avg} ms (Packet Loss: ${ping_loss})"
    echo -e "  TCP Handshake  : ${tcp_ms} ms"
    if [[ "$tls_ms" != "N/A" ]]; then
        echo -e "  TLS Handshake  : ${tls_ms} ms"
        echo -e "  HTTP TTFB      : ${ttfb_ms} ms (Status: ${http_code})"
    fi

    if [[ -n "$warnings" ]]; then
        echo -e "\n${YELLOW}[!] ANOMALY DETECTED:${NC}"
        echo -e "  ${warnings}"
    else
        echo -e "\n${GREEN}[OK] No routing or proxy interception anomalies detected.${NC}"
    fi
    echo ""
}
