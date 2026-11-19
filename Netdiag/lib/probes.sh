#!/usr/bin/env bash

probe_gateway_ping() {
    local gw="$1"
    local timeout="$2"
    if [[ -z "$gw" || "$gw" == "none" ]]; then
        echo "N/A"
        return
    fi
    ping -c 2 -W "$timeout" "$gw" 2>/dev/null | awk -F'/' 'END{if(NF>=5) print $5; else print "timeout"}'
}

probe_dns() {
    local target="$1"
    local start_ns end_ns ip_addr elapsed_ms
    start_ns="$(date +%s%N)"

    if command -v getent >/dev/null 2>&1; then
        ip_addr="$(getent ahostsv4 "$target" 2>/dev/null | awk '{print $1; exit}' || true)"
    elif command -v dig >/dev/null 2>&1; then
        ip_addr="$(dig +short "$target" A 2>/dev/null | head -n1 || true)"
    fi

    end_ns="$(date +%s%N)"
    elapsed_ms="$(awk "BEGIN {printf \"%.2f\", ($end_ns - $start_ns)/1000000}")"
    echo "${ip_addr:-FAILED}|${elapsed_ms}"
}

probe_icmp() {
    local target="$1"
    local count="$2"
    local timeout="$3"
    local raw_out loss avg

    raw_out="$(ping -c "$count" -W "$timeout" "$target" 2>/dev/null || true)"
    loss="$(echo "$raw_out" | grep -oE '[0-9]+(\.[0-9]+)?% packet loss' | awk '{print $1}' || echo "100%")"
    avg="$(echo "$raw_out" | awk -F'/' 'END{if(NF>=5) print $5; else print "timeout"}')"
    echo "${avg}|${loss}"
}

probe_tcp_http() {
    local target="$1"
    local port="$2"
    local timeout="$3"

    if command -v curl >/dev/null 2>&1 && [[ "$port" == "443" || "$port" == "80" ]]; then
        local proto="https"
        [[ "$port" == "80" ]] && proto="http"
        local out code t_conn t_app t_ttfb tcp_ms tls_ms ttfb_ms
        out="$(curl -o /dev/null -s -w "%{http_code} %{time_connect} %{time_appconnect} %{time_starttransfer}" \
            --connect-timeout "$timeout" "${proto}://${target}" 2>/dev/null || echo "000 0 0 0")"
        read -r code t_conn t_app t_ttfb <<< "$out"
        tcp_ms="$(awk "BEGIN {printf \"%.2f\", $t_conn * 1000}")"
        tls_ms="$(awk "BEGIN {printf \"%.2f\", ($t_app > 0 ? ($t_app - $t_conn) * 1000 : 0)}")"
        ttfb_ms="$(awk "BEGIN {printf \"%.2f\", $t_ttfb * 1000}")"
        echo "${tcp_ms}|${tls_ms}|${ttfb_ms}|${code}"
    else
        local start_ns end_ns tcp_ms
        start_ns="$(date +%s%N)"
        if timeout "$timeout" bash -c "cat < /dev/null > /dev/tcp/${target}/${port}" 2>/dev/null; then
            end_ns="$(date +%s%N)"
            tcp_ms="$(awk "BEGIN {printf \"%.2f\", ($end_ns - $start_ns)/1000000}")"
        else
            tcp_ms="failed"
        fi
        echo "${tcp_ms}|N/A|N/A|N/A"
    fi
}

detect_anomalies() {
    local target="$1"
    local resolved_ip="$2"
    local ping_avg="$3"
    local notes=()

    if [[ "$resolved_ip" =~ ^(127\.|0\.0\.0\.0|198\.18\.) ]]; then
        notes+=("DNS resolved to ${resolved_ip} (Fake-IP proxy, VPN TUN interface, or /etc/hosts override)")
    fi

    if [[ "$ping_avg" != "timeout" ]] && awk "BEGIN {exit !($ping_avg < 1.5)}"; then
        if [[ ! "$target" =~ ^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.) ]]; then
            notes+=("Sub-1.5ms ICMP RTT (${ping_avg} ms) to external target indicates local proxy/VPN ICMP interception")
        fi
    fi

    local IFS="; "
    echo "${notes[*]:-}"
}
