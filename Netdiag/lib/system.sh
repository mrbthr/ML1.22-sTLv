#!/usr/bin/env bash

# License: MIT


if [[ "${BASH_SOURCE}" == "${0}" ]]; then
    echo "Error: lib/system.sh must be sourced, not executed directly." >&2
    exit 1
fi


get_default_gateway() {
    local gw=""
    if command -v ip >/dev/null 2>&1; then
        gw="$(ip -4 route show default 2>/dev/null | awk '/^default/ {for(i=1;i<=NF;i++) if($i=="via") {print $(i+1); exit}}')"
    fi

    
    if [[ -z "$gw" && -r /proc/net/route ]]; then
        gw="$(awk '$2 == "00000000" && $3 != "00000000" {
            printf "%d.%d.%d.%d\n",
                strtonum("0x" substr($3,7,2)),
                strtonum("0x" substr($3,5,2)),
                strtonum("0x" substr($3,3,2)),
                strtonum("0x" substr($3,1,2))
            exit
        }' /proc/net/route 2>/dev/null || true)"
    fi

    echo "${gw:-none}"
}

get_default_interface() {
    local iface=""
    if command -v ip >/dev/null 2>&1; then
        iface="$(ip -4 route show default 2>/dev/null | awk '/^default/ {for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')"
    fi

    if [[ -z "$iface" && -r /proc/net/route ]]; then
        iface="$(awk '$2 == "00000000" {print $1; exit}' /proc/net/route 2>/dev/null || true)"
    fi

    echo "${iface:-none}"
}


get_route_to_target() {
    local target_ip="$1"
    if [[ -z "$target_ip" || "$target_ip" == "FAILED" ]] || ! command -v ip >/dev/null 2>&1; then
        echo "unknown|unknown|direct|1500"
        return
    fi

    local route_out iface src via mtu
    route_out="$(ip -4 route get "$target_ip" 2>/dev/null | tr '\n' ' ' || true)"
    iface="$(echo "$route_out" | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')"
    src="$(echo "$route_out" | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')"
    via="$(echo "$route_out" | awk '{for(i=1;i<=NF;i++) if($i=="via") {print $(i+1); exit}}')"
    mtu="$(get_interface_mtu "${iface:-}")"

    echo "${iface:-unknown}|${src:-unknown}|${via:-direct}|${mtu}"
}



get_interface_mtu() {
    local iface="$1"
    if [[ -n "$iface" && -r "/sys/class/net/${iface}/mtu" ]]; then
        cat "/sys/class/net/${iface}/mtu"
    else
        echo "1500"
    fi
}


get_interface_health() {
    local iface="$1"
    local base="/sys/class/net/${iface}"

    if [[ -z "$iface" || "$iface" == "none" || ! -d "$base" ]]; then
        echo "down|-1|0|0|0|0"
        return
    fi

    local state speed rx_drop tx_drop rx_err tx_err
    state="$(cat "${base}/operstate" 2>/dev/null || echo "unknown")"
    speed="$(cat "${base}/speed" 2>/dev/null || echo "-1")"
    rx_drop="$(cat "${base}/statistics/rx_dropped" 2>/dev/null || echo "0")"
    tx_drop="$(cat "${base}/statistics/tx_dropped" 2>/dev/null || echo "0")"
    rx_err="$(cat "${base}/statistics/rx_errors" 2>/dev/null || echo "0")"
    tx_err="$(cat "${base}/statistics/tx_errors" 2>/dev/null || echo "0")"

    echo "${state}|${speed}|${rx_drop}|${tx_drop}|${rx_err}|${tx_err}"
}




get_tcp_socket_states() {
    if command -v ss >/dev/null 2>&1; then
        ss -tan 2>/dev/null | awk '
            NR>1 {
                if ($1 == "ESTAB") est++
                else if ($1 == "TIME-WAIT") tw++
                else if ($1 == "SYN-SENT") syn++
                else if ($1 == "CLOSE-WAIT") cw++
            }
            END { printf "%d|%d|%d|%d\n", est+0, tw+0, syn+0, cw+0 }
        '
    elif [[ -r /proc/net/tcp ]]; then
        
        awk '
            NR>1 {
                if ($4 == "01") est++
                else if ($4 == "06") tw++
                else if ($4 == "02") syn++
                else if ($4 == "08") cw++
            }
            END { printf "%d|%d|%d|%d\n", est+0, tw+0, syn+0, cw+0 }
        ' /proc/net/tcp
    else
        echo "0|0|0|0"
    fi
}

get_snmp_counter() {
    local proto="$1"
    local metric="$2"
    local file="${3:-/proc/net/snmp}"

    [[ ! -r "$file" ]] && { echo "0"; return; }

    awk -v p="${proto}:" -v m="$metric" '
        $1 == p && !seen { for (i=2; i<=NF; i++) h[i]=$i; seen=1; next }
        $1 == p && seen  { for (i=2; i<=NF; i++) if (h[i]==m) { print $i; exit } }
    ' "$file" 2>/dev/null || echo "0"
}


get_softnet_drops() {
    if [[ -r /proc/net/softnet_stat ]]; then
        awk '{ sum += strtonum("0x" $2) } END { print sum+0 }' /proc/net/softnet_stat 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}


run_custom_command() {
    local custom_cmd="$1"
    local cmd_timeout="${2:-5}"

    if [[ -z "$custom_cmd" ]]; then
        echo "0|0|"
        return
    fi

    local start_ns end_ns elapsed_ms raw_out exit_code=0
    start_ns="$(date +%s%N)"

    
    if raw_out="$(timeout "$cmd_timeout" bash -c "$custom_cmd" 2>&1)"; then
        exit_code=0
    else
        exit_code=$?
    fi

    end_ns="$(date +%s%N)"
    elapsed_ms="$(awk "BEGIN {printf \"%.2f\", ($end_ns - $start_ns)/1000000}")"

    
    raw_out="${raw_out:0:4096}"
    echo "${exit_code}|${elapsed_ms}|${raw_out}"
}
