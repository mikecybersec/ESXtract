#!/bin/sh
###############################################################################
# ESXi Incident Response Triage Script
# Authors:
# - Michael L (@mikecybersec)
# - AI ;) 
# References:
# - DCScoder/ESXiTri: https://github.com/DCScoder/ESXiTri
# - iBlue Team ESXi Forensics: https://www.iblue.team/esxi-forensics/triage-and-imaging
# - Synacktiv Velociraptor ESXi Forensics: https://www.synacktiv.com/en/publications/vmware-esxi-forensic-with-velociraptor
# - Aon QELP ESXi Log Parsing: https://www.aon.com/en/insights/cyber-labs/parsing-esxi-logs-for-incident-response
# - Binalyze AIR ESXi Collector: https://kb.binalyze.com/air/setup/air-responder-supported-operating-systems/air-esxi-standalone-collector
# - Sygnia: https://www.sygnia.co/blog/esxi-ransomware-ssh-tunneling-defense-strategies/
# Usage:
#   1. Upload this script to a VMware ESXi datastore (e.g., via vSphere Client or Datastore Browser).
#   2. SSH into the ESXi host or access the ESXi Shell.
#   3. Navigate to the script location (e.g., /vmfs/volumes/datastore1/).
#   4. Make it executable: chmod +x ./esxtract.sh
#   5. Run collection on the host: ./esxtract.sh -c
#   6. Retrieve the resulting .tar.gz archive from /vmfs/volumes/datastore1 when present, or from /tmp otherwise, for analysis.
#   7. To scan an extracted archive locally: ./esxtract.sh -s /path/to/folder
#
# For help: ./esxtract.sh --help
###############################################################################

show_help() {
cat << EOF
ESXi Incident Response Triage Script

This script collects forensic artifacts from a VMware ESXi host for incident response
or scans a previously collected folder for quick indicators of attack.

Instructions:
  1. Upload this script to a VMware datastore (e.g., using vSphere Client).
  2. SSH into the ESXi host or use the ESXi Shell.
  3. Navigate to the script location (e.g., /vmfs/volumes/datastore1/).
  4. Make it executable:
       chmod +x ./esxtract.sh
  5. Run collection on an ESXi host:
       ./esxtract.sh -c
  6. To scan a previously collected (unzipped) folder for quick IoA checks:
       ./esxtract.sh -s /path/to/esxi_triage_host_timestamp
  7. The output archive (esxi_triage_<hostname>_<date>.tar.gz) will be created in
     /vmfs/volumes/datastore1 when that datastore exists, or in /tmp if it does not.
     Download it from the host for further analysis.

Options:
  -h, --help      Show this help message and exit
  -c, --collection
                  Run the artifact collection workflow on an ESXi host
  -s, --scan <dir>
                  Scan an extracted collection folder for suspicious indicators
  -d, --detections <file>
                  Optional: detections file to use during scanning (defaults to bundled detections.sh)

References:
  - DCScoder/ESXiTri
  - iBlue Team ESXi Forensics
  - Synacktiv Velociraptor ESXi Forensics
  - Aon QELP ESXi Log Parsing
  - Binalyze AIR ESXi Collector

EOF
}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DEFAULT_DETECTIONS_FILE="$SCRIPT_DIR/detections.sh"

# Determine mode
MODE=""
SCAN_PATH=""
SCAN_FINDINGS_FILE=""
DETECTIONS_FILE=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        -c|--collection)
            MODE="collect"
            ;;
        -s|--scan)
            MODE="scan"
            shift
            SCAN_PATH="$1"
            ;;
        -d|--detections)
            shift
            DETECTIONS_FILE="$1"
            ;;
        *)
            echo "[!] Unknown option: $1" >&2
            show_help
            exit 1
            ;;
    esac
    shift
done

# Helpers for scanning mode
log_line() {
    msg="$1"
    printf "%b\n" "$msg"
    if [ -n "$SCAN_FINDINGS_FILE" ]; then
        printf "%b\n" "$msg" >> "$SCAN_FINDINGS_FILE"
    fi
}

log_error() {
    msg="$1"
    printf "%b\n" "$msg" >&2
    if [ -n "$SCAN_FINDINGS_FILE" ]; then
        printf "%b\n" "$msg" >> "$SCAN_FINDINGS_FILE"
    fi
}

is_public_ipv4() {
    ip="$1"
    case "$ip" in
        10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|127.*|169.254.*|0.*|255.255.255.255|224.*|240.*)
            return 1
            ;;
        *)
            return 0
            ;;
    esac
}

report_section() {
    log_line "\n[+] $1"
}

scan_network_connections() {
    file="$1/network_connections.txt"
    if [ ! -f "$file" ]; then
        log_line "[-] network_connections.txt not found in scan path"
        return
    fi

    report_section "Potential external IPv4 connections"
    flagged=0
    for ip in $(grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' "$file" | sort -u); do
        if is_public_ipv4 "$ip"; then
            log_line "  Suspicious IP: $ip"
            flagged=1
        fi
    done
    [ "$flagged" -eq 0 ] && log_line "  None detected"
}

scan_processes() {
    file="$1/process_list.txt"
    if [ ! -f "$file" ]; then
        log_line "[-] process_list.txt not found in scan path"
        return
    fi

    report_section "Potentially suspicious processes"
    matches=$(grep -Ei '/tmp/|/var/tmp/|/dev/shm/|python|perl|curl|wget|nc |netcat|socat|bash -i|openssl enc' "$file")
    if [ -n "$matches" ]; then
        log_line "$matches"
    else
        log_line "  None detected"
    fi
}

scan_cron() {
    file="$1/root_crontab.txt"
    if [ ! -f "$file" ]; then
        log_line "[-] root_crontab.txt not found in scan path"
        return
    fi

    report_section "Non-comment cron entries"
    matches=$(grep -E '^[^#].*\S' "$file")
    if [ -n "$matches" ]; then
        log_line "$matches"
    else
        log_line "  None detected"
    fi
}

scan_users() {
    file="$1/user_accounts.txt"
    if [ ! -f "$file" ]; then
        log_line "[-] user_accounts.txt not found in scan path"
        return
    fi

    report_section "Non-default users"
    baseline="root dcui daemon nobody vpxuser"
    found=0
    for user in $(awk 'NR>1 {print $1}' "$file" | sort -u); do
        echo "$baseline" | grep -qw "$user" && continue
        found=1
        log_line "  Unexpected user: $user"
    done
    [ "$found" -eq 0 ] && log_line "  None detected"
}

run_detections() {
    target_dir="$1"
    report_section "Detections"
    hits=0

    detections_path="$DETECTIONS_FILE"
    [ -z "$detections_path" ] && detections_path="$DEFAULT_DETECTIONS_FILE"

    if [ -z "$detections_path" ]; then
        log_error "[!] No detections file provided or found."
    elif [ -f "$detections_path" ]; then
        log_line "  Using detections file: $detections_path"

        run_block() {
            block="$1"
            [ -z "$block" ] && return

            tmpfile=$(mktemp)
            printf '%s\n' "$block" > "$tmpfile"
            if output=$(cd "$target_dir" && sh "$tmpfile" 2>&1); then
                if [ -n "$output" ]; then
                    log_line "$output"
                    hits=1
                fi
            else
                log_error "$output"
            fi
            rm -f "$tmpfile"
        }

        current_block=""
        flush_block() {
            if [ -n "$current_block" ]; then
                run_block "$current_block"
                current_block=""
            fi
        }

        while IFS= read -r line || [ -n "$line" ]; do
            trimmed_leading="${line#${line%%[![:space:]]*}}"

            # Empty or whitespace-only lines break blocks
            if [ -z "$trimmed_leading" ]; then
                flush_block
                continue
            fi

            # Skip standalone comments before a block starts
            case "$trimmed_leading" in
                '#'* )
                    [ -z "$current_block" ] && continue
                    ;;
            esac

            if [ -n "$current_block" ]; then
                current_block=$(printf '%s\n%s' "$current_block" "$line")
            else
                current_block="$line"
            fi
        done < "$detections_path"
        flush_block
    else
        log_error "[!] Detections file not found: $detections_path"
    fi

    [ "$hits" -eq 0 ] && log_line "  No detection hits"
}

run_scan() {
    target_dir="$1"
    if [ -z "$target_dir" ]; then
        log_error "[!] Scan mode requires a directory path"
        exit 1
    fi

    if [ ! -d "$target_dir" ]; then
        log_error "[!] Scan path does not exist or is not a directory: $target_dir"
        exit 1
    fi

    SCAN_FINDINGS_FILE="$target_dir/scan_findings.txt"
    : > "$SCAN_FINDINGS_FILE"

    log_line "[+] Starting scan of $target_dir"
    scan_network_connections "$target_dir"
    scan_processes "$target_dir"
    scan_cron "$target_dir"
    scan_users "$target_dir"
    run_detections "$target_dir"
    log_line "\n[+] Scan complete"
}

if [ "$MODE" = "scan" ]; then
    run_scan "$SCAN_PATH"
    exit 0
fi

if [ "$MODE" != "collect" ]; then
    echo "[!] No mode selected. Use -c for collection or -s <path> for scanning." >&2
    show_help
    exit 1
fi

if [ -d "/vmfs/volumes/datastore1" ]; then
    BASEDIR="/vmfs/volumes/datastore1"
elif [ -d "/tmp" ]; then
    BASEDIR="/tmp"
else
    echo "[!] Neither /vmfs/volumes/datastore1 nor /tmp is available as a base directory." >&2
    exit 1
fi

OUTDIR="${BASEDIR}/esxi_triage_$(hostname)_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

# System and Host Information
vmware -v > "$OUTDIR/esxi_version.txt"
hostname > "$OUTDIR/hostname.txt"
date > "$OUTDIR/date.txt"
uptime > "$OUTDIR/uptime.txt"

# Configuration and Installed Software
esxcli software vib list > "$OUTDIR/vib_list.txt"
esxcli system services list > "$OUTDIR/services_list.txt"

# Scheduled Tasks and Persistence
cat /var/spool/cron/crontabs/root > "$OUTDIR/root_crontab.txt" 2>/dev/null
ls -al /etc/rc.local.d/ > "$OUTDIR/rc_local_d_listing.txt" 2>/dev/null
cat /etc/rc.local.d/local.sh > "$OUTDIR/rc_local_d_local.sh.txt" 2>/dev/null

# Network and Storage
esxcli network ip neighbor list > "$OUTDIR/arp_cache.txt"
esxcli network ip route ipv4 list > "$OUTDIR/ipv4_routes.txt"
esxcli storage filesystem list > "$OUTDIR/filesystems.txt"
esxcli storage nfs list > "$OUTDIR/nfs_shares.txt"

# Accounts and Permissions
esxcli system permission list > "$OUTDIR/permissions.txt"
cat /etc/group > "$OUTDIR/group.txt" 2>/dev/null

# Process and Network Data
esxcli system process list > "$OUTDIR/process_list.txt"
esxcli network ip connection list > "$OUTDIR/network_connections.txt"
esxcli network firewall ruleset list > "$OUTDIR/firewall_rules.txt"
esxcli network firewall ruleset rule list > "$OUTDIR/firewall_rules_detailed.txt"
esxcli network firewall get > "$OUTDIR/firewall_config.txt"
esxcli system account list > "$OUTDIR/user_accounts.txt"
esxcli system settings advanced list > "$OUTDIR/advanced_settings.txt"

# File System and Binary Integrity
md5sum /bin/* > "$OUTDIR/bin_md5sums.txt" 2>/dev/null
ls -al /tmp/ > "$OUTDIR/tmp_listing.txt"

# Running VMs
vim-cmd vmsvc/getallvms > "$OUTDIR/running_vms.txt"

# Comprehensive Log Collection
cp /var/log/* "$OUTDIR/" 2>/dev/null
cp /scratch/log/* "$OUTDIR/" 2>/dev/null

# Additional logs (if present)
[ -f /var/log/auth.log ] && cp /var/log/auth.log "$OUTDIR/auth.log"
[ -f /var/log/hostd.log ] && cp /var/log/hostd.log "$OUTDIR/hostd.log"
[ -f /var/log/syslog.log ] && cp /var/log/syslog.log "$OUTDIR/syslog.log"
[ -f /var/log/shell.log ] && cp /var/log/shell.log "$OUTDIR/shell.log"

# Hash Collected Files
cd "$OUTDIR"
md5sum * > hashes.md5
cd /

# Archive and Clean Up
(cd "$BASEDIR" && tar -czf "$(basename "$OUTDIR").tar.gz" "$(basename "$OUTDIR")" >/dev/null)
echo "[+] Triage collection complete: ${OUTDIR}.tar.gz"
rm -rf "$OUTDIR"
