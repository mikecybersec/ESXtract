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
#   4. Make it executable: chmod +x ./esxi_triage.sh
#   5. Run it: ./esxi_triage.sh
#   6. Retrieve the resulting .tar.gz archive from /vmfs/volumes/datastore1 when present, or from /tmp otherwise, for analysis.
#
# For help: ./esxi_triage.sh --help
###############################################################################

show_help() {
cat << EOF
ESXi Incident Response Triage Script

This script collects forensic artifacts from a VMware ESXi host for incident response.

Instructions:
  1. Upload this script to a VMware datastore (e.g., using vSphere Client).
  2. SSH into the ESXi host or use the ESXi Shell.
  3. Navigate to the script location (e.g., /vmfs/volumes/datastore1/).
  4. Make it executable:
       chmod +x ./esxi_triage.sh
  5. Run the script:
       ./esxi_triage.sh
  6. The output archive (esxi_triage_<hostname>_<date>.tar.gz) will be created in
     /vmfs/volumes/datastore1 when that datastore exists, or in /tmp if it does not.
     Download it from the host for further analysis.

Options:
  -h, --help      Show this help message and exit

References:
  - DCScoder/ESXiTri
  - iBlue Team ESXi Forensics
  - Synacktiv Velociraptor ESXi Forensics
  - Aon QELP ESXi Log Parsing
  - Binalyze AIR ESXi Collector

EOF
}

# Parse arguments for help
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    show_help
    exit 0
fi

OUTDIR="/tmp/esxi_triage_$(hostname)_$(date +%Y%m%d_%H%M%S)"
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
tar czf "${OUTDIR}.tar.gz" -C /tmp "$(basename "$OUTDIR")"
rm -rf "$OUTDIR"

echo "[+] Triage collection complete: ${OUTDIR}.tar.gz"
