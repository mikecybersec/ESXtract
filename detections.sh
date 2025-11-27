grep -R -H --exclude=detections.sh -E "esxcli system account" . \
  | grep -E "\-i |--id" \
  | grep -Ev "shell" \
  | awk '{ print $0 "   <-- ESXi Account Modified" }'

grep -R -H --exclude=detections.sh -E "esxcli system auditrecords" . \
  | grep -E "remote|local" \
  | grep -Ev "shell" \
  | awk '{ print $0 "   <-- ESXi Audit Tampering" }'

grep -R -H --exclude=detections.sh -E "pkill -9 vmx-" . \
  | awk '{ print $0 "   <-- ESXi Bulk VM Termination" }'

grep -R -H --exclude=detections.sh -E "esxcli" . \
  | grep -E "--format-param" \
  | grep -E "vm process list" \
  | grep -E "awk" \
  | grep -E "esxcli vm process kill" \
  | awk '{ print $0 "   <-- ESXi Bulk VM Termination" }'

grep -R -H --exclude=detections.sh -E "Download failed|Failed to download file|File download error|Could not download" . \
  | awk '{ print $0 "   <-- ESXi Download Errors" }'

grep -R -H --exclude=detections.sh -E "system settings encryption set" . \
  | grep -Ev "shell" \
  | grep -E " -s | -e |--require-secure-boot|require-exec-installed-only|execInstalledOnly" \
  | awk '{ print $0 "   <-- ESXi Encryption Settings Modified" }'

grep -R -H --exclude=detections.sh -E "root" . \
  | grep -E "logged in" \
  | grep -E "root@[0-9]{1,3}(\.[0-9]{1,3}){3}" \
  | grep -Ev "root@127\.|root@10\.|root@192\.168\.|root@172\.(1[6-9]|2[0-9]|3[0-1])\." \
  | awk '{ print $0 "   <-- ESXi External Root Login Activity" }'

grep -R -H --exclude=detections.sh -E "network firewall set" . \
  | grep -E "enabled f" \
  | awk '{ print $0 "   <-- ESXi Firewall Disabled" }'

grep -R -H --exclude=detections.sh -E "lockdownmode\.disabled|Administrator access to the host has been enabled" . \
  | awk '{ print $0 "   <-- ESXi Lockdown Mode Disabled" }'

grep -R -H --exclude=detections.sh -E "Set called with key" . \
  | grep -E "Syslog\.global\.logHost|Syslog\.global\.logdir" \
  | awk '{ print $0 "   <-- ESXi Loghost Config Tampering" }'

grep -R -H --exclude=detections.sh -E "image profile with validation disabled\.|image profile bypassing signing and acceptance level verification\.|vib without valid signature," . \
  | awk '{ print $0 "   <-- ESXi Malicious VIB Forced Install" }'

grep -R -H --exclude=detections.sh -E "bash -i >&|/dev/tcp/|/dev/udp/|socat exec:|socket\(S,PF_INET" . \
  | awk '{ print $0 "   <-- ESXi Reverse Shell Patterns" }'

grep -R -H --exclude=detections.sh -E "shell\[" . \
  | grep -E "/etc/shadow|/etc/vmware/hostd/hostd\.xml|/etc/vmware/vpxa/vpxa\.cfg|/etc/sfcb/sfcb\.cfg|/etc/security/|/etc/likewise/krb5-affinity\.conf|/etc/vmware-vpx/vcdb\.properties" \
  | awk '{ print $0 "   <-- ESXi Sensitive Files Accessed" }'

grep -R -H --exclude=detections.sh -E "root" . \
  | grep -E "logged in" \
  | grep -E "root@[0-9]{1,3}(\.[0-9]{1,3}){3}" \
  | grep -Ev "root@127\.0\.0\.1" \
  | awk '{ print $0 "   <-- ESXi Shared or Stolen Root Account" }'

grep -R -H --exclude=detections.sh -E "ESXi Shell" . \
  | grep -E "has been enabled" \
  | awk '{ print $0 "   <-- ESXi Shell Access Enabled" }'

grep -R -H --exclude=detections.sh -E "syslog config set" . \
  | grep -E "esxcli" \
  | awk '{ print $0 "   <-- ESXi Syslog Config Change" }'

grep -R -H --exclude=detections.sh -E "NTPClock" . \
  | grep -E "system clock stepped" \
  | awk '{ print $0 "   <-- ESXi System Clock Manipulation" }'

grep -R -H --exclude=detections.sh -E "system" . \
  | grep -E "esxcli" \
  | grep -E "get|list" \
  | grep -E "user=" \
  | grep -Ev "filesystem" \
  | awk '{ print $0 "   <-- ESXi System Information Discovery" }'

grep -R -H --exclude=detections.sh -E "esxcli system permission set" . \
  | grep -E "role Admin" \
  | awk '{ print $0 "   <-- ESXi User Granted Admin Role" }'

grep -R -H --exclude=detections.sh -E "esxcli software acceptance set" . \
  | grep -E "shell" \
  | awk '{ print $0 "   <-- ESXi VIB Acceptance Level Tampering" }'

grep -R -H --exclude=detections.sh -E "esxcli vm process" . \
  | grep -E "list" \
  | awk '{ print $0 "   <-- ESXi VM Discovery" }'

grep -R -H --exclude=detections.sh -E "File download from path" . \
  | grep -E "was initiated from" \
  | awk '{ print $0 "   <-- ESXi VM Exported via Remote Tool" }'



