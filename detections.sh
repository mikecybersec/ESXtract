grep -R -H --exclude=detections.sh -E "esxcli system account" . \
  | grep -E "\-i |--id" \
  | grep -Ev "shell" \
  | awk -F: '
    {
        file = $1
        gsub(/^\.\//, "", file)
        count[file]++
    }
    END {
        for (f in count) {
            printf("[+] %d findings in %s - ESXi Account Modified\n", count[f], f)
        }
    }
'

grep -R -H --exclude=detections.sh -E "esxcli system auditrecords" . \
  | grep -E "remote|local" \
  | grep -Ev "shell" \
  | awk -F: '
    {
        file = $1
        gsub(/^\.\//, "", file)
        count[file]++
    }
    END {
        for (f in count) {
            printf("[+] %d findings in %s - ESXi Audit Tampering\n", count[f], f)
        }
    }
'

grep -R -H --exclude=detections.sh -E "pkill -9 vmx-" . \
  | awk -F: '
    {
        file = $1
        gsub(/^\.\//, "", file)
        count[file]++
    }
    END {
        for (f in count) {
            printf("[+] %d findings in %s - ESXi Bulk VM Termination\n", count[f], f)
        }
    }
'

grep -R -H -a --exclude=detections.sh -E "esxcli" . \
  | grep -E -- "--format-param" \
  | grep -E "vm process list" \
  | grep -E "awk" \
  | grep -E "esxcli vm process kill" \
  | awk -F: '
    {
        file = $1
        gsub(/^\.\//, "", file)
        count[file]++
    }
    END {
        for (f in count) {
            printf("[+] %d findings in %s - ESXi Bulk VM Termination\n", count[f], f)
        }
    }
'

grep -R -H --exclude=detections.sh -E "Download failed|Failed to download file|File download error|Could not download" . \
  | awk -F: '
    {
        file = $1
        gsub(/^\.\//, "", file)
        count[file]++
    }
    END {
        for (f in count) {
            printf("[+] %d findings in %s - ESXi Download Errors\n", count[f], f)
        }
    }
'

grep -R -H --exclude=detections.sh -E "system settings encryption set" . \
  | grep -Ev "shell" \
  | grep -E " -s | -e |--require-secure-boot|require-exec-installed-only|execInstalledOnly" \
  | awk -F: '
    {
        file = $1
        gsub(/^\.\//, "", file)
        count[file]++
    }
    END {
        for (f in count) {
            printf("[+] %d findings in %s - ESXi Encryption Settings Modified\n", count[f], f)
        }
    }
'

grep -R -H --binary-files=without-match --exclude=detections.sh -E "root" . \
  | grep -E "logged in" \
  | grep -E "root@[0-9]{1,3}(\.[0-9]{1,3}){3}" \
  | grep -Ev "root@127\.|root@10\.|root@192\.168\.|root@172\.(1[6-9]|2[0-9]|3[0-1])\." \
  | awk -F: '
    {
        file = $1
        gsub(/^\.\//, "", file)
        count[file]++
    }
    END {
        for (f in count) {
            printf("[+] %d findings in %s - ESXi External Root Login Activity\n", count[f], f)
        }
    }


grep -R -H --exclude=detections.sh -E "network firewall set" . \
  | grep -E "enabled f" \
  | awk -F: '
    {
        file = $1
        gsub(/^\.\//, "", file)
        count[file]++
    }
    END {
        for (f in count) {
            printf("[+] %d findings in %s - ESXi Firewall Disabled\n", count[f], f)
        }
    }
'

grep -R -H --exclude=detections.sh -E "lockdownmode\.disabled|Administrator access to the host has been enabled" . \
  | awk -F: '
    {
        file = $1
        gsub(/^\.\//, "", file)
        count[file]++
    }
    END {
        for (f in count) {
            printf("[+] %d findings in %s - ESXi Lockdown Mode Disabled\n", count[f], f)
        }
    }
'

grep -R -H --exclude=detections.sh -E "Set called with key" . \
  | grep -E "Syslog\.global\.logHost|Syslog\.global\.logdir" \
  | awk -F: '
    {
        file = $1
        gsub(/^\.\//, "", file)
        count[file]++
    }
    END {
        for (f in count) {
            printf("[+] %d findings in %s - ESXi Loghost Config Tampering\n", count[f], f)
        }
    }
'

grep -R -H --exclude=detections.sh -E "image profile with validation disabled\.|image profile bypassing signing and acceptance level verification\.|vib without valid signature," . \
  | awk -F: '
    {
        file = $1
        gsub(/^\.\//, "", file)
        count[file]++
    }
    END {
        for (f in count) {
            printf("[+] %d findings in %s - ESXi Malicious VIB Forced Install\n", count[f], f)
        }
    }
'

grep -R -H --exclude=detections.sh -E "bash -i >&|/dev/tcp/|/dev/udp/|socat exec:|socket\(S,PF_INET" . \
  | awk -F: '
    {
        file = $1
        gsub(/^\.\//, "", file)
        count[file]++
    }
    END {
        for (f in count) {
            printf("[+] %d findings in %s - ESXi Reverse Shell Patterns\n", count[f], f)
        }
    }
'

grep -R -H --exclude=detections.sh -E "shell\[" . \
  | grep -E "/etc/shadow|/etc/vmware/hostd/hostd\.xml|/etc/vmware/vpxa/vpxa\.cfg|/etc/sfcb/sfcb\.cfg|/etc/security/|/etc/likewise/krb5-affinity\.conf|/etc/vmware-vpx/vcdb\.properties" \
  | awk -F: '
    {
        file = $1
        gsub(/^\.\//, "", file)
        count[file]++
    }
    END {
        for (f in count) {
            printf("[+] %d findings in %s - ESXi Sensitive Files Accessed\n", count[f], f)
        }
    }
'

grep -R -H --exclude=detections.sh -E "root" . \
  | grep -E "logged in" \
  | grep -E "root@[0-9]{1,3}(\.[0-9]{1,3}){3}" \
  | grep -Ev "root@127\.0\.0\.1" \
  | awk -F: '
    {
        file = $1
        gsub(/^\.\//, "", file)
        count[file]++
    }
    END {
        for (f in count) {
            printf("[+] %d findings in %s - ESXi Shared or Stolen Root Account\n", count[f], f)
        }
    }
'

grep -R -H --exclude=detections.sh -E "ESXi Shell" . \
  | grep -E "has been enabled" \
  | awk -F: '
    {
        file = $1
        gsub(/^\.\//, "", file)
        count[file]++
    }
    END {
        for (f in count) {
            printf("[+] %d findings in %s - ESXi Shell Access Enabled\n", count[f], f)
        }
    }
'

grep -R -H --exclude=detections.sh -E "syslog config set" . \
  | grep -E "esxcli" \
  | awk -F: '
    {
        file = $1
        gsub(/^\.\//, "", file)
        count[file]++
    }
    END {
        for (f in count) {
            printf("[+] %d findings in %s - ESXi Syslog Config Change\n", count[f], f)
        }
    }
'

grep -R -H --exclude=detections.sh -E "NTPClock" . \
  | grep -E "system clock stepped" \
  | awk -F: '
    {
        file = $1
        gsub(/^\.\//, "", file)
        count[file]++
    }
    END {
        for (f in count) {
            printf("[+] %d findings in %s - ESXi System Clock Manipulation\n", count[f], f)
        }
    }
'

grep -R -H --exclude=detections.sh -E "Hostd\[[0-9]+\].*Dispatch.*system\.[A-Za-z0-9_]+\.(get|list)( done)?" .   | grep -E "opID=esxcli"   | grep -E "user=[A-Za-z0-9_-]+"   | grep -Ev "filesystem"   | awk '
    {
        pos = index($0, ":")
        file = substr($0, 1, pos-1)
        gsub("^\./", "", file)
        count[file]++
    }
    END {
        for (f in count) {
            printf("[+] %d findings in %s - ESXi System Information Discovery\n", count[f], f)
        }
    }
'

grep -R -H --exclude=detections.sh -E "esxcli system permission set" . \
  | grep -E "role Admin" \
  | awk -F: '
    {
        file = $1
        gsub(/^\.\//, "", file)
        count[file]++
    }
    END {
        for (f in count) {
            printf("[+] %d findings in %s - ESXi User Granted Admin Role\n", count[f], f)
        }
    }
'

grep -R -H --exclude=detections.sh -E "esxcli software acceptance set" . \
  | grep -E "shell" \
  | awk -F: '
    {
        file = $1
        gsub(/^\.\//, "", file)
        count[file]++
    }
    END {
        for (f in count) {
            printf("[+] %d findings in %s - ESXi VIB Acceptance Level Tampering\n", count[f], f)
        }
    }
'

grep -R -H --exclude=detections.sh -E "esxcli vm process" . \
  | grep -E "list" \
  | awk -F: '
    {
        file = $1
        gsub(/^\.\//, "", file)
        count[file]++
    }
    END {
        for (f in count) {
            printf("[+] %d findings in %s - ESXi VM Discovery\n", count[f], f)
        }
    }
'

grep -R -H --exclude=detections.sh -E "File download from path" . \
  | grep -E "was initiated from" \
  | grep -Ev "\.vmdk([ '\"]|$)" \
  | awk -F: '
    {
        file = $1
        gsub(/^\.\//, "", file)
        count[file]++
    }
    END {
        for (f in count) {
            printf("[+] %d findings in %s - File Exported via Remote Tool\n", count[f], f)
        }
    }
'

grep -R -H --exclude=detections.sh -E "File download from path" . \
  | grep -E "was initiated from" \
  | grep -Ei "\.vmdk'" \
  | awk -F: '
    {
        file = $1
        gsub(/^\.\//, "", file)
        count[file]++
    }
    END {
        for (f in count) {
            printf("[+] %d findings in %s - ESXi VM Exported via Remote Tool\n", count[f], f)
        }
    }
'
