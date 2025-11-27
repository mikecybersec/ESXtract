# ESXtract
ESXtract is a project focused on improving the forensics collection process from ESXi hosts.</br>
The guide related to this utility is here; https://mikecybersec.notion.site/ESXi-IR-Guide-0ffbcec7272244d6b10dba4f4d16a7c8?pvs=7

## Usage
Note there are 2 modes!

**Options**

- `-h`, `--help`: Show the help message and exit.
- `-c`, `--collection`: Run the artifact collection workflow on an ESXi host.
- `-s <dir>`, `--scan <dir>`: Scan an extracted collection folder for suspicious indicators.
- `-d <file>`, `--detections <file>`: Use a custom detections file during scanning (defaults to the bundled `detections.sh`).
### Collector Mode - To be ran on ESXi via shell

Example:

```bash
./esxtract.sh -c
```

1. Upload `esxtract.sh` to a VMware ESXi datastore (for example, using vSphere Client or Datastore Browser).
2. SSH into the ESXi host or open the ESXi Shell and navigate to the script location (for example, `/vmfs/volumes/datastore1/`).
3. Make the script executable: `chmod +x ./esxtract.sh`
4. Collect forensic artifacts on the ESXi host: `./esxtract.sh -c`
   - The resulting archive (`esxi_triage_<hostname>_<date>.tar.gz`) is written to `/vmfs/volumes/datastore1` when available, or `/tmp` otherwise. Download it from the host for further analysis.
5. Scan a previously collected (unzipped) folder for quick indicators of attack: `./esxtract.sh -s /path/to/esxi_triage_<hostname>_<date>`
   - Use custom detection pipelines during scanning with `./esxtract.sh -s /path/to/esxi_triage_<hostname>_<date> -d /path/to/detections.sh`.
   - When a detections file is provided, each non-comment line is executed from within the scan directory; if no file is specified, the bundled `detections.sh` runs by default.
6. For help or usage details at any time: `./esxtract.sh --help`

### Scan Mode - To be ran against your collection via your forensics machine
Example:

```bash
./esxtract.sh -s /path/to/esxi_triage_<hostname>_<date> [-d /path/to/detections.sh]
```

The scan mode reviews key text outputs (such as `network_connections.txt`, `process_list.txt`, `root_crontab.txt`, and `user_accounts.txt`) to highlight:

- Potential external IPv4 connections
- Processes tied to common attacker tooling or temporary directories
- Non-comment cron entries
- Accounts outside a baseline ESXi user list

#### Writing a custom detections file
- Each non-empty, non-comment line should be a shell pipeline that **only reads** files inside the scan directory; avoid commands that modify files or reach the network.
- Prefer `grep`, `awk`, `sed`, and similar read-only utilities, and remember that each pipeline is executed with the scan directory as the working directory (use `.` or relative paths).
- Add `--exclude=detections.sh` (or the name of your detection file) to recursive `grep` commands so they do not match on the rule file itself when it sits in the scan directory.
- Quote patterns that contain special characters and append a clear marker (for example, `'<-- Description>'`) so hits are easy to spot in the output.
- Save your rules into a file (for example, `detections.sh`) and run `./esxtract.sh -s /path/to/collection -d /path/to/detections.sh`. If no file is provided, the bundled detections file runs automatically and the log will still report when no detections fire.
- The repository ships with `detections.sh`, which includes out-of-the-box detection rules converted from Splunk's ESXi ransomware guidance so they work directly in ESXtract. You can use the default rules, fork and adjust them, or point to your own file entirely. See the original reference for additional context: https://www.splunk.com/en_us/blog/security/detecting-esxi-ransomware-activity-splunk.html

Example custom rule line:

```
grep -R -H -E "unexpected user" . | awk '{ print $0 "   <-- Suspicious account change" }'
```

## Planned Changes
- Offer a compiled version
- Add atomic tests for scanning function
- Add option to push to S3 bucket
- Add feature to check for presence of known vulnerabilities/misconfigurations that help common ESXi incidents to manifest or worsen.
- Add option for verbose or quiet mode
- Add detection for potentially falsified VIBs
