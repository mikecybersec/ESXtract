# ESXtract
ESXtract is a project focused on improving the forensics collection process from ESXi hosts.</br>
The guide related to this utility is here; https://mikecybersec.notion.site/ESXi-IR-Guide-0ffbcec7272244d6b10dba4f4d16a7c8?pvs=7

## Usage
Note there are 2 modes!

### Collector Mode - To be ran on ESXi via shell

1. Upload `esxtract.sh` to a VMware ESXi datastore (for example, using vSphere Client or Datastore Browser).
2. SSH into the ESXi host or open the ESXi Shell and navigate to the script location (for example, `/vmfs/volumes/datastore1/`).
3. Make the script executable: `chmod +x ./esxtract.sh`
4. Collect forensic artifacts on the ESXi host: `./esxtract.sh -c`
   - The resulting archive (`esxi_triage_<hostname>_<date>.tar.gz`) is written to `/vmfs/volumes/datastore1` when available, or `/tmp` otherwise. Download it from the host for further analysis.
5. Scan a previously collected (unzipped) folder for quick indicators of attack: `./esxtract.sh -s /path/to/esxi_triage_<hostname>_<date>`
6. For help or usage details at any time: `./esxtract.sh --help`

### Scan Mode - To be ran against your collection via your forensics machine
The scan mode reviews key text outputs (such as `network_connections.txt`, `process_list.txt`, `root_crontab.txt`, and `user_accounts.txt`) to highlight:

- Potential external IPv4 connections
- Processes tied to common attacker tooling or temporary directories
- Non-comment cron entries
- Accounts outside a baseline ESXi user list

## Planned Changes
- Offer a compiled version
- Add cleanup option
- Add option to push to S3 bucket
- Add a 'chainsaw' function to identify Indicators of Attack (IoA)
- Add feature to check for presence of known vulnerabilities/misconfigurations that help common ESXi incidents to manifest or worsen.
- Add option for password
- Add option for verbose or quiet mode
