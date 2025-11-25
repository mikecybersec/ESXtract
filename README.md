# ESXtract
ESXtract is a project focused on improving the forensics collection process from ESXi hosts.</br>
The guide related to this utility is here; https://mikecybersec.notion.site/ESXi-IR-Guide-0ffbcec7272244d6b10dba4f4d16a7c8?pvs=74

## Usage

```
chmod +x ./esxtract.sh

# Collect artifacts on an ESXi host
./esxtract.sh -c

# Scan a previously collected (unzipped) folder for indicators of attack
./esxtract.sh -s /path/to/esxi_triage_<hostname>_<date>
```

The scan mode reviews key text outputs (such as `network_connections.txt`, `process_list.txt`,
`root_crontab.txt`, and `user_accounts.txt`) to highlight:

- Potential external IPv4 connections
- Processes tied to common attacker tooling or temporary directories
- Non-comment cron entries
- Accounts outside a baseline ESXi user list

## Planned Changes
- Offer a compiled version
- Add usage instructions
- Add cleanup option
- Add option to push to S3 bucket
- Add a 'chainsaw' function to identify Indicators of Attack (IoA)
- Add feature to check for presence of known vulnerabilities/misconfigurations that help common ESXi incidents to manifest or worsen.
- Add option for password
- Add option for verbose or quiet mode
