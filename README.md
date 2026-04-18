# blocklist-firewall-update

Language: 🇬🇧 English | [🇩🇪 Deutsch](README.de.md)

### Overview
This project provides a shell script that downloads IP blocklists from multiple threat intelligence sources and updates a local firewall block set.

Supported sources (focused on SSH and web login attacks):
- **blocklist.de** – SSH, brute-force, mail, web, and more
- **AbuseIPDB** – community-reported abusive IPs (API key required)
- **DShield** – top attacking /24 networks (no key required)
- **FireHOL** – aggregated curated IP sets (no key required)
- **ThreatFox** – C2 and malware IOC IPs from abuse.ch (no key required)

The script:
- Reads a config file to determine which sources are enabled
- Downloads feeds and validates IPv4 addresses and CIDR blocks
- Loads entries into an ipset (`hash:net`) using a temporary set and atomic swap
- Applies an iptables chain that drops traffic from listed source IPs
- Prints a short update summary (added/removed/net change)

Main files:
- `blocklist-firewall-update.sh` – main script
- `blocklist-firewall-update.conf` – configuration file

### Requirements
Install and make sure these commands are available:
- curl
- ipset
- iptables

You also need:
- Linux system with iptables/ipset support
- Root privileges to change firewall rules

### Configuration
Configuration is done via `blocklist-firewall-update.conf`. A template file `blocklist-firewall-update.conf.example` is provided. Copy it to create your config:

```sh
cp blocklist-firewall-update.conf.example blocklist-firewall-update.conf
# Edit as needed
```

The script searches for the config file in:
1. Path from the `CONFIG_FILE` environment variable
2. Same directory as the script (`blocklist-firewall-update.sh`)
3. `/etc/blocklist-firewall-update.conf`

All settings can also be set as environment variables. Settings in the config file override the script's built-in defaults.

Key configuration options:

| Variable | Default | Description |
|---|---|---|
| `BLOCKLIST_CHAIN_NAME` | `BLOCKLIST_INPUT` | Name of the iptables chain |
| `ENABLE_BLOCKLIST_DE` | `yes` | Enable blocklist.de source |
| `BLOCKLIST_DE_TYPES` | `ssh,bruteforcelogin` | Comma-separated blocklist.de types |
| `ENABLE_ABUSEIPDB` | `no` | Enable AbuseIPDB source |
| `ABUSEIPDB_API_KEY` | _(empty)_ | AbuseIPDB API key (required when enabled) |
| `ABUSEIPDB_CONFIDENCE_MINIMUM` | `90` | Minimum abuse confidence score (1–100) |
| `ENABLE_DSHIELD` | `no` | Enable DShield source |
| `DSHIELD_URL` | _(dshield URL)_ | DShield block list URL |
| `ENABLE_FIREHOL` | `no` | Enable FireHOL source |
| `FIREHOL_SETS` | `firehol_level1 firehol_level2` | Space-separated FireHOL set names |
| `ENABLE_THREATFOX` | `no` | Enable ThreatFox source |
| `THREATFOX_DAYS` | `7` | Fetch IOCs from the last N days (1–7) |

Each enabled source maintains its own **dedicated ipset** with a fixed name:

| Source | ipset name |
|---|---|
| blocklist.de | `blocklist_de` |
| AbuseIPDB | `abuseipdb_com` |
| DShield | `dshield_org` |
| FireHOL (per set) | same as the set name, e.g. `firehol_level1` |
| ThreatFox | `threatfox_abuse_ch` |

The iptables chain gets one `match-set … src -j DROP` rule per active ipset.

When using the provided `blocklist-firewall-update.conf`, all sources except AbuseIPDB are enabled by default.

Allowed values for `BLOCKLIST_DE_TYPES`: `all`, `ssh`, `mail`, `apache`, `imap`, `ftp`, `sip`, `bots`, `strongips`, `ircbot`, `bruteforcelogin`

FireHOL sets focused on login attacks: `firehol_level1`, `firehol_level2`, `sshpranker`
(Browse all sets at https://iplists.firehol.org/)

### How It Works
1. Load `blocklist-firewall-update.conf` if found.
2. For each enabled source, download the feed and write entries to a per-source raw file.
3. For each source: keep only valid IPv4 addresses and CIDR blocks, deduplicate, and load into a dedicated `hash:net` ipset using a temporary set and atomic swap. Per-set stats (entries, added, removed) are logged.
4. Migrate any existing `hash:ip` sets to `hash:net` automatically (one-time).
5. Flush the iptables chain and add one `match-set … src -j DROP` rule per active ipset.
6. Ensure chain is linked into `INPUT`.
7. Print a summary listing the chain name and all active ipsets.

### Usage
Set up the config file first time:

```sh
cp blocklist-firewall-update.conf.example blocklist-firewall-update.conf
# edit blocklist-firewall-update.conf as needed
```

Run the script:

```sh
sudo sh ./blocklist-firewall-update.sh
```

Dry run with command-line option:

```sh
sudo sh ./blocklist-firewall-update.sh -n
# or
sudo sh ./blocklist-firewall-update.sh --dry-run
```

Use a custom config file path:

```sh
sudo CONFIG_FILE=/etc/blocklist-firewall-update.conf sh ./blocklist-firewall-update.sh
```

Override individual settings via environment variables:

```sh
sudo ENABLE_DSHIELD=yes ENABLE_FIREHOL=no sh ./blocklist-firewall-update.sh
```

Custom chain name:

### Cron Example
Run every 10 minutes:

```cron
*/10 * * * * /bin/sh /path/to/blocklist-firewall-update.sh >> /path/to/log/blocklist-update.log 2>&1
```

### Notes and Caveats
- IPv4 addresses and CIDR blocks are accepted; IPv6 is not supported.
- The ipset type is `hash:net` (supports both individual IPs and CIDR ranges). Existing `hash:ip` sets are automatically migrated on first run.
- The chain is flushed on every run and rebuilt with one DROP rule matching the ipset.
- Existing unrelated firewall rules are not modified, but rule order in `INPUT` matters.
- In dry-run mode, actions are printed and not executed.
- AbuseIPDB requires a free API key from https://www.abuseipdb.com/register
- If a source download fails, it is skipped and other sources continue normally.

### Troubleshooting

- `curl not found`: install curl.
- `ipset not found`: install ipset tools/package.
- `iptables not found`: install iptables package.
- No effect on traffic:
  - verify chain is linked in `INPUT`
  - verify set name matches chain rule
  - inspect rules with `iptables -S` and set members with `ipset list <set>`

#### Example: Inspect the iptables chain

```sh
sudo iptables -L BLOCKLIST_INPUT -n -v
```

Sample output:

```
Chain BLOCKLIST_INPUT (1 references)
 pkts bytes target     prot opt in     out     source               destination
    4   240 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set blocklist_de src
    1    60 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set dshield_org src
    2   120 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set firehol_level1 src
```

#### Example: List the content of a set

```sh
sudo ipset list blocklist_de
sudo ipset list dshield_org
sudo ipset list firehol_level1
```

#### Example: Remove a stale set that is no longer used

```sh
sudo ipset destroy blocklist_combined
```
