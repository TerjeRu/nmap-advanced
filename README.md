````markdown
# █▓▒▒░░░ THE ULTIMATE **NMAP** NETWORK‑SCANNING TUTORIAL ░░░▒▒▓█

> **Goal:** Take you from “I can run `nmap -F`” to “I can fine‑tune scans, evade an IDS, parse XML into Splunk,
> and teach others why each packet matters.”
>
> **Lab Topology (minimum):**
> * **Attacker VM:** Kali Linux 2024.4 or later
> * **Target VM:** Metasploitable 2 (192.168.56.102 used throughout)
> * **Network:** _Host‑Only Adapter_ – keeps scans off your real LAN
> * **Optionally:** A third VM with Zeek/Snort if you want live detection practice
>
> **Audience:** Budding SOC analysts, red‑team interns, or the unlucky soul suddenly in charge of vulnerability scans.
>
> **Formatting legend:**
> * **LIVE EXERCISE** = hands‑on task (do it!)
> * `code` = paste into your terminal
> * *Blue‑Team Insight* = what defenders should notice

---

## 目次 – TABLE OF CONTENTS

1. [壱 – LAB PREPARATION](#壱--lab-preparation)
2. [弐 – INSTALLING & UPDATING NMAP](#弐--installing--updating-nmap)
3. [参 – THE ANATOMY OF A SCAN LINE](#参--the-anatomy-of-a-scan-line)
4. [四 – TARGET SPECIFICATION](#四--target-specification)
5. [五 – HOST DISCOVERY (PING SCANS)](#五--host-discovery-ping-scans)
6. [六 – TCP PORT SCANNING MODES](#六--tcp-port-scanning-modes)
7. [七 – UDP PORT SCANNING](#七--udp-port-scanning)
8. [八 – SCTP & IP‑PROTOCOL SCANS](#八--sctp--ip-protocol-scans)
9. [九 – VERSION & OS DETECTION](#九--version--os-detection)
10. [拾 – TIMING & PERFORMANCE TUNING](#拾--timing--performance-tuning)
11. [拾壱 – FIREWALL / IDS EVASION FLAGS](#拾壱--firewall--ids-evasion-flags)
12. [拾弐 – NMAP SCRIPTING ENGINE (NSE)](#拾弐--nmap-scripting-engine-nse)
13. [拾参 – OUTPUT FORMATS & AUTOMATION](#拾参--output-formats--automation)
14. [拾肆 – BLUE‑TEAM ANALYSIS CHECKLIST](#拾肆--blue-team-analysis-checklist)
15. [拾伍 – FREQUENTLY FORGOTTEN FLAGS](#拾伍--frequently-forgotten-flags)
16. [拾陸 – CONTINUING EDUCATION](#拾陸--continuing-education)

_Total read‑through + lab time: ≈ 4 hours._

---

## 壱 – LAB PREPARATION

1. **Spin up the VMs.** Snapshot both so you can roll back quickly.
2. **Verify connectivity.** From Kali:
   ```bash
   ping -c3 192.168.56.102
````

If no response, fix your virtual switch *before* proceeding.
3\. **Install Wireshark on Kali** (already included in most ISO builds but make sure you have GUI libs):

```bash
sudo apt update && sudo apt install wireshark -y
sudo usermod -aG wireshark $USER
```

4. **Open two terminals**: one for Nmap, one for `tail -f /var/log/*` on the target (you’ll thank me later).

---

## 弐 – INSTALLING & UPDATING NMAP

```bash
sudo apt update && sudo apt install nmap -y
nmap --version   # Expect 7.95 or later
```

*Why update regularly?* Every release ships fresh OS and service fingerprints plus new NSE scripts. Stale fingerprints = wrong conclusions.

---

## 参 – THE ANATOMY OF A SCAN LINE

```bash
sudo nmap [Scan Type(s)] [Options] <target spec>
```

Example dissected:

```bash
sudo nmap -sS -p22,80,443 -A -T4 192.168.56.102
```

| Part             | Meaning                                                    |
| ---------------- | ---------------------------------------------------------- |
| `-sS`            | SYN (half‑open) scan                                       |
| `-p22,80,443`    | Port list                                                  |
| `-A`             | Aggressive: OS detect + version + traceroute + default NSE |
| `-T4`            | Timing template “Aggressive”                               |
| `192.168.56.102` | Target IP                                                  |

👉 **LIVE EXERCISE:** Type the above command. Then open Wireshark and filter `ip.addr==192.168.56.102` to see every packet generated.

---

## 四 – TARGET SPECIFICATION

Nmap lets you describe targets in multiple ways:

| Syntax    | Example                       | Notes                                    |
| --------- | ----------------------------- | ---------------------------------------- |
| Single IP | `192.168.56.102`              | Most common                              |
| CIDR      | `192.168.56.0/24`             | Scan a subnet                            |
| Range     | `192.168.56.100-120`          | Inclusive                                |
| DNS Name  | `example.com`                 | Beware CDN IP sprawl                     |
| File      | `-iL targets.txt`             | One per line                             |
| Exclude   | `--exclude 192.168.56.1`      | Skip host(s)                             |
| List Scan | `-sL`                         | Show list *– no packets sent to targets* |
| Randomize | `--randomize-hosts`           | Shuffle order                            |
| IPv6      | `-6 fe80::20c:29ff:fea1:b2c3` | Requires `-6` flag                       |

**Pro Tip:** Combine multiple lists: `nmap -iL prod_hosts.txt --exclude-file maintenance.txt`.

---

## 五 – HOST DISCOVERY (PING SCANS)

### 5.1 Difference Between “Discover” and “Scan”

A “ping scan” (`-sn`) tells you *what is up*; a “port scan” tells you *what is open*. Combine them, or run discovery first to avoid wasting packets on dead hosts.

### 5.2 Flags & When to Use Them

| Flag         | Packet Sent       | Purpose                                                   |
| ------------ | ----------------- | --------------------------------------------------------- |
| `-sn`        | ICMP Echo/ARP     | Skip port scan, just discover live hosts                  |
| `-Pn`        | *No* ping         | Treat targets as *alive* – necessary when ICMP is blocked |
| `-PS<ports>` | TCP SYN Ping      | Often 80,443 pass through firewalls                       |
| `-PA<ports>` | TCP ACK Ping      | Slip past some rulesets                                   |
| `-PE`        | ICMP Echo Request | Default on non‑local networks                             |
| `-PP`        | ICMP Timestamp    | Bypasses some echo filters                                |
| `-PM`        | ICMP Netmask      | Rarely filtered, great on old routers                     |
| `-PR`        | ARP Ping          | Fast & reliable on local LAN                              |
| `-n`         | No DNS resolve    | Saves time if you’re scanning IPs only                    |
| `-R`         | Force reverse DNS | When you *need* names for reporting                       |

### 5.3 **LIVE EXERCISE:** Compare Discovery Methods

```bash
sudo nmap -sn 192.168.56.0/24 -oN arp.txt          # Uses ARP
sudo nmap -Pn -p 1 192.168.56.102 -oN no_ping.txt   # Forces port scan w/o discovery
sudo nmap -PS80,443 192.168.56.102 -oN syn_ping.txt # SYN ping on web ports
```

*Blue‑Team Insight:* ICMP may be blocked, but a SYN to 80 often isn’t – watch for unanswered SYNs as pseudo‑pings.

---

## 六 – TCP PORT SCANNING MODES

Nmap’s bread and butter. Understand the flag = predict the packet pattern.

| Scan Type        | Flag           | Packet Logic                 | Privilege    | Notes                      |
| ---------------- | -------------- | ---------------------------- | ------------ | -------------------------- |
| Connect          | `-sT`          | Full 3‑way handshake         | Unprivileged | Easiest to log; slow       |
| SYN (Stealth)    | `-sS`          | SYN only, abort w/ RST       | Root         | Default for root scans     |
| ACK              | `-sA`          | Bare ACK                     | Root         | Map firewall state         |
| Window           | `-sW`          | Like ACK + window check      | Root         | Older fingerprint trick    |
| Maimon           | `-sM`          | FIN/ACK                      | Root         | Bypass old BSD filters     |
| FIN              | `-sF`          | FIN only                     | Root         | evade stateless ACLs       |
| NULL             | `-sN`          | No flags                     | Root         | same goal                  |
| Xmas             | `-sX`          | FIN+PSH+URG                  | Root         | flashy but obvious         |
| Idle             | `-sI <zombie>` | Spoofs via IPID side‑channel | Root         | Super stealth              |
| SCTP INIT        | `-sY`          | First packet of SCTP         | Root         | Rarely used                |
| SCTP COOKIE‑ECHO | `-sZ`          | Like connect for SCTP        | Root         |                            |
| IP Protocol      | `-sO`          | Enumerate IP proto field     | Root         | Finds non‑TCP/UDP services |

### 6.1 **LIVE EXERCISE:** Flag Bake‑Off

```bash
for m in sT sS sA sF sN sX; do
  sudo nmap -$m -p 1-200 --reason -oN scan_$m.txt 192.168.56.102
  echo "$m done"
done
```

Open each file, compare the `Reason` column (e.g., `syn-ack`, `rst`, `open|filtered`).

*Blue‑Team Insight:* Multiple RSTs from a single host to random high ports in a short window = NULL/FIN/Xmas scan.

### 6.2 Port Selection Flags

| Flag               | Example             | What It Does                                 |
| ------------------ | ------------------- | -------------------------------------------- |
| `-p`               | `-p22,80,443`       | Specify ports individually                   |
|                    | `-p1-65535`         | Range                                        |
| `--top-ports <n>`  | `--top-ports 100`   | Scan top *n* most‑common ports               |
| `-F`               |                     | Same as `--top-ports 100`                    |
| `-r`               |                     | Don’t randomize port order                   |
| `--port-ratio <x>` | `--port-ratio 0.01` | Scan ports probed on ≥ 1 % of Internet hosts |

---

## 七 – UDP PORT SCANNING

`-sU` is slow but unavoidable. Closed UDP ports usually respond with **no packet** or ICMP Type 3 Code 3.

### 7.1 Quick Top‑Port Scan

```bash
sudo nmap -sU --top-ports 50 --reason 192.168.56.102 -oN udp_top.txt
```

### 7.2 Single‑Port Verification

```bash
sudo nmap -sU -p 161 --script snmp-info 192.168.56.102 -oN snmp.txt
```

### 7.3 Helpful Flags for UDP

| Flag                      | Purpose                                  |
| ------------------------- | ---------------------------------------- |
| `--max-retries <n>`       | Reduce from default 10 to speed up       |
| `--host-timeout <time>`   | Bail on hosts that take too long         |
| `--min-rate / --max-rate` | Throttle packet rate                     |
| `--defeat-rst-ratelimit`  | Helps when ICMP unreachable rate‑limited |

*Blue‑Team Insight:* Spikes of ICMP Type 3 Code 3 mean someone is UDP scanning you.

---

## 八 – SCTP & IP‑PROTOCOL SCANS

Rare in labs but worth knowing for exams.

* **SCTP INIT Scan (`-sY`)** – Sends INIT chunk to detect listening SCTP services (telecom gear).
* **SCTP COOKIE‑ECHO (`-sZ`)** – Completes SCTP handshake.
* **IP Protocol Scan (`-sO`)** – Enumerates OSI Layer‑3 protocols (e.g., GRE 47, ESP 50). Useful when you’re hunting VPN/encap services.

```bash
sudo nmap -sO 192.168.56.102 -oN ip_proto.txt
```

---

## 九 – VERSION & OS DETECTION

| Flag                      | Function                                         |
| ------------------------- | ------------------------------------------------ |
| `-sV`                     | Probe service versions                           |
| `--version-intensity 0‑9` | Control aggressiveness                           |
| `--version-light`         | Intensity 2                                      |
| `--version-all`           | Intensity 9                                      |
| `-O`                      | OS fingerprinting                                |
| `--osscan-guess`          | Guess if match < 90 %                            |
| `--osscan-limit`          | Only test if at least one open & closed port     |
| `-A`                      | Shortcut: `-O -sV --traceroute --script=default` |

### 9.1 **LIVE EXERCISE:** Aggressive vs Surgical

```bash
sudo nmap -A 192.168.56.102 -oA full_aggr
sudo nmap -sV --version-intensity 3 -O 192.168.56.102 -oN surgical.txt
```

Compare runtime, packet count, and result accuracy.

---

## 拾 – TIMING & PERFORMANCE TUNING

Nmap ships six templates (`-T0`…`-T5`). Under the hood they adjust min/max parallelism, scan delay, and timeouts.

| Template           | Parallelism | RTT Multiplier | Idle Warn                        |
| ------------------ | ----------- | -------------- | -------------------------------- |
| `-T0` (Paranoid)   | 1           | 5.0            | IDS Evade                        |
| `-T1` (Sneaky)     | 1           | 3.0            | IDS Evade                        |
| `-T2` (Polite)     | 1‑10        | 2.0            | Low priority                     |
| `-T3` (Normal)     | Auto        | 1.0            | Default                          |
| `-T4` (Aggressive) | Higher      | 0.5            | Local LAN                        |
| `-T5` (Insane)     | Max         | 0.3            | Only on very fast, reliable nets |

### 10.1 Fine‑Grained Flags

| Flag                                    | Why You Care                     |
| --------------------------------------- | -------------------------------- |
| `--min-hostgroup / --max-hostgroup`     | Hosts scanned in parallel        |
| `--min-parallelism / --max-parallelism` | Concurrent probes per host       |
| `--min-rate / --max-rate`               | Packets per second               |
| `--scan-delay`                          | Wait between probes (e.g., `1s`) |
| `--max-retries`                         | Retransmissions before giving up |
| `--host-timeout`                        | Kill scan against slow hosts     |
| `--initial-rtt-timeout`                 | Set starting RTT                 |

### 10.2 **LIVE EXERCISE:** Throttle Like a Pro

```bash
sudo nmap -sS -p- --min-rate 100 --max-rate 200 --max-retries 2 --host-timeout 2m 192.168.56.102 -oN tune.txt
```

---

## 拾壱 – FIREWALL / IDS EVASION FLAGS

| Category      | Flag                                 | Effect                                      |
| ------------- | ------------------------------------ | ------------------------------------------- |
| Fragmentation | `-f` / `--mtu <n>`                   | Break packets into tiny pieces              |
| Decoys        | `-D decoy1,decoy2,ME` or `-D RND:10` | Mix spoofed sources                         |
| MAC Spoof     | `--spoof-mac 0`                      | Random vendor MAC                           |
| Bad Checksum  | `--badsum`                           | Send wrong checksum packets (IDS confusion) |
| Data Padding  | `--data-length <n>`                  | Extra payload bytes                         |
| IP Options    | `--ip-options <hex>`                 | Insert option headers                       |
| Source Port   | `-g <port>` or `--source-port`       | Pretend traffic from 53 (DNS)               |
| Interface     | `-e <iface>`                         | Explicit interface (for VPN tunnels)        |
| TTL           | `--ttl <n>`                          | Manipulate hop count                        |

### 11.1 **LIVE EXERCISE:** IDS Ghost Walk

```bash
sudo nmap -sS -p 445 --scan-delay 1s --data-length 60 --spoof-mac Cisco --source-port 53 192.168.56.102 -oN evade.txt
```

*Blue‑Team Insight:* Look for anomalies: packets *from* port 53 that are clearly not DNS.

---

## 拾弐 – NMAP SCRIPTING ENGINE (NSE)

NSE ≈ mini‑Metasploit inside Nmap.

### 12.1 Script Categories (excerpt)

| Category    | Purpose          | Example Script      |
| ----------- | ---------------- | ------------------- |
| `default`   | Safe, quick info | `http-title`        |
| `auth`      | Brute/login      | `ssh-auth-methods`  |
| `vuln`      | CVE checks       | `smb-vuln-ms17-010` |
| `discovery` | Enumerate        | `snmp-info`         |
| `intrusive` | May crash        | `rpcap-brute`       |
| `exploit`   | Payloads         | `http-shellshock`   |
| `malware`   | IOC checks       | `http-malware-host` |
| `safe`      | No extra traffic | `banner`            |

### 12.2 Running Scripts

```bash
sudo nmap -sV --script=vuln 192.168.56.102 -oN vuln.txt
sudo nmap -p 80 --script=http-headers,http-methods 192.168.56.102 -oN web_enum.txt
```

### 12.3 Script Arguments & Tracing

```bash
sudo nmap -p 445 --script smb-enum-shares --script-args smbuser=guest,smbpass="" 192.168.56.102 --script-trace -oN smb_enum.txt
```

---

## 拾参 – OUTPUT FORMATS & AUTOMATION

### 13.1 Core Flags

| Flag             | Format           | Usage                    |
| ---------------- | ---------------- | ------------------------ |
| `-oN <file>`     | Normal           | Readable text            |
| `-oG <file>`     | Grepable         | Easy `awk/sed` parsing   |
| `-oX <file>`     | XML              | Import to Splunk, Dradis |
| `-oJ <file>`     | JSON             | Feed dashboards          |
| `-oA <basename>` | All of the above | Adds `.nmap .gnmap .xml` |

### 13.2 HTML Report in Two Commands

```bash
sudo nmap -A -oX full.xml 192.168.56.102
xsltproc /usr/share/nmap/nmap.xsl full.xml > report.html
```

Open `report.html` in a browser – instant fancy report.

### 13.3 Diffing Scans

```bash
ndiff yesterday.xml today.xml > delta.txt
```

Only changed ports → instant change‑management report.

### 13.4 Cron Example

```bash
# Run at 02:30 every night
30 2 * * * /usr/bin/nmap -sS -p 22,80,443 --open -oG nightly.gnmap 192.168.56.102
```

---

## 拾肆 – BLUE‑TEAM ANALYSIS CHECKLIST

1. **Log sources to monitor:**

   * `Zeek conn.log` – look for high unique destination ports per source.
   * `/var/log/auth.log` – bursts of failed SSH = brute or version scan.
2. **Packet behaviors:**

   * Lone RSTs → FIN/NULL/Xmas.
   * ACKs without corresponding SYNs → `-sA` firewall mapping.
   * High‑entropy payload length 36 bytes → `--data-length` obfuscation.
3. **Detection rules (Snort / Suricata):**

   ```
   alert tcp any any -> $HOME_NET any (flags:F; msg:"TCP FIN scan";)
   alert icmp any any -> any any (itype:3; icode:3; msg:"UDP port scan";)
   ```

---

## 拾伍 – FREQUENTLY FORGOTTEN FLAGS

| Flag                  | Why It’s Cool                         |
| --------------------- | ------------------------------------- |
| `--traceroute`        | Map hop path *during* scan            |
| `--resolve-all`       | Query every DNS A record              |
| `--packet-trace`      | Dump every packet Nmap sends          |
| `--reason`            | Show why a port is marked open/closed |
| `--open`              | Output only open ports – tidy reports |
| `--stats-every 30s`   | Live ETA updates                      |
| `--append-output`     | Add results to existing file          |
| `--stylesheet <file>` | Custom XSLT for fancy HTML            |

---

## 拾陸 – CONTINUING EDUCATION

* **Book:** *Nmap Network Scanning* by Fyodor.
* **Talk:** DEF CON 32 – “Why Your IDS Hates My Port Scan.”
* **CTF:** Hack The Box *Nmap TryHarder* challenge.
* **Tools to Compare:** `masscan` (faster), `rustscan` (async front‑end), `zmap` (research‑grade breadth).
* **Certification:** If OSCP/OSCE is on your radar, re‑do every **LIVE EXERCISE** blind (no Wireshark) until outputs feel intuitive.

---

## 🚀 YOU’RE DONE – WHAT NOW?

1. **Repeat scans** with varying flags until you can predict the packet trace.
2. **Switch roles:** Instrument the target with Zeek/Snort and catch yourself.
3. **Write a one‑page after‑action report** for each scan: goal, command, findings, defensive mitigations.
4. **Never run these flags on production without permission.**

Happy scanning – and happier defending.

```
```
