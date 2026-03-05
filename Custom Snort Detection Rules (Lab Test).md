# 🧾 Custom Snort Detection Rules

This lab includes several **custom Snort IDS rules** designed to detect common reconnaissance and suspicious network behavior.

These rules are stored in:

```
/usr/local/etc/rules/local.rules
```

---

# 1️⃣ ICMP Echo Flood Detection

Detects repeated ICMP echo requests that may indicate a **ping flood attack**.

```snort
alert icmp any any -> $HOME_NET any \
(msg:"Possible ICMP echo flood requests detected"; itype:8; \
detection_filter:track by_src, count 10, seconds 5; sid:10000001; rev:1;)
```

### What it detects

- Multiple ping requests from a single host
- Possible ICMP flooding attempts

---

# 2️⃣ Oversized ICMP Packet Detection

Detects abnormally large ICMP packets that may indicate **malformed traffic or attack traffic**.

```snort
alert icmp any any -> $HOME_NET any \
(msg:"Possible oversized ICMP Echo Request flood"; itype:8; dsize:>1000; \
detection_filter:track by_src, count 10, seconds 5; sid:10000002; rev:2;)
```

### What it detects

- Oversized ICMP packets
- Potential network flooding attempts

---

# 3️⃣ TCP SYN Port Scan Detection

Detects TCP SYN packets commonly used during **port scanning activities**.

```snort
alert tcp any any -> $HOME_NET any \
(msg:"Possible TCP SYN port scan detected"; flags:S; flow:to_server; \
detection_filter:track by_src, count 20, seconds 3; sid:10000003; rev:1;)
```

### What it detects

- SYN scan attempts
- Reconnaissance activity
- Port scanning tools such as **Nmap**

Example attack simulation:

```bash
nmap -sS <snort_vm_ip>
```

---

# 4️⃣ Known Malicious IP Detection (Inbound)

Detects inbound connections from known malicious IP addresses.

```snort
alert ip <Input MALICIOUS IP> any -> $HOME_NET any \
(msg:"Inbound connection from known malicious IP"; sid:10000004; rev:1;)
```

### Use case

- Threat intelligence IP blocklists
- Known attacker infrastructure

---

# 5️⃣ Known Malicious IP Detection (Outbound)

Detects connections from internal hosts to known malicious infrastructure.

```snort
alert ip $HOME_NET any -> <Input MALICIOUS IP> any \
(msg:"Outbound connection to known malicious IP"; sid:10000005; rev:1;)
```

### Use case

- Detect compromised machines
- Identify malware command-and-control traffic

---

# 6️⃣ Malicious DNS Query Detection

Detects DNS queries for a suspicious or malicious domain.

```snort
alert udp $HOME_NET any -> any 53 \
(msg:"Outbound DNS query to known malicious domain"; content:"badexample.com"; sid:10000006; rev:1;)
```

### What it detects

- DNS queries to suspicious domains
- Potential malware communication

---

# 7️⃣ Malicious DNS Response Detection

Detects inbound DNS responses associated with a suspicious domain.

```snort
alert udp any 53 -> $HOME_NET any \
(msg:"Inbound DNS response for known malicious domain"; content:"badexample.com"; sid:10000007; rev:1;)
```

### What it detects

- DNS responses from malicious domains
- Domain resolution attempts by infected systems

---



This rule set was created to demonstrate **custom IDS signature development and testing** in a controlled lab environment.
