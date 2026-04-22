# ARP & DNS Spoofing Tool — Group 28 (2IC80)

A Python-based network attack tool built for the 2IC80 course. It performs ARP spoofing and DNS poisoning on a local network using [Scapy](https://scapy.net/).

> **For educational and authorized testing purposes only.** Running these attacks on networks you do not own or have explicit permission to test is illegal.

---

## What it does

### ARP Spoofing
ARP (Address Resolution Protocol) maps IP addresses to MAC addresses on a local network. This attack poisons the ARP cache of a target host by sending crafted ARP reply packets, making the target believe the attacker's machine is a different host (e.g. the gateway). This enables a man-in-the-middle position, allowing traffic interception.

The tool:
1. Scans the local network for active hosts (IP + MAC pairs)
2. Asks you to pick a **target** (victim) and a host to **impersonate**
3. Sends spoofed ARP packets to both the target and the impersonated host
4. Restores the real ARP entries after 512 seconds

### DNS Spoofing
DNS spoofing redirects DNS queries from a victim to a controlled IP address. This attack builds on ARP spoofing — once the attacker is in the middle, DNS responses to the victim are intercepted and replaced with fake records.

The tool:
1. Performs an ARP spoof to position itself between the victim and the gateway
2. Sniffs UDP traffic on port 53 (DNS)
3. For matching domain names (e.g. `google.com`, `facebook.com`), it crafts and sends a forged DNS response pointing to a controlled IP (`10.0.2.6` by default)

---

## Requirements

- Python 3
- [Scapy](https://scapy.net/) — `pip install scapy`
- [netifaces](https://pypi.org/project/netifaces/) — `pip install netifaces`
- [netaddr](https://pypi.org/project/netaddr/) — `pip install netaddr`
- Root / administrator privileges (required for raw socket access)
- Linux (the tool hardcodes interface names like `enp0s3` / `enp0s9`)

---

## Usage

```bash
sudo python3 whole_tool.py
```

1. Select attack type: `1` for ARP spoofing, `2` for DNS spoofing
2. Select the network interface to use
3. The tool scans and lists active hosts on the subnet
4. For ARP: select the target IP and the IP to impersonate
5. For DNS: select the target IP — spoofing starts immediately

---

## Configuration

The DNS spoof target records are hardcoded near the top of `whole_tool.py`:

```python
dns_hosts = {
    b"www.google.com": "10.0.2.6",
    b"google.com":     "10.0.2.6",
    b"facebook.com":   "10.0.2.6"
}
```

Change the IP values to redirect victims to a different host. The network interface names (`enp0s3`, `enp0s9`) may also need updating to match your system.

