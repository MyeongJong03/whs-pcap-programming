# PCAP TCP Sniffer

WhiteHat School Network Security PCAP Programming assignment using C and libpcap.

## Build

```sh
make
```

Manual compile command:

```sh
gcc -Wall -Wextra -O2 -o pcap_sniffer pcap_sniffer.c -lpcap
```

## Run

Choose the first non-loopback interface automatically:

```sh
sudo ./pcap_sniffer
```

Or provide an interface name:

```sh
sudo ./pcap_sniffer eth0
```

## Behavior

- Captures packets through the PCAP API.
- Uses a BPF filter of `tcp`.
- Processes TCP packets only.
- Ignores UDP, ICMP, ARP, and other non-TCP packets.
- Prints Ethernet source/destination MAC addresses.
- Prints IP source/destination addresses.
- Prints TCP source/destination ports.
- Prints the TCP application payload when present.
- Uses the IP header length and TCP header length from the packet instead of assuming fixed 20-byte headers.
- Prints non-printable payload bytes as `.` while preserving printable ASCII, CR, LF, and TAB.

HTTPS payloads are encrypted, so HTTPS traffic usually will not show readable HTTP text.
