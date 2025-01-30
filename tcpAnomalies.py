from scapy.all import *
from collections import defaultdict


def tcp_anomalies(pcap_file):
    packets = rdpcap(pcap_file)
    syn_count = defaultdict(int)
    null_scan_count = 0
    xmas_scan_count = 0
    retransmissions = defaultdict(int)
    duplicate_acks = defaultdict(int)

    for packet in packets:
        if TCP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = packet[TCP].flags

            # SYN flood detection
            if flags == "S":
                syn_count[(src, dst, sport, dport)] += 1

            # Null/Xmas scan detection
            if flags == 0:
                null_scan_count += 1
            elif flags & 0x29 == 0x29:  # FIN, PSH, URG flags set
                xmas_scan_count += 1

            # Retransmission detection
            seq = packet[TCP].seq
            if (src, dst, sport, dport, seq) in retransmissions:
                retransmissions[(src, dst, sport, dport, seq)] += 1
            else:
                retransmissions[(src, dst, sport, dport, seq)] = 1

            # Duplicate ACK detection
            ack = packet[TCP].ack
            if flags == "A":
                if (src, dst, sport, dport, ack) in duplicate_acks:
                    duplicate_acks[(src, dst, sport, dport, ack)] += 1
                else:
                    duplicate_acks[(src, dst, sport, dport, ack)] = 1

    # Print results
    print(f"SYN flood suspects: {len([k for k, v in syn_count.items() if v > 10])}")
    print(f"Null scans detected: {null_scan_count}")
    print(f"Xmas scans detected: {xmas_scan_count}")
    print(
        f"Retransmissions detected: {len([k for k, v in retransmissions.items() if v > 1])}"
    )
    print(
        f"Duplicate ACKs detected: {len([k for k, v in duplicate_acks.items() if v > 1])}"
    )


# Run the analysis
tcp_anomalies("example.pcap")
