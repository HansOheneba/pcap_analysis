from scapy.all import *
from collections import defaultdict
import time


def traffic_analysis(pcap_file):
    packets = rdpcap(pcap_file)
    packet_sizes = []
    packet_times = defaultdict(int)
    total_packets = len(packets)
    start_time = packets[0].time
    end_time = packets[-1].time
    duration = end_time - start_time

    # Analyze packet sizes and timestamps
    for packet in packets:
        packet_sizes.append(len(packet))
        packet_times[int(packet.time)] += 1

    # Identify large/small packets
    avg_packet_size = sum(packet_sizes) / total_packets
    large_packets = [p for p in packet_sizes if p > 2 * avg_packet_size]
    small_packets = [p for p in packet_sizes if p < avg_packet_size / 2]

    # Identify high packet rates (potential DoS)
    packet_rate = total_packets / duration
    high_rate_threshold = 1000  # packets per second
    if packet_rate > high_rate_threshold:
        print(
            f"High packet rate detected: {packet_rate:.2f} packets/sec (Potential DoS)"
        )

    print(f"Average packet size: {avg_packet_size:.2f} bytes")
    print(f"Large packets (> {2 * avg_packet_size:.2f} bytes): {len(large_packets)}")
    print(f"Small packets (< {avg_packet_size / 2:.2f} bytes): {len(small_packets)}")


# Run the analysis
traffic_analysis("example.pcap")
