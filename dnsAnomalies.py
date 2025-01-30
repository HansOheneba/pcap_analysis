from scapy.all import *
from scapy.layers.dns import DNSQR, DNSRR


def dns_anomalies(pcap_file):
    packets = rdpcap(pcap_file)
    suspicious_queries = []
    long_queries = []
    internal_recon = []

    for packet in packets:
        if DNSQR in packet:
            query = packet[DNSQR].qname.decode("utf-8", errors="ignore")

            # Detect C2 traffic (e.g., random subdomains)
            if len(query.split(".")) > 4:  # Too many subdomains
                suspicious_queries.append(query)

            # Detect DNS tunneling (long queries)
            if len(query) > 50:  # Arbitrary threshold
                long_queries.append(query)

            # Detect internal reconnaissance (e.g., internal domain queries)
            if "internal" in query or "local" in query:
                internal_recon.append(query)

    # Print results
    print(f"Suspicious DNS queries (potential C2): {len(suspicious_queries)}")
    print(f"Long DNS queries (potential tunneling): {len(long_queries)}")
    print(f"Internal reconnaissance queries: {len(internal_recon)}")


# Run the analysis
dns_anomalies("example.pcap")
