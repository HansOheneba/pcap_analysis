from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import TCP


def http_tls_monitoring(pcap_file):
    packets = rdpcap(pcap_file)
    suspicious_agents = []
    large_exfiltrations = []
    outdated_tls = []

    for packet in packets:
        if TCP in packet:
            # Detect suspicious user agents
            if HTTPRequest in packet:
                user_agent = (
                    packet[HTTPRequest]
                    .fields.get("User-Agent", "")
                    .decode("utf-8", errors="ignore")
                )
                if "curl" in user_agent.lower() or "wget" in user_agent.lower():
                    suspicious_agents.append(user_agent)

            # Detect large exfiltrations (HTTP responses)
            if HTTPResponse in packet:
                content_length = int(
                    packet[HTTPResponse].fields.get("Content-Length", 0)
                )
                if content_length > 1000000:  # 1 MB threshold
                    large_exfiltrations.append(content_length)

            # Detect outdated SSL/TLS versions
            if packet[TCP].dport == 443 or packet[TCP].sport == 443:
                if packet.haslayer(Raw):
                    payload = packet[Raw].load
                    if b"\x03\x01" in payload:  # TLS 1.0
                        outdated_tls.append("TLS 1.0")
                    elif b"\x03\x02" in payload:  # TLS 1.1
                        outdated_tls.append("TLS 1.1")

    # Print results
    print(f"Suspicious user agents: {len(suspicious_agents)}")
    print(f"Large exfiltrations (> 1 MB): {len(large_exfiltrations)}")
    print(f"Outdated TLS versions detected: {len(outdated_tls)}")


# Run the analysis
http_tls_monitoring("test.pcapng")
