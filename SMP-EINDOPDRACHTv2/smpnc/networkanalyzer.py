import json
from collections import Counter
import argparse

class MostRequestsAnalyzer:
    def __init__(self, data):
        self.data = data

    def analyze(self):
        request_times = []

        for item in self.data:
            # Extract the request time from the item
            request_time = item["_source"]["layers"]["frame"]["frame.time"]
            # Round the time to the nearest integer
            rounded_time = request_time.split('.')[0]
            request_times.append(rounded_time)

        # Count the occurrences of each rounded time
        request_counts = Counter(request_times)
        # Sort the times based on their frequency, from high to low
        sorted_request_counts = request_counts.most_common(10)

        result = ["The 10 most requested times:"]
        for time, count in sorted_request_counts:
            # Add the time and count to the result
            result.append(f"Time: {time}, Count: {count}")

        return result


class AmountOfHostsAnalyzer:
    def __init__(self, data, university_network_ip):
        self.data = data
        self.university_network_ip = university_network_ip

    def analyze(self):
        university_hosts = set()
        external_hosts = set()

        for item in self.data:
            # Extract the source and destination IP from the item
            ip_src = item["_source"]["layers"]["ip"]["ip.src"]
            ip_dst = item["_source"]["layers"]["ip"]["ip.dst"]

            if self.university_network_ip in ip_src:
                # Add the source IP to the set of university hosts
                university_hosts.add(ip_src)
            else:
                # Add the source IP to the set of external hosts
                external_hosts.add(ip_src)

            if self.university_network_ip in ip_dst:
                # Add the destination IP to the set of university hosts
                university_hosts.add(ip_dst)
            else:
                # Add the destination IP to the set of external hosts
                external_hosts.add(ip_dst)

        # Count the number of unique university hosts and external hosts
        university_hosts_count = len(university_hosts)
        external_hosts_count = len(external_hosts)

        print("Number of different hosts communicating with the webserver:")
        print(f"From the university network: {university_hosts_count}")
        print(f"From external sources: {external_hosts_count}")


class SynfloodScanAnalyzer:
    def __init__(self, data):
        self.data = data

    def analyze(self):
        syn_packets = []
        source_ips = []
        incomplete_handshakes = []

        for item in self.data:
            if "tcp" in item["_source"]["layers"]:
                flags = item["_source"]["layers"]["tcp"]["tcp.flags"]
                source_ip = item["_source"]["layers"]["ip"]["ip.src"]

                if int(flags, 16) & 0x02:
                    # Add the item to the list of SYN packets
                    syn_packets.append(item)
                    # Add the source IP to the list of source IPs
                    source_ips.append(source_ip)

                if not (int(flags, 16) & 0x10):
                    # Add the source IP to the list of incomplete handshakes
                    incomplete_handshakes.append(source_ip)

        # Count the occurrences of each source IP and incomplete handshake
        ip_counts = Counter(source_ips)
        incomplete_counts = Counter(incomplete_handshakes)

        potentially_malicious_ips = []
        threshold = 100

        for ip, count in ip_counts.items():
            if count > threshold:
                # Add the source IP to the list of potentially malicious IPs
                potentially_malicious_ips.append(ip)

        print("Potentially malicious source IP addresses with a significant increase in SYN packets:")
        for ip in potentially_malicious_ips:
            print(f"IP: {ip} | Total SYN Requests: {ip_counts[ip]} | Total Incomplete SYN Requests: {incomplete_counts[ip]}")
        print()
        for ip, count in incomplete_counts.most_common(5):
            print(f"IP: {ip} | Count: {count}")


def main(dataset, options, university_network_ip):
    with open(dataset, "r") as f:
        data = json.load(f)

    if "most_requests" in options:
        print()
        print("**Most Requests Scan**")
        analyzer = MostRequestsAnalyzer(data)
        result = analyzer.analyze()
        print('\n'.join(result))
        print()

    if "amount_of_hosts" in options:
        print()
        print("**Amount of Hosts Scan**")
        analyzer = AmountOfHostsAnalyzer(data, university_network_ip)
        analyzer.analyze()
        print()

    if "synflood_scan" in options:
        print()
        print("**Synflood Scan**")
        analyzer = SynfloodScanAnalyzer(data)
        analyzer.analyze()
        print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyzing network dataset")
    parser.add_argument("-ds", "--dataset", type=str, required=True, help="Path to the dataset file")
    parser.add_argument("-mr", "--most-requests", action="store_true", help="Perform analysis of most requests")
    parser.add_argument("-aoh", "--amount-of-hosts", action="store_true", help="Perform analysis of amount of hosts")
    parser.add_argument("-uni", "--university-network-ip", type=str, help="University network IP address")
    parser.add_argument("-ss", "--synflood-scan", action="store_true", help="Perform analysis of SYN flood scan")
    args = parser.parse_args()

    options = []

    if args.most_requests:
        options.append("most_requests")
    if args.amount_of_hosts:
        options.append("amount_of_hosts")
    if args.synflood_scan:
        options.append("synflood_scan")

    main(args.dataset, options, args.university_network_ip)
