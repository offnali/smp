import json
from collections import Counter
import argparse

def most_requests(data):
    request_times = []

    for item in data:
        request_time = item["_source"]["layers"]["frame"]["frame.time"]
        rounded_time = request_time.split('.')[0]
        request_times.append(rounded_time)

    request_counts = Counter(request_times)
    sorted_request_counts = request_counts.most_common(10)

    result = ["The 10 most requested times:"]
    for time, count in sorted_request_counts:
        result.append(f"Time: {time}, Count: {count}")

    return result

def amount_of_hosts(data, university_network_ip):
    university_network_ip = university_network_ip

    university_hosts = set()
    external_hosts = set()

    for item in data:
        ip_src = item["_source"]["layers"]["ip"]["ip.src"]
        ip_dst = item["_source"]["layers"]["ip"]["ip.dst"]

        if university_network_ip in ip_src:
            university_hosts.add(ip_src)
        else:
            external_hosts.add(ip_src)

        if university_network_ip in ip_dst:
            university_hosts.add(ip_dst)
        else:
            external_hosts.add(ip_dst)

    university_hosts_count = len(university_hosts)
    external_hosts_count = len(external_hosts)

    print("Number of different hosts communicating with the webserver:")
    print(f"From the university network: {university_hosts_count}")
    print(f"From external sources: {external_hosts_count}")

def synflood_scan(data):
    syn_packets = []
    source_ips = []
    incomplete_handshakes = []

    for item in data:
        if "tcp" in item["_source"]["layers"]:
            flags = item["_source"]["layers"]["tcp"]["tcp.flags"]
            source_ip = item["_source"]["layers"]["ip"]["ip.src"]

            if int(flags, 16) & 0x02:
                syn_packets.append(item)
                source_ips.append(source_ip)

            if not (int(flags, 16) & 0x10):
                incomplete_handshakes.append(source_ip)

    ip_counts = Counter(source_ips)
    incomplete_counts = Counter(incomplete_handshakes)

    potentially_malicious_ips = []
    threshold = 100

    for ip, count in ip_counts.items():
        if count > threshold:
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
        result = most_requests(data)
        print('\n'.join(result))
        print()


    if "amount_of_hosts" in options:
        print()
        print("**Amount of Hosts Scan**")
        amount_of_hosts(data, university_network_ip)
        print()


    if "synflood_scan" in options:
        print()
        print("**Synflood Scan**")
        synflood_scan(data)
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