# Analyzer documentation

## Imports

```py
import json
from collections import Counter
import argparse
```

- De modules hierboven zijn essentieel voor de werking van de Network Analyzer.


## Functie Most Requests

- De functie Most requests print de top 10 meeste requests die worden gedaan op een bepaalde tijd afgerond op secondes.

```py
class MostRequestsAnalyzer:
    def __init__(self, data):
        self.data = data
```
- Deze regels definiëren een klasse genaamd MostRequestsAnalyzer die verantwoordelijk is voor het analyseren van de meest aangevraagde tijden.
- De __init__-methode wordt gebruikt als een constructor voor de klasse en initialiseert een instantie van de klasse met de gegeven data.
```py
    def analyze(self):
        request_times = []

        for item in self.data:
            request_time = item["_source"]["layers"]["frame"]["frame.time"]
            rounded_time = request_time.split('.')[0]
            request_times.append(rounded_time)
```
- De analyze-methode analyseert de gegevens door een lege lijst request_times aan te maken om de aangevraagde tijden op te slaan. Vervolgens wordt er door elk item in de gegevens gelust en wordt de aanvraagtijd opgehaald uit het item met behulp van de juiste key. De aanvraagtijd wordt afgerond naar het dichtstbijzijnde gehele getal door het te splitsen op het decimaalteken en alleen het gehele deel te behouden. Ten slotte wordt de afgeronde tijd toegevoegd aan de request_times-lijst.
```py
        request_counts = Counter(request_times)
        sorted_request_counts = request_counts.most_common(10)
```
- In de volgende stap wordt het aantal voorkomens van elke afgeronde tijd geteld met behulp van de Counter-functie. Dit creëert een object dat de tellingen bijhoudt. Vervolgens worden de resultaten van het Counter-object gesorteerd op basis van hun frequentie, waarbij de meest voorkomende tijden eerst worden geplaatst. Om de top 10 meest voorkomende tijden op te halen, wordt de methode most_common(10) gebruikt.
```py
        result = ["The 10 most requested times:"]
        for time, count in sorted_request_counts:
            result.append(f"Time: {time}, Count: {count}")

        return result
```
- Vervolgens wordt een lijst gemaakt met de eerste regel van het resultaat, die de titel bevat. Daarna wordt er een lus uitgevoerd door de gesorteerde resultaten van de meest voorkomende tijden. Voor elke tijd en het bijbehorende aantal wordt een string gemaakt en toegevoegd aan de result-lijst. Uiteindelijk wordt het volledige resultaat, inclusief de titelregel en de regels met tijd en aantal, geretourneerd als output van de methode. Het wordt in een lijst gezet zodat ik de tests kon maken, want ik kon niet achterhalen hoe ik de tests kon maken als ik gebruik maakte van print in plaats van return. De return statements worden ook gebruikt bij de andere 2 functies.


## Functie Amount of Hosts

- De functie Amount of Hosts print hoeveel verbindingen er worden gemaakt van binnen de universiteitsnetwerk en van buiten de universiteitsnetwerk. Dit vereist echter wel de verplicte argument bijvoorbeeld `-uni 192.169.0.1`. zonder de universiteit ip te geven werkt de functie niet omdat deze van belang is voor de functionaliteit.

```py
class AmountOfHostsAnalyzer:
    def __init__(self, data, university_network_ip):
        self.data = data
        self.university_network_ip = university_network_ip
```
- Deze regels definiëren een klasse genaamd AmountOfHostsAnalyzer die verantwoordelijk is voor het analyseren van het aantal hosts.
- De __init__-methode wordt gebruikt als een constructor voor de klasse en initialiseert een instantie van de klasse met de gegeven data en university_network_ip.
```py
    def analyze(self):
        university_hosts = set()
        external_hosts = set()

        for item in self.data:
            ip_src = item["_source"]["layers"]["ip"]["ip.src"]
            ip_dst = item["_source"]["layers"]["ip"]["ip.dst"]

            if self.university_network_ip in ip_src:
                university_hosts.add(ip_src)
            else:
                external_hosts.add(ip_src)

            if self.university_network_ip in ip_dst:
                university_hosts.add(ip_dst)
            else:
                external_hosts.add(ip_dst)
```
- Vervolgens worden het aantal unieke universitaire hosts en externe hosts geteld door de lengte van de respectievelijke sets te nemen. Het resultaat wordt opgeslagen in een lege lijst genaamd "result". Deze lijst bevat een titelregel en regels met het aantal hosts per type.

```py

        university_hosts_count = len(university_hosts)
        external_hosts_count = len(external_hosts)

        result = []
        result.append("Number of different hosts communicating with the webserver:")
        result.append(f"From the university network: {university_hosts_count}")
        result.append(f"From external sources: {external_hosts_count}")

        return result
```
- Het uiteindelijke resultaat wordt geretourneerd als een lijst, waarin de informatie over het aantal verschillende hosts die communiceren met de webserver wordt weergegeven. Het resultaat bevat het aantal hosts vanuit het universitaire netwerk en het aantal hosts van externe bronnen.


## Functie Synflood Scan

- De functie Synflood Scan scant print de hosts die verdacht worden op een synflood attack. Eerst wordt de ip geprint die de meeste syn requests verzoekt ongeacht of de 3-way handshake afgerond wordt. Vervolgens wordt de top 5 ip's geprint met de aantal niet afgemaakte tcp sessie.

```py
class SynfloodScanAnalyzer:
    def __init__(self, data):
        self.data = data
```
- Deze regels definiëren een klasse genaamd SynfloodScanAnalyzer die verantwoordelijk is voor het analyseren van synflood-scans.
- De __init__-methode wordt gebruikt als een constructor voor de klasse en initialiseert een instantie van de klasse met de gegeven data.
```py
    def analyze(self):
        syn_packets = []
        source_ips = []
        incomplete_handshakes = []

        for item in self.data:
            if "tcp" in item["_source"]["layers"]:
                flags = item["_source"]["layers"]["tcp"]["tcp.flags"]
                source_ip = item["_source"]["layers"]["ip"]["ip.src"]

                if int(flags, 16) & 0x02:
                    syn_packets.append(item)
                    source_ips.append(source_ip)

                if not (int(flags, 16) & 0x10):
                    incomplete_handshakes.append(source_ip)
```
- De analyze-methode analyseert de gegevens door door elk item in de data te loopen, controleert of het item een TCP-laag heeft, haalt de vlaggen en het bron-IP op, en voegt het item toe aan de lijst syn_packets en het bron-IP aan de lijst source_ips als de SYN-vlag aanwezig is (0x02), en voegt het bron-IP toe aan de lijst incomplete_handshakes als de ACK-vlag niet aanwezig is (0x10).
```py
        ip_counts = Counter(source_ips)
        incomplete_counts = Counter(incomplete_handshakes)

        potentially_malicious_ips = []
        threshold = 100

        for ip, count in ip_counts.items():
            if count > threshold:
                potentially_malicious_ips.append(ip)
```
- Met behulp van de Counter-functie worden de aantallen van elk bron-IP en onvolledige handshake geteld. Een lijst potentially_malicious_ips wordt aangemaakt om potentieel kwaadwillende IP-adressen op te slaan. Een drempelwaarde van 100 wordt ingesteld. Vervolgens wordt er gelust door de bron-IP's en hun bijbehorende tellingen in het ip_counts-object, waarbij IP-adressen die vaker voorkomen dan de drempelwaarde worden toegevoegd aan de lijst potentially_malicious_ips.
```py
        result = []
        result.append("Potentially malicious source IP addresses with a significant increase in SYN packets:")
        for ip in potentially_malicious_ips:
            result.append(f"IP: {ip} | Total SYN Requests: {ip_counts[ip]} | Total Incomplete SYN Requests: {incomplete_counts[ip]}")
        result.append("")

        result.append("Potentially malicious source IP addresses with incomplete SYN packets:")
        for ip, count in incomplete_counts.most_common(5):
            result.append(f"IP: {ip} | Count: {count}")

        return result
```
- Een lege lijst genaamd "result" wordt gemaakt om het resultaat van de analyse op te slaan. Vervolgens worden de regels voor potentieel kwaadwillende IP-adressen met een significante toename van SYN-pakketten aan "result" toegevoegd. Voor elk potentieel kwaadwillend IP-adres worden het IP-adres, het totale aantal SYN-aanvragen en het totale aantal onvolledige SYN-aanvragen toegevoegd aan "result". Daarna wordt een lege regel aan "result" toegevoegd. De regels voor potentieel kwaadwillende IP-adressen met onvolledige SYN-pakketten worden ook aan "result" toegevoegd. Voor de top 5 meest voorkomende onvolledige SYN-pakketten wordt het IP-adres en het aantal toegevoegd aan "result". Uiteindelijk wordt "result" als het resultaat van de analyse geretourneerd.    


## Functie Main

```py
def main(dataset, options, university_network_ip):
    with open(dataset, "r") as f:
        data = json.load(f)
```
- De main-functie is de belangrijkste functie in het script en wordt gebruikt om het programma te starten. Het accepteert drie parameters: dataset, options en university_network_ip. De dataset parameter verwijst naar het pad van het datasetbestand dat moet worden geanalyseerd. Het bestand wordt geopend en de inhoud wordt geladen met behulp van json.load, en vervolgens toegewezen aan de variabele data.
```py
    if "most_requests" in options:
        print()
        print("**Most Requests Scan**")
        analyzer = MostRequestsAnalyzer(data)
        result = analyzer.analyze()
        print('\n'.join(result))
        print()
```
- Wanneer "most_requests" in de lijst met opties voorkomt, wordt een analyse uitgevoerd op basis van de meest aangevraagde items. Dit omvat het genereren van een titel, het maken van een instantie van de MostRequestsAnalyzer-klasse met de gegevens, het aanroepen van de analyze-methode van die instantie om het resultaat te verkrijgen, het afdrukken van het resultaat door de tijd- en aantalinformatie te combineren met behulp van '\n'.join(result), en het afdrukken van een lege regel ter scheiding. Het zelfde geldt voor de volgende 2 functies.
```py
    if "amount_of_hosts" in options:
        print()
        print("**Amount of Hosts Scan**")
        analyzer = AmountOfHostsAnalyzer(data, university_network_ip)
        result = analyzer.analyze()
        print('\n'.join(result))
        print()

    if "synflood_scan" in options:
        print()
        print("**Synflood Scan**")
        analyzer = SynfloodScanAnalyzer(data)
        result = analyzer.analyze()
        print('\n'.join(result))
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

```
- Deze sectie van de code wordt alleen uitgevoerd wanneer het script direct wordt gestart. Het script maakt een argumentparser aan om command line argumenten te verwerken. Verschillende argumenten worden toegevoegd, zoals dataset, most-requests, amount-of-hosts, university-network-ip en synflood-scan. Deze argumenten specificeren de vereiste invoer voor het script. De argumenten worden geparseerd en opgeslagen in de args-variabele. Een lege lijst genaamd options wordt aangemaakt. Op basis van de argumentwaarden worden relevante strings aan de options-lijst toegevoegd. Vervolgens wordt de main-functie opgeroepen met de dataset, opties en universitaire netwerk-IP als argumenten om de gewenste analyses uit te voeren.