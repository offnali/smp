# Network Analyzer Deelvragen

## Deelvraag 1

De functie most_requests(data), analyseert de dataset om de top 10 meest voorkomende tijden per seconde te bepalen waarop verzoeken worden gedaan van zowel het universiteitsnetwerk als van buitenaf. Dit geeft inzicht in mogelijke aanvallen die op specifieke tijden plaatsvinden en of er beveiligingsmaatregelen moeten worden genomen. Het kan ook worden gebruikt om te bepalen wanneer er sprake is van piek- of daluren en of er mogelijk extra capaciteit nodig is voor de webserver.

Het werkt als volgt:

- Het verzamelt de aanvraagtijden uit elk item in de dataset.

- Elke aanvraagtijd wordt afgerond naar het dichtstbijzijnde gehele getal.

- Vervolgens worden de aantallen voorkomens van elke afgeronde tijd geteld.

- De tijden worden gesorteerd op basis van hun frequentie, van hoog naar laag.

- Het resultaat is een lijst met de top 10 meest voorkomende tijden, samen met het aantal verzoeken op die tijden.

- Het resultaat wordt geretourneerd als een lijst met strings in het volgende formaat:

-    "Time: [tijd], Count: [aantal verzoeken]"

## Deelvraag 2

De functie amount_of_hosts(data, university_network_ip), analyseert de dataset om het aantal verschillende hosts te bepalen dat communiceert met de webserver, zowel vanuit het universiteitsnetwerk als van buitenaf. Dit geeft inzicht in het aantal potentiële aanvallers en kan worden gebruikt om te bepalen of er beveiligingsmaatregelen nodig zijn. Het kan ook aangeven of er bepaalde hosts zijn die frequent communiceren met de webserver en mogelijk aanvallers zijn.

Het werkt als volgt:

- Het houdt twee sets bij: university_hosts voor de hosts vanuit het universiteitsnetwerk en external_hosts voor externe hosts.

- Voor elk item in de dataset worden het bron-IP en het bestemmings-IP opgehaald.

- Als het universitaire netwerk-IP aanwezig is in het bron-IP, wordt het bron-IP toegevoegd aan de set university_hosts. Anders wordt het bron-IP toegevoegd aan de set external_hosts.

- Op dezelfde manier wordt het bestemmings-IP gecontroleerd en toegevoegd aan de juiste set.

- Aan het einde wordt het aantal unieke universitaire hosts en externe hosts geteld door de lengte van respectievelijk university_hosts en external_hosts te bepalen.

- Het resultaat wordt afgedrukt met behulp van print()-statements in het volgende formaat:

-    "Number of different hosts communicating with the webserver:"
-    "From the university network: [aantal universitaire hosts]"
-    "From external sources: [aantal externe hosts]"

## Deelvraag 3

De functie synflood_scan(data), identificeert de aanwezigheid van een TCP SYN flood-aanval door het analyseren van het netwerkverkeer. Een TCP SYN flood-aanval treedt op wanneer een aanvaller een groot aantal TCP SYN-pakketten verstuurt om de bronnen van een server te overbelasten en deze ongevoelig te maken voor legitieme verzoeken.

Het werkt als volgt:

- Het houdt verschillende lijsten bij, namelijk syn_packets voor SYN-pakketten, source_ips voor bron-IP's en incomplete_handshakes voor incomplete handshakes.

- Voor elk item in de dataset wordt gecontroleerd of het TCP-protocol aanwezig is.

- Het vlaggenveld (flags) en het bron-IP (source_ip) worden opgehaald uit de betreffende lagen in het item.

- Als het SYN-vlaggenbit is ingesteld (0x02), wordt het item toegevoegd aan de lijst syn_packets en het bron-IP aan de lijst source_ips.

- Als het SYN-ACK-vlaggenbit niet is ingesteld (0x10), wordt het bron-IP toegevoegd aan de lijst incomplete_handshakes.

- Vervolgens worden de voorkomens van elk bron-IP en incomplete handshake geteld met behulp van de Counter-functie.

- Het algoritme identificeert potentieel kwaadwillende IP-adressen door te controleren welke bron-IP's meer voorkomen dan een vooraf gedefinieerde drempelwaarde (threshold).
- Het resultaat wordt afgedrukt met behulp van print()-statements in het volgende formaat:

-    "Potentially malicious source IP addresses with a significant increase in SYN packets:"
-    "IP: [bron-IP] | Total SYN Requests: [aantal SYN-verzoeken] | Total Incomplete SYN Requests: [aantal incomplete handshakes]"

-    Er worden ook de top 5 van incomplete handshakes afgedrukt met het aantal keren dat ze voorkomen.