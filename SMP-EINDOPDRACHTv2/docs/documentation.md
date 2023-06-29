# Analyzer documentation

## Imports

import json
from collections import Counter
import argparse

<!--De modules hierboven zijn essentieel voor de werking van de Network Analyzer.-->


class MostRequestsAnalyzer:
    def __init__(self, data):
        self.data = data

    def analyze(self):
        request_times = []

        for item in self.data:
            # Haal de aanvraagtijd op uit het item
            request_time = item["_source"]["layers"]["frame"]["frame.time"]
            # Rond de tijd af naar het dichtstbijzijnde gehele getal
            rounded_time = request_time.split('.')[0]
            request_times.append(rounded_time)

        # Tel het aantal voorkomens van elke afgeronde tijd
        request_counts = Counter(request_times)
        # Sorteer de tijden op basis van hun frequentie, van hoog naar laag
        sorted_request_counts = request_counts.most_common(10)

        result = ["The 10 most requested times:"]
        for time, count in sorted_request_counts:
            # Voeg de tijd en het aantal toe aan het resultaat
            result.append(f"Time: {time}, Count: {count}")

        return result



