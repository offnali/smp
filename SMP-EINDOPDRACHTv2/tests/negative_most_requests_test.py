from smpnc.networkanalyzer import MostRequestsAnalyzer

def test_most_requests_empty_data():
    data = []
    expected_result = ["The 10 most requested times:"]

    analyzer = MostRequestsAnalyzer(data)
    result = analyzer.analyze()

    assert result == expected_result
