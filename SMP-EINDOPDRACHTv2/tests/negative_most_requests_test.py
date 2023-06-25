from smpnc.networkanalyzer import most_requests

def test_most_requests():
    data = [
        {"_source": {"layers": {"frame": {"frame.time": "Jan  5, 1970 03:23:09.568563000 W. Europe Standard Time"}}}},
        {"_source": {"layers": {"frame": {"frame.time": "Jan  5, 1970 03:23:09.839731000 W. Europe Standard Time"}}}},
        {"_source": {"layers": {"frame": {"frame.time": "Jan  5, 1970 03:23:12.703649000 W. Europe Standard Time"}}}},
        {"_source": {"layers": {"frame": {"frame.time": "Jan  5, 1970 03:23:12.703652000 W. Europe Standard Time"}}}},
        {"_source": {"layers": {"frame": {"frame.time": "Jan  5, 1970 03:48:31.898383000 W. Europe Standard Time"}}}},
        {"_source": {"layers": {"frame": {"frame.time": "Jan  5, 1970 03:48:31.898387000 W. Europe Standard Time"}}}},
        {"_source": {"layers": {"frame": {"frame.time": "Jan  5, 1970 03:48:31.957082000 W. Europe Standard Time"}}}},
    ]

    expected_result = [
        "The 10 most requested times:",
        "Time: Jan  5, 1970 03:23:09, Count: 2",
        "Time: Jan  5, 1970 03:23:12, Count: 2",
        "Time: Jan  5, 1970 03:48:31, Count: 3"
    ]

    result = most_requests(data)

    assert result == expected_result