import sys
sys.path.append('../')

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

    print(most_requests(data))

test_most_requests()

