from netscope.pipeline import Pipeline
from netscope.settings import Settings

GEO = {"ip": "8.8.8.8", "lat": 1.0, "lon": 2.0, "city": "Testville", "country": "Testland", "cc": "TT"}


class FakeGeo:
    def __init__(self, result=GEO):
        self.result = result

    def lookup(self, ip):
        return None if self.result is None else {**self.result, "ip": ip}


def make(geo=None):
    events = []
    pipe = Pipeline(FakeGeo() if geo is None else geo, Settings(), lambda name, payload: events.append((name, payload)),
                    resolve_names=False)
    return pipe, events


EV = {"ip": "142.250.80.46", "port": 443, "direction": "out", "proto": "HTTPS"}


def test_emits_enriched_event():
    pipe, events = make()
    assert pipe.handle(EV)
    name, payload = events[0]
    assert name == "pkt"
    assert payload["ip"] == EV["ip"] and payload["country"] == "Testland" and payload["proto"] == "HTTPS"
    assert payload["top"] == [("Testland", 1)]


def test_duplicates_within_window_are_suppressed():
    pipe, events = make()
    assert pipe.handle(EV) and not pipe.handle(EV)
    assert len(events) == 1


def test_same_host_different_direction_is_not_a_duplicate():
    pipe, events = make()
    pipe.handle(EV)
    pipe.handle({**EV, "direction": "in", "proto": "PROBE"})
    assert len(events) == 2


def test_ip_without_location_is_dropped():
    pipe, events = make(FakeGeo(None))
    assert not pipe.handle(EV)
    assert events == []


BAD_EVENTS = [
    {"ip": "nope", "port": 1, "direction": "out", "proto": "TCP"},
    {"ip": "1.1.1.1", "port": "x", "direction": "out", "proto": "TCP"},
    {"ip": "1.1.1.1", "port": 1, "direction": "sideways", "proto": "TCP"},
    {"ip": "1.1.1.1", "port": 1, "direction": "out", "proto": "<script>"},
    {"port": 1},
]


def test_malformed_events_are_rejected():
    pipe, events = make()
    for bad in BAD_EVENTS:
        assert not pipe.handle(bad)
    assert events == []


def test_stats_count_per_country():
    pipe, events = make()
    for i in range(3):
        pipe.handle({**EV, "ip": f"142.250.80.{i + 1}"})
    assert events[-1][1]["top"] == [("Testland", 3)]
