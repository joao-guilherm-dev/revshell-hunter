from revshell_hunter.beacon import BeaconTracker, detect_beacon
from revshell_hunter.config import BeaconConfig

CFG = BeaconConfig(min_events=6, max_cv=0.25, min_interval_seconds=5, history_seconds=3600)


def test_regular_intervals_detected():
    res = detect_beacon([i * 30 + (i % 2) for i in range(8)], CFG)
    assert res is not None and 28 < res.mean_interval < 32 and res.cv < 0.1


def test_irregular_intervals_not_detected():
    assert detect_beacon([0, 5, 100, 130, 900, 905, 2000], CFG) is None


def test_too_few_events_or_too_fast():
    assert detect_beacon([0, 30, 60], CFG) is None
    assert detect_beacon([i * 1.0 for i in range(20)], CFG) is None  # intervalo médio < 5s


def test_identical_timestamps_do_not_crash():
    assert detect_beacon([5.0] * 10, CFG) is None


def test_tracker_counts_each_flow_once():
    t = BeaconTracker(CFG)
    res = None
    for i in range(8):
        for _ in range(3):  # mesma conexão observada várias vezes
            res = t.observe(("p", "8.8.8.8", 443), ("flow", i), now=i * 60.0)
    assert res is not None and res.events == 8


def test_tracker_prunes_old_events():
    t = BeaconTracker(BeaconConfig(min_events=3, max_cv=0.25, min_interval_seconds=5,
                                   history_seconds=100))
    for i in range(5):
        t.observe("k", i, now=i * 60.0)
    assert len(t._events["k"]) <= 3
