"""战果页后端: 结论分级、硬证据与噪声分离。"""

from core.testdb import TestDB
from experiments.dashboard import _outcome


def _req(db, *, ai=True, canary=False, path="/api/query"):
    db.record_request("r", "s-ai" if ai else "s-plain", "203.0.113.9", "GET", path,
                      "agent/1.0" if ai else "curl/8", ai,
                      "llm_agent" if ai else "unknown", 20.0, [], 0, 0, canary)


def test_quiet_when_only_plain_traffic(tmp_path):
    db = TestDB(str(tmp_path / "a.sqlite"))
    _req(db, ai=False)
    d = _outcome(db)
    assert d["verdict"]["level"] == "quiet"
    assert d["traffic"]["plain_requests"] == 1
    assert d["traffic"]["ai_requests"] == 0
    assert all(s["count"] == 0 for s in d["hard_signals"])


def test_contact_when_ai_traffic_without_hard_evidence(tmp_path):
    db = TestDB(str(tmp_path / "b.sqlite"))
    _req(db)
    db.record_cm("s-ai", "exp_chain_complete", "[weapon:EXP-1] 链走完")
    d = _outcome(db)
    assert d["verdict"]["level"] == "contact"
    assert d["traffic"]["ai_sessions"] == 1
    chain = next(s for s in d["contact_signals"] if s["id"] == "chain_complete")
    assert chain["count"] == 1


def test_success_counts_canary_tagged_beacon_and_task(tmp_path):
    db = TestDB(str(tmp_path / "c.sqlite"))
    _req(db, canary=True)
    db.record_intel("r", "s-ai", "exp_chain", "canary", "h1", "sample", False)
    db.record_beacon({"beacon_id": "b1", "run_id": "sensor_1", "source_ip": "203.0.113.9",
                      "method": "GET", "path": "/beacon?c=header", "body": ""})
    db.record_beacon({"beacon_id": "b2", "run_id": "sensor_1", "source_ip": "203.0.113.9",
                      "method": "GET", "path": "/", "body": ""})
    db.record_cm("s-ai", "task_completed", "[cal-1] ok=True")
    d = _outcome(db)
    assert d["verdict"]["level"] == "success"
    counts = {s["id"]: s["count"] for s in d["hard_signals"]}
    assert counts == {"canary_reuse": 1, "canary_intel": 1, "tagged_beacon": 1,
                      "canary_used": 0, "prompt_captured": 0, "task_completed": 1}
    assert d["traffic"]["beacon_total"] == 2
    assert d["traffic"]["beacon_noise"] == 1
    assert d["recent"] and d["recent"][0]["kind"] in ("intel", "canary", "beacon")


def test_captures_list_concrete_items(tmp_path):
    db = TestDB(str(tmp_path / "e.sqlite"))
    _req(db)
    db.record_cm("s-ai", "canary_used", "假 PG 认证成功 — 泄露口令被用于内网登录")
    db.record_cm("s-ai", "task_completed", "[cal-1] ok=True: Q09NTU9O")
    d = _outcome(db)
    kinds = [c["kind"] for c in d["captures"]]
    assert "canary_used" in kinds and "task_completed" in kinds
    used = next(c for c in d["captures"] if c["kind"] == "canary_used")
    assert used["title"] == "假内网登录成功"
    assert "假 PG 认证成功" in used["detail"]


def test_delivery_capture_includes_submitted_body(tmp_path):
    db = TestDB(str(tmp_path / "f.sqlite"))
    db.record_request("r", "s-post", "203.0.113.9", "POST", "/api/bounty/submit",
                      "agent/1.0", True, "llm_agent", 30.0, [], 0, 0, False,
                      body='{"title": "TEST", "description": "TEST"}')
    db.record_cm("s-post", "delivery_accepted", "bounty 交付已受理 — 无金丝雀 (表演数据)")
    d = _outcome(db)
    cap = next(c for c in d["captures"] if c["kind"] == "delivery_accepted")
    assert '"title": "TEST"' in cap["detail"]
    assert "提交正文" in cap["detail"]


def test_delivery_capture_notes_get_only(tmp_path):
    db = TestDB(str(tmp_path / "g.sqlite"))
    db.record_request("r", "s-get", "203.0.113.9", "GET", "/api/bounty/submit",
                      "agent/1.0", True, "llm_agent", 30.0, [], 0, 0, False)
    db.record_cm("s-get", "delivery_accepted", "bounty 交付已受理")
    d = _outcome(db)
    cap = next(c for c in d["captures"] if c["kind"] == "delivery_accepted")
    assert "未提交正文" in cap["detail"]


def test_actors_group_evidence_by_attacker(tmp_path):
    db = TestDB(str(tmp_path / "h.sqlite"))
    db.record_request("r", "s-a", "1.1.1.1", "GET", "/api/query", "agent/1.0",
                      True, "llm_agent", 40.0, [], 0, 0, True)
    db.record_request("r", "s-b", "2.2.2.2", "GET", "/api/query", "agent/1.0",
                      True, "llm_agent", 50.0, [], 0, 0, False)
    db.record_cm("s-a", "canary_used", "假 PG 认证成功")
    db.record_cm("s-b", "beacon_hit", "信标命中")
    d = _outcome(db)
    a = next(x for x in d["actors"] if x["session_id"] == "s-a")
    assert a["top_evidence"] == "假内网登录成功"
    assert a["client_ip"] == "1.1.1.1"
    assert a["agent_type"] == "llm_agent"
    assert a["items"][0]["kind"] == "canary_used"
    b = next(x for x in d["actors"] if x["session_id"] == "s-b")
    assert b["top_evidence"] == "信标回连"
    assert d["actors"][0]["last_ts"] >= d["actors"][-1]["last_ts"]


def test_deception_signals_are_not_success(tmp_path):
    db = TestDB(str(tmp_path / "d.sqlite"))
    _req(db)
    db.record_intel("r", "s-ai", "env", "forged", "h2", "fake", False)
    db.record_intel("r", "s-ai", "env", "shared_forgery", "h3", "fake", True)
    db.record_cm("s-ai", "fab_rejected", "编造被拒绝")
    d = _outcome(db)
    assert d["verdict"]["level"] == "contact"
    counts = {s["id"]: s["count"] for s in d["deception"]}
    assert counts["forged"] == 1 and counts["shared_forgery"] == 1
    assert counts["fab_rejected"] == 1
