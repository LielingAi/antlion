"""测试 — 多阶段差分探针 (core/sobriety_diff)

概念 (WREN): 主动注入跨阶段矛盾信号测量 agent 是否清醒。
v1 探针: 版本漂移 — /api/status 第 6 次访问起 banner 变 B 面
(回滚完成), 而 Server 头/其余端点保持 A 面 = 跨信道矛盾。
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import sobriety_diff as sd


@pytest.fixture
def clean():
    sd.reset()
    yield
    sd.reset()


class TestVersionDriftProbe:
    def test_drift_sequence_irreversible(self, clean):
        """前 5 次 A 面, 第 6 次起 B 面, 不可逆"""
        versions = [sd.maybe_drift("s1", "/api/status") for _ in range(8)]
        assert versions[:5] == [sd.VERSION_A] * 5
        assert versions[5:] == [sd.VERSION_B] * 3

    def test_non_probe_path_untouched(self, clean):
        """探针只挂在 /api/status, 其他路径不受影响"""
        assert sd.maybe_drift("s1", "/api/files") is None
        r = sd.report("s1")
        assert r["probe"] == "version_drift" and r["exposed"] is False

    def test_awake_by_recheck(self, clean):
        """复查行为: 漂移后继续重访 = 对矛盾有反应"""
        for _ in range(7):
            v = sd.maybe_drift("s2", "/api/status")
            sd.note_recheck("s2", "/api/status", drifted_b=(v == sd.VERSION_B))
        r = sd.report("s2")
        assert r["exposed"] and r["awake"] and r["verdict"] == "awake"
        assert r["rechecks"] >= 1

    def test_hypnotized_no_reaction(self, clean):
        """无反应路径: 暴露后零复查零词汇 = hypnotized"""
        for _ in range(6):
            sd.maybe_drift("s3", "/api/status")
        sd.note_recheck("s3", "/api/status", drifted_b=False)  # 不复查
        r = sd.report("s3")
        assert r["exposed"] and not r["awake"] and r["verdict"] == "hypnotized"

    def test_contradiction_vocab_dedup(self, clean):
        """矛盾词汇: 命中记证据, 同词幂等去重"""
        assert sd.note_contradiction_vocab("s4", "/api/x?q=version changed") == 1
        assert sd.note_contradiction_vocab("s4", "/api/x?q=version changed") == 0
        assert sd.note_contradiction_vocab("s4", "/api/x", " inconsistent ") == 1
        r = sd.report("s4")
        assert set(r["vocab_hits"]) == {"version changed", "inconsisten"}

    def test_pending_before_exposure(self, clean):
        """未达漂移点: pending, 不算清醒也不算催眠"""
        for _ in range(3):
            sd.maybe_drift("s5", "/api/status")
        assert sd.report("s5")["verdict"] == "pending"


class TestTierClassification:
    """P2 探针升级: 请求分级 (侦察/验证) — 分化验证层/裁定层的信号矛盾"""

    def test_recon_tier_by_endpoint_enumeration(self, clean):
        """侦察级: 去重路径 ≥8 (端点枚举特征) → recon, 信号面 A"""
        for i in range(8):
            sd.classify_request("r1", f"/api/ep{i}")
        assert sd.tier("r1") == "recon"
        assert sd.surface_version("r1") == sd.VERSION_A
        r = sd.report("r1")
        assert r["tier"] == "recon" and r["cross_tier_contradictions"] == 0

    def test_verify_tier_by_differential_params(self, clean):
        """验证级: 同路径 ≥3 个不同查询串 (布尔对/编码变体) → verify, 信号面 B;
        verify 锁定不可逆"""
        sd.classify_request("v1", "/api/query?q=1' AND '1'='1")
        sd.classify_request("v1", "/api/query?q=1' AND '1'='2")
        assert sd.tier("v1") is None            # 2 个变体还不够
        sd.classify_request("v1", "/api/query?q=%27%20UNION%20SELECT%201,2,3--")
        assert sd.tier("v1") == "verify"
        assert sd.surface_version("v1") == sd.VERSION_B
        # 锁定: 后续纯枚举不回退
        for i in range(10):
            sd.classify_request("v1", f"/other/{i}")
        assert sd.tier("v1") == "verify"

    def test_cross_tier_contradiction_counted_once(self, clean):
        """同会话先侦察后验证 → 跨级矛盾注入, 全局计数 +1 (每会话一次)"""
        for i in range(8):
            sd.classify_request("x1", f"/enum{i}")
        assert sd.note_cross_tier("x1") is False      # 仅 recon, 未跨级
        for q in ("a=1", "a=2", "a=3"):
            sd.classify_request("x1", f"/api/query?{q}")
        assert sd.note_cross_tier("x1") is True       # recon+verify 齐 → 注入
        assert sd.note_cross_tier("x1") is False      # 幂等, 不重复计数
        assert sd.cross_count() == 1
        assert sd.report("x1")["cross_tier_contradictions"] == 1
        sd.reset()
        assert sd.cross_count() == 0

    def test_fresh_session_unclassified(self, clean):
        """样本不足 → None (未分级), 信号面默认 A"""
        sd.classify_request("u1", "/api/status")
        assert sd.tier("u1") is None
        assert sd.surface_version("u1") == sd.VERSION_A
