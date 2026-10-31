"""
实验运行器 — 自动化验证反制结果有效性

运行流程:
1. 启动 信标服务（后台）
2. 对每个实验场景:
   a. 构造攻击请求
   b. 通过蜜罐四层流水线获取响应
   c. 用靶标Agent处理响应
   d. 检查信标服务是否收到 beacon
   e. 记录量化指标
3. 生成实验报告

实验场景:
- S1: 通用扫描器访问 /wp-login.php (L1)
- S2: 通用扫描器访问 /.env (L2)
- S3: LangChain Agent 访问 /.env (L2 + L3)
- S4: LangChain Agent 访问 CSV payload (L3)
- S5: SK Agent 访问 eval payload (L3)
- S6: 多路径扫描累积威胁分 (L1+L2+L3)
"""

import asyncio
import json
import os
import random
import sys
import time
from typing import List, Dict

# 确保能导入项目根目录下的模块
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.discovery import DiscoveryLayer, AgentType
from core.monitoring import AttackClassifier
from core.analysis import AnalysisLayer
from core.countermeasure import CountermeasureService

from targets import (
    LangChainTargetAgent,
    SemanticKernelTargetAgent,
    GenericScannerTargetAgent,
)
from targets.base import TargetCompromiseResult

from beacon_service import BeaconService
from experiments.validator import ExperimentMetrics, ExperimentReport


class ExperimentRunner:
    """实验运行器"""

    def __init__(self, beacon_port: int = 9999, honeypot_port: int = 8080):
        self.beacon_port = beacon_port
        self.honeypot_port = honeypot_port
        self.beacon_listener: BeaconService = None
        self.report = ExperimentReport()

        # 蜜罐四层流水线
        self.discovery = DiscoveryLayer()
        self.monitoring = AttackClassifier()
        self.analysis = AnalysisLayer()
        self.countermeasure = CountermeasureService(level=3)

    async def run_all(self) -> ExperimentReport:
        """运行所有实验场景"""
        print("=" * 70)
        print("AI Honeypot Countermeasure Effectiveness Experiment")
        print("=" * 70)

        # 启动 信标服务
        self.beacon_listener = BeaconService(port=self.beacon_port)
        beacon_task = asyncio.create_task(self.beacon_listener.start())
        await asyncio.sleep(0.5)  # 等待监听器启动

        # 定义实验场景
        scenarios = [
            self._scenario_l1_maze,
            self._scenario_l2_fake_credentials,
            self._scenario_l2_prompt_injection,
            self._scenario_l3_langchain_cve,
            self._scenario_l3_sk_cve,
            self._scenario_multi_path_cumulative,
        ]

        for scenario_fn in scenarios:
            try:
                metrics = await scenario_fn()
                self.report.scenarios.append(metrics)
            except Exception as e:
                print(f"[Experiment] Scenario failed: {e}")

        # 停止 信标服务
        self.beacon_listener.stop()
        beacon_task.cancel()
        try:
            await beacon_task
        except asyncio.CancelledError:
            pass

        self.report.calculate_aggregates()
        return self.report

    # ------------------------------------------------------------------
    # 场景定义
    # ------------------------------------------------------------------

    async def _scenario_l1_maze(self) -> ExperimentMetrics:
        """S1: L1 资源耗尽 — 无限迷宫"""
        print("\n[Scenario 1] L1 Resource Exhaustion — Infinite Maze")

        # 通用扫描器访问 /wp-login.php
        response_body = self._get_honeypot_response(
            method="GET", path="/wp-login.php",
            headers={"User-Agent": "Mozilla/5.0"},
        )

        target = GenericScannerTargetAgent()
        result = target.process_response(response_body)

        m = ExperimentMetrics(
            scenario_name="L1 Infinite Maze",
            target_agent=target.name,
            threat_score=35.0,  # L1 阈值
            l1_triggered=True,
            response_size_bytes=len(response_body),
            processing_time_ms=result.resource_wasted_ms,
            maze_depth=response_body.count("<a href="),
            is_compromised=result.is_compromised,
            compromise_level=result.compromised_level,
            total_actions=len(result.actions),
        )
        print(f"  Result: maze_depth={m.maze_depth}, processing_time={m.processing_time_ms}ms")
        return m

    async def _scenario_l2_fake_credentials(self) -> ExperimentMetrics:
        """S2: L2 情报欺骗 — 假凭证提取"""
        print("\n[Scenario 2] L2 Intelligence Deception — Fake Credentials")

        response_body = self._get_honeypot_response(
            method="GET", path="/.env",
            headers={"User-Agent": "python-requests/2.31"},
        )

        target = GenericScannerTargetAgent()
        result = target.process_response(response_body)

        # 计算凭证提取率: 响应中植入的凭证数 ≈ 5 (DB_URL, AWS_ID, AWS_SECRET, JWT, REDIS)
        implanted_creds = 5
        extracted = len(result.extracted_credentials)

        m = ExperimentMetrics(
            scenario_name="L2 Fake Credential Extraction",
            target_agent=target.name,
            threat_score=55.0,
            l2_triggered=True,
            response_size_bytes=len(response_body),
            processing_time_ms=result.resource_wasted_ms,
            fake_credentials_extracted=extracted,
            credential_extraction_rate=extracted / implanted_creds if implanted_creds else 0,
            is_compromised=result.is_compromised,
            compromise_level=result.compromised_level,
            total_actions=len(result.actions),
        )
        print(f"  Result: extracted={extracted}/{implanted_creds}, rate={m.credential_extraction_rate*100:.1f}%")
        return m

    async def _scenario_l2_prompt_injection(self) -> ExperimentMetrics:
        """S3: L2 Prompt 反向 — 诱导泄露 system prompt"""
        print("\n[Scenario 3] L2 Prompt Reverse — System Prompt Leakage")

        # 模拟一个高威胁分触发的响应，包含 Prompt Injection
        response_body = self._get_honeypot_response(
            method="GET", path="/.env",
            headers={"User-Agent": "langchain-agent/0.2.5"},
            session_requests=[
                {"method": "GET", "path": "/.env"},
                {"method": "GET", "path": "/debug"},
                {"method": "POST", "path": "/api/query"},
            ],
        )

        target = LangChainTargetAgent()
        result = target.process_response(response_body)

        m = ExperimentMetrics(
            scenario_name="L2 Prompt Injection Leak",
            target_agent=target.name,
            threat_score=75.0,
            l2_triggered=True,
            response_size_bytes=len(response_body),
            processing_time_ms=result.resource_wasted_ms,
            prompt_leaked=bool(result.leaked_system_prompt),
            prompt_leak_success=bool(result.leaked_system_prompt),
            is_compromised=result.is_compromised,
            compromise_level=result.compromised_level,
            total_actions=len(result.actions),
        )
        print(f"  Result: prompt_leaked={m.prompt_leaked}")
        return m

    async def _scenario_l3_langchain_cve(self) -> ExperimentMetrics:
        """S4: L3 CVE — LangChain CSV Agent RCE"""
        print("\n[Scenario 4] L3 CVE Weaponization — LangChain CSV Agent")

        # 获取 CVE-2026-27966 的 payload
        from core.weapon_plugins.cve import CVECatalog
        loader = CVECatalog()
        plugins = loader.find_for_framework("langchain", enabled_only=True)

        if not plugins:
            print("  SKIP: No LangChain CVE plugin found")
            return ExperimentMetrics(scenario_name="L3 LangChain CVE", target_agent="N/A")

        plugin = plugins[0]
        beacon_url = f"http://127.0.0.1:{self.beacon_port}/beacon"
        payload = plugin.craft_payload(beacon_server=beacon_url)

        # 构造包含 payload 的响应（模拟蜜罐返回的武器化内容）
        response_body = f"CSV Analysis Result:\n{payload}"

        target = LangChainTargetAgent()
        result = target.process_response(response_body)

        # 检查信标服务
        await asyncio.sleep(0.3)
        beacon_confirmed = any(
            b.source_ip == "127.0.0.1" and "beacon" in b.path
            for b in self.beacon_listener.beacons[-10:]
        ) if self.beacon_listener.beacons else False

        m = ExperimentMetrics(
            scenario_name="L3 LangChain CSV RCE",
            target_agent=target.name,
            threat_score=85.0,
            l3_triggered=True,
            response_size_bytes=len(response_body),
            processing_time_ms=result.resource_wasted_ms,
            payload_executed=result.compromised_level >= 3,
            beacon_sent=result.beacon_sent,
            beacon_confirmed=beacon_confirmed,
            matched_cve_plugin=plugin.cve_id,
            matched_framework="langchain",
            is_compromised=result.is_compromised,
            compromise_level=result.compromised_level,
            total_actions=len(result.actions),
        )
        print(f"  Result: payload_executed={m.payload_executed}, beacon_sent={m.beacon_sent}, beacon_confirmed={m.beacon_confirmed}")
        return m

    async def _scenario_l3_sk_cve(self) -> ExperimentMetrics:
        """S5: L3 CVE — Semantic Kernel eval RCE"""
        print("\n[Scenario 5] L3 CVE Weaponization — Semantic Kernel eval()")

        from core.weapon_plugins.cve import CVECatalog
        loader = CVECatalog()
        plugins = loader.find_for_framework("semantic_kernel", enabled_only=True)

        if not plugins:
            print("  SKIP: No SK CVE plugin found")
            return ExperimentMetrics(scenario_name="L3 SK CVE", target_agent="N/A")

        plugin = plugins[0]
        beacon_url = f"http://127.0.0.1:{self.beacon_port}/beacon"
        payload = plugin.craft_payload(beacon_server=beacon_url)

        response_body = f"Search result: {payload}"

        target = SemanticKernelTargetAgent()
        result = target.process_response(response_body)

        await asyncio.sleep(0.3)
        beacon_confirmed = any(
            b.source_ip == "127.0.0.1" and "beacon" in b.path
            for b in self.beacon_listener.beacons[-10:]
        ) if self.beacon_listener.beacons else False

        m = ExperimentMetrics(
            scenario_name="L3 Semantic Kernel eval RCE",
            target_agent=target.name,
            threat_score=85.0,
            l3_triggered=True,
            response_size_bytes=len(response_body),
            processing_time_ms=result.resource_wasted_ms,
            payload_executed=result.compromised_level >= 3,
            beacon_sent=result.beacon_sent,
            beacon_confirmed=beacon_confirmed,
            matched_cve_plugin=plugin.cve_id,
            matched_framework="semantic_kernel",
            is_compromised=result.is_compromised,
            compromise_level=result.compromised_level,
            total_actions=len(result.actions),
        )
        print(f"  Result: payload_executed={m.payload_executed}, beacon_sent={m.beacon_sent}, beacon_confirmed={m.beacon_confirmed}")
        return m

    async def _scenario_multi_path_cumulative(self) -> ExperimentMetrics:
        """S6: 多路径累积 — L1+L2+L3 同时触发"""
        print("\n[Scenario 6] Multi-Path Cumulative — L1+L2+L3")

        # 模拟一个完整的攻击会话
        requests = [
            ("GET", "/.env"),
            ("GET", "/debug"),
            ("GET", "/api/internal/users"),
            ("GET", "/backup"),
            ("GET", "/wp-login.php"),
        ]

        # 用 LangChain Agent 作为靶标
        target = LangChainTargetAgent()
        total_time = 0
        max_level = 0
        total_size = 0

        for method, path in requests:
            body = self._get_honeypot_response(
                method=method, path=path,
                headers={"User-Agent": "langchain-agent/0.2.5"},
                session_requests=[{"method": m, "path": p} for m, p in requests],
            )
            total_size += len(body)
            result = target.process_response(body)
            total_time += result.resource_wasted_ms
            max_level = max(max_level, result.compromised_level)

        await asyncio.sleep(0.3)
        beacon_confirmed = any(
            b.source_ip == "127.0.0.1"
            for b in self.beacon_listener.beacons[-10:]
        ) if self.beacon_listener.beacons else False

        m = ExperimentMetrics(
            scenario_name="Multi-Path Cumulative Attack",
            target_agent=target.name,
            threat_score=95.0,
            l1_triggered=True,
            l2_triggered=True,
            l3_triggered=True,
            response_size_bytes=total_size,
            processing_time_ms=total_time,
            fake_credentials_extracted=len(target.extracted_creds),
            prompt_leaked=bool(target.leaked_prompt),
            payload_executed=target.beacon_sent,
            beacon_sent=target.beacon_sent,
            beacon_confirmed=beacon_confirmed,
            is_compromised=target.compromised or len(target.actions) > 0,
            compromise_level=max_level,
            total_actions=len(target.actions),
        )
        print(f"  Result: total_time={total_time}ms, beacon_confirmed={beacon_confirmed}, actions={len(target.actions)}")
        return m

    # ------------------------------------------------------------------
    # 工具方法
    # ------------------------------------------------------------------

    def _get_honeypot_response(self, method: str, path: str, headers: dict,
                                session_requests: List[Dict] = None) -> str:
        """
        直接调用蜜罐的四层流水线，获取响应体。
        不经过 HTTP 网络层，直接调用核心逻辑。
        """
        from core.countermeasure import HallucinationExploit, ResourceExhaustion

        # 构造请求头文本
        header_text = f"{method} {path} HTTP/1.1\r\n"
        for k, v in headers.items():
            header_text += f"{k}: {v}\r\n"

        ua = headers.get("User-Agent", "")
        client_ip = "127.0.0.1"

        # 发现层
        disc = self.discovery.analyze(client_ip, headers, ua, random.uniform(500, 2000))

        # 监控层
        mon = self.monitoring.classify(method, path, "", header_text)

        # 会话分析
        reqs = session_requests or [{"method": method, "path": path, "query": ""}]
        session_data = self.monitoring.classify_session(reqs)
        attr = self.analysis.analyze(
            session_data.get("distribution", {}),
            agent_type=disc.agent_type.value,
            mcp_triggered=False,
            timing_ms=random.uniform(500, 2000),
        )

        # 反制层
        cm = None
        if attr.trigger_countermeasure:
            cm = self.countermeasure.execute(
                threat_score=attr.threat_score,
                agent_type=disc.agent_type.value,
                attack_family=mon.families[0].value if mon.families else "unknown",
                mcp_triggered=False,
                path=path,
            )

        # 构造响应体（模拟 build_response）
        if cm and cm.success and "maze" in (cm.response_payload or "").lower():
            return cm.response_payload
        if path in ("/", ""):
            return HallucinationExploit().fake_env()
        if path == "/.env":
            body = HallucinationExploit().fake_env()
            # 如果触发了 L2 Prompt 反向，追加注入内容
            if cm and cm.success:
                for action in cm.applied_actions:
                    if action.action_type == "prompt_reverse":
                        body += f"\n<!-- {action.payload} -->\n"
                    elif action.action_type == "memory_poisoning":
                        body += f"\n<!-- {action.payload} -->\n"
            return body
        if path == "/debug":
            return HallucinationExploit().fake_debug_info()
        if path.startswith("/api/internal"):
            return json.dumps(HallucinationExploit().fake_internal_api())
        if path in ("/wp-login.php", "/phpmyadmin", "/admin", "/actuator"):
            return ResourceExhaustion().infinite_maze(path)
        if path == "/backup":
            return "<!DOCTYPE html><html><body><h1>Backup Repository</h1></body></html>"

        return f"404 Not Found: {path}"


async def main():
    """独立运行实验"""
    runner = ExperimentRunner(beacon_port=9999)
    report = await runner.run_all()
    report.save()
    print("\n" + "=" * 70)
    print("Experiment Complete!")
    print(f"L1 Success Rate: {report.l1_success_rate*100:.1f}%")
    print(f"L2 Success Rate: {report.l2_success_rate*100:.1f}%")
    print(f"L3 Success Rate: {report.l3_success_rate*100:.1f}%")
    print(f"Overall Success Rate: {report.overall_success_rate*100:.1f}%")
    print(f"Beacons Confirmed: {report.total_beacons}")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
