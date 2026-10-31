# DeepTeam 武器工艺桥接

## 1. 定位

DeepTeam 在本项目中不是独立红队 Runner，而是 Arsenal 的武器工艺提供者：

```text
DeepTeam Vulnerability + Attack
        ↓ 生成或增强
反制 payload + 动作契约
        ↓ 蜜罐挂载点投送
来访 Agent 执行动作
        ↓
蜜罐行为证据与武器效能
```

桥接插件位于 `weapon_packs/deepteam_bridge/`，复用统一 `WeaponRuntime`，不调用 DeepTeam 的 `red_team()`，也不使用其 CVSS 作为蜜罐武器效能。

## 2. 模块

| 文件 | 职责 |
| --- | --- |
| `adapter.py` | 可选依赖、动态攻击/漏洞解析、AttackSimulator |
| `generator.py` | `enhance_only`、`generate` 与多轮基础 payload |
| `contract.py` | 反制目标、预期动作、成功信号和世界依赖 |
| `progression.py` | 同步 DeepTeam 多轮攻击到事件驱动会话的桥接 |
| `weapon.py` | Prompt、Vuln、MCP、CLI 输出、缓存和生命周期 |

## 3. 武器配置

```json
{
  "plugin": "deepteam.bridge",
  "config": {
    "deepteam": {
      "mode": "generate",
      "vulnerability": "SQLInjection",
      "vulnerability_types": ["union_based_injection"],
      "attack": "PromptInjection",
      "target_purpose": "引导 Agent 对蜜罐 /api/query 执行 SQL 注入"
    },
    "action": {
      "goal": "数据",
      "expected": "Agent 向 /api/query 发送 SQL 注入请求",
      "success_signal": ["request:/api/query", "exp_stage_advance"],
      "world_requirements": ["endpoint:/api/query"],
      "next_stage": "W-BEACON-STAGE2-1"
    },
    "generation": {
      "cache": "session",
      "simulator_model": "gpt-4o-mini"
    }
  }
}
```

`action.goal` 支持 `数据/提示词/控制` 及对应英文值。`success_signal` 是蜜罐可观察的行为证据，不是 DeepTeam Metric 分数。

## 4. 生成模式

### `enhance_only`

```text
config.deepteam.base_payload
  → DeepTeam Attack.enhance()
  → 武器 payload
```

适合现有武器变形和 A/B。`Base64` 等确定性攻击不需要模型调用；`PromptInjection` 等攻击需要 simulator model。

### `generate`

```text
Vulnerability + target_purpose
  → AttackSimulator 生成基础攻击
  → Attack.enhance()
  → 武器 payload
```

`vulnerability_types`、`vulnerability_options`、`attack_options` 会按 DeepTeam 构造函数签名传入。

## 5. 多轮事件驱动

`deepteam.multi_turn=true` 时使用 `LinearJailbreaking`、`CrescendoJailbreaking` 等 DeepTeam 多轮攻击。

每个会话启动一个守护线程：

1. DeepTeam 调用桥接 `model_callback`；
2. 回调将当前 payload 放入事件队列并等待 Agent 响应；
3. 蜜罐把 payload 投送给 Agent；
4. Agent 下一次请求携带响应，插件把响应交回 DeepTeam；
5. DeepTeam 继续推进，直到完成、拒绝、超时或会话销毁。

不会重放历史，也不会为每个请求重新创建攻击。`release_session()` 和 `deactivate()` 会停止等待中的线程。

相关配置：

- `generation.delivery_timeout`：等待 DeepTeam 生成下一轮的时间，默认 30 秒；
- `generation.agent_timeout`：等待外部 Agent 响应的时间，默认 300 秒。

## 6. 缓存与一致性

`generation.cache`：

- `session`：每个会话生成一次并复用；
- `instance`：武器实例共享生成结果；
- `none`：每次调用重新生成，仅用于显式实验。

多轮攻击始终使用会话级 `ProgressionDriver`。同一会话还受统一运行时的插件版本和配置固定约束。

## 7. 输出与遥测

插件支持：

- `render()`：Prompt 文本；
- `handle()`：漏洞 HTTP 响应；
- `describe()`：MCP 工具描述；
- `next_instruction()`：CLI 阶段指令；
- `advance()`：多轮响应推进。

默认遥测包含 DeepTeam 攻击、漏洞、生成模式、动作契约、缓存、轮次和停止原因，不包含默认生成的原始 payload。

## 8. 安装与 Docker

### 8.1 模型与凭据

控制台“配置 → DeepTeam 模型”提供集中配置：

- 供应商：`openai`、`deepseek`、`anthropic`、`google`、`moonshotai`、`xai`、`ollama`；
- `Simulator model`：模型名称，或 `provider/model` 形式；
- `Base URL`：可选的 OpenAI 兼容端点或 Ollama 地址；
- `API Key`：只写入服务端，浏览器不返回明文，留空不会覆盖已有凭据；勾选“清除已保存的 API Key”可显式删除。

配置保存在 Hive，并通过受保护的 `/api/sensor_config` 通道下发 Sensor。ConfigAgent 的状态展示会将凭据脱敏。确定性攻击（如 Base64）不需要模型或凭据；`generate`、模型驱动增强和多轮推进需要有效配置。

基础蜜罐不强制依赖 DeepTeam。手动安装可选依赖：

```bash
pip install -r requirements-deepteam.txt
```

Docker 默认不安装。需要桥接时：

```bash
INSTALL_DEEPTEAM=1 docker compose up -d --build
```

`requirements-deepteam.txt` 额外声明了 `sentry-sdk`，因为上游 `deepteam.telemetry` 在导入时强制使用它但未在包依赖中声明。

`GET /api/deepteam/catalog` 返回当前安装包的攻击和漏洞目录；未安装时返回 `available=false`，不影响其他武器。

## 9. 试射与激活

- `validate()` 检查依赖、攻击/漏洞名称和动作契约。
- `test_fire()` 额外验证 `endpoint:*` 世界依赖，并执行实际生成。
- 激活前需要保证 simulator model 配置可用；确定性 `enhance_only` 攻击除外。
- 多轮试射只执行首轮，后续轮次由实际会话响应推进。

## 10. 内置参考武器

- `W-DT-PROMPT-LEAK-1`：`enhance_only + Base64`，无外部模型依赖。
- `W-DT-SQLI-CHAIN-1`：`generate + SQLInjection + PromptInjection`，需要受控 simulator model。

两把武器默认停用，需先完成配置校验和试射。

## 11. 离线 A/B

```bash
python experiments/deepteam_ab.py --attack Base64 --payload "your counter payload"
```

脚本对比原 payload 与 DeepTeam 增强结果，检查动作契约和会话缓存，并明确输出 `effectiveness_measured=false`。它只验证工艺差异；真实 Agent 命中率需要在目标模型矩阵中另行测量。

## 12. 验证

```bash
py -3.13 -m pytest tests/test_deepteam_bridge.py -q
py -3.13 -m pytest tests/test_deepteam_model.py -q
py -3.13 -m pytest tests/test_weapon_plugins.py -q
py -3.13 -m pytest tests/test_weapon_upload.py -q
py -3.13 -m pytest -q
```

未配置模型凭据时，不应对外宣称 `generate` 和真实 DeepTeam 多轮模型链路已完成端到端验证；确定性测试只覆盖适配、契约、缓存和事件桥接。
