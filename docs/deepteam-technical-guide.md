# DeepTeam 技术文档

> 集成状态（2026-10-30）：DeepTeam 已作为可选武器工艺桥接到 Arsenal，详见 [`deepteam-weapon-bridge.md`](deepteam-weapon-bridge.md)。本文保留上游技术分析。

## 1. 文档说明

本文基于 Confident AI 开源项目 [DeepTeam](https://github.com/confident-ai/deepteam) 的 README、Python 包配置及核心源码整理，目标是说明其技术定位、执行架构、主要接口、结果模型，以及它与当前 AI Agent 蜜罐项目的结合方式。

| 项目 | 内容 |
| --- | --- |
| 上游项目 | `confident-ai/deepteam` |
| 源码分支 | `main` |
| 分析基线 | `6306f0ff319a932955399405af82f78ee91e9370` |
| 包版本 | `1.0.10`（以分析基线中的 `pyproject.toml` 为准） |
| 许可证 | Apache 2.0 |
| 文档日期 | 2026-10-30 |
| 验证范围 | 文档与源码静态分析，未进行本地安装和运行验证 |

## 2. 项目定位

DeepTeam 是一个面向 LLM 应用和 AI Agent 的自动化红队测试框架，构建在 DeepEval 之上。它将红队测试抽象为以下过程：

> 选择风险类别 → 动态生成攻击 → 调用目标系统 → 评估目标输出 → 汇总风险结果

其主要用途包括：

- 对聊天机器人、RAG 管线和 Agent 进行安全回归测试；
- 检查提示词泄漏、隐私泄漏、越权、工具滥用等风险；
- 使用单轮或多轮攻击方法提高测试覆盖率；
- 按 OWASP、NIST、MITRE ATLAS 等框架组织测试；
- 将测试结果保存为 JSON 或转换为 DataFrame；
- 使用独立 Guardrails 模块对生产输入和输出进行分类检查。

DeepTeam 不是传统 Web 漏洞扫描器，也不是蜜罐系统。它关注的是**由模型输出和 Agent 行为表现出来的安全风险**。

## 3. 核心概念

| 概念 | 作用 | 主要实现 |
| --- | --- | --- |
| Vulnerability | 定义要测试的风险及其子类型，并关联攻击生成和评估指标 | `deepteam/vulnerabilities/` |
| Attack | 对基础攻击进行编码、重构或多轮推进 | `deepteam/attacks/` |
| AttackSimulator | 生成基础攻击，选择并执行攻击增强 | `deepteam/attacks/attack_simulator/` |
| AttackEngine | 为攻击生成提供底层生成能力 | `deepteam/attacks/attack_engine/` |
| `model_callback` | 将 DeepTeam 与待测 LLM 应用解耦 | 由使用方实现 |
| Metric | 使用规则或 LLM-as-a-Judge 判断测试结果 | `deepteam/metrics/` |
| `RTTestCase` | 保存攻击输入、目标输出、对话轮次、分数、理由和错误 | `deepteam/test_case/test_case.py` |
| `RiskAssessment` | 聚合测试用例，统计通过率并计算风险分数 | `deepteam/red_teamer/risk_assessment.py` |
| Guardrails | 在生产请求链路中检查输入或输出 | `deepteam/guardrails/` |

### 3.1 Vulnerability 与 Attack 的区别

两者不能混为一谈：

- **Vulnerability 决定“测试什么”**，例如 PII Leakage、BOLA、Goal Theft。
- **Attack 决定“如何测试”**，例如 Prompt Injection、Base64、Linear Jailbreaking。

同一个漏洞类型可以搭配多种攻击方法，同一种攻击方法也可以用于多个漏洞类型。

### 3.2 Simulator Model 与 Evaluation Model

DeepTeam 默认使用两个逻辑角色：

- **Simulator model**：生成基础攻击，并在需要时增强或推进攻击；
- **Evaluation model**：判断目标输出是否通过相应漏洞指标。

在顶层 `red_team()` API 中，两者默认均为 `gpt-4o-mini`。二者可以替换为 DeepEval 支持的自定义模型，因此攻击生成模型、评审模型和被测目标可以彼此不同。

## 4. 总体架构

```text
┌──────────────────────────────────────────────────────────┐
│                      Python API / CLI                    │
│ vulnerabilities / attacks / framework / runtime options  │
└────────────────────────────┬─────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────┐
│                        RedTeamer                         │
│        参数解析、任务编排、同步/异步执行、结果输出         │
└───────────────────┬──────────────────┬───────────────────┘
                    │                  │
                    ▼                  ▼
┌───────────────────────────┐  ┌──────────────────────────┐
│      AttackSimulator      │  │   Framework Mapping      │
│ 生成基础攻击、攻击增强、   │  │ OWASP / NIST / MITRE ... │
│ 多轮对话推进               │  │ 风险类别到漏洞与攻击映射  │
└─────────────┬─────────────┘  └──────────────────────────┘
              │
              ▼
┌──────────────────────────────────────────────────────────┐
│                     model_callback                       │
│          待测 Chatbot / RAG / Agent / LLM Endpoint        │
└────────────────────────────┬─────────────────────────────┘
                             │ actual_output / turns
                             ▼
┌──────────────────────────────────────────────────────────┐
│                 Red-Teaming Metrics                      │
│          LLM-as-a-Judge、二值分数、判断理由               │
└────────────────────────────┬─────────────────────────────┘
                             ▼
┌──────────────────────────────────────────────────────────┐
│                     RiskAssessment                       │
│     漏洞维度统计 / 攻击维度统计 / CVSS / JSON / DataFrame │
└──────────────────────────────────────────────────────────┘
```

## 5. 核心执行流程

### 5.1 初始化

顶层 `deepteam.red_team()` 是轻量封装，主要负责：

1. 创建 `RedTeamer`；
2. 传入模拟模型、评审模型、并发数、目标用途和暴露等级；
3. 调用 `RedTeamer.red_team()`；
4. 返回 `RiskAssessment`。

目标系统不需要向 DeepTeam 暴露内部实现，只需提供符合约定的回调。

### 5.2 生成基础攻击

`AttackSimulator` 遍历漏洞对象及其子类型，调用漏洞实现的 `simulate_attacks()` 或 `a_simulate_attacks()` 生成基础测试用例。

设：

- 漏洞子类型总数为 `V`；
- 每个子类型的基础攻击数为 `A`，即 `attacks_per_vulnerability_type`；
- 配置的增强攻击方法数为 `M`。

则基础攻击数量为：

```text
N = V × A
```

当 `run_all_attacks=True` 时，每个基础攻击会分别应用所有攻击方法，理论测试用例数为：

```text
N_total = V × A × M
```

当 `run_all_attacks=False` 时，每个基础攻击只应用一种按 `weight` 加权随机选择的攻击方法，因此攻击组合和结果可能随运行变化。若需要覆盖全部组合或进行严格对比，应显式启用 `run_all_attacks`，并控制模型、随机性和测试预算。

### 5.3 攻击增强

所有攻击继承 `BaseAttack`，其核心接口为：

```python
class BaseAttack(ABC):
    weight: int = 1
    multi_turn: bool = False
    name: str
    description: Optional[str] = None
    exploitability: Exploitability

    def enhance(self, attack: str, *args, **kwargs) -> str:
        ...

    async def a_enhance(self, attack: str, *args, **kwargs) -> str:
        ...

    @abstractmethod
    def get_name(self) -> str:
        ...
```

单轮攻击通常将基础输入转换为增强后的输入。多轮攻击则通过目标回调持续获取响应，并根据响应推进后续轮次。多轮执行期间可以进行逐轮指标检查，对话及停止原因会记录在 `RTTurn` 中。

### 5.4 调用目标

DeepTeam 支持同步和异步目标回调。包装器通过函数签名判断回调是否接收历史轮次：

```python
async def model_callback(input: str) -> str:
    ...
```

或：

```python
async def model_callback(
    input: str,
    turns: Optional[List[RTTurn]] = None,
) -> RTTurn:
    ...
```

回调可以返回：

- 字符串，由框架包装为 `RTTurn(role="assistant", content=...)`；
- `RTTurn`，但其 `role` 必须为 `assistant`。

除回调外，`model_callback` 也支持 DeepEval 模型对象或带供应商前缀的模型字符串。源码中的字符串映射包括 `openai`、`anthropic`、`google`、`xai`、`moonshotai`、`deepseek` 和 `ollama`，格式示例为 `openai/gpt-4.1`。

### 5.5 评估与聚合

评估指标要求测试用例至少包含 `input` 和 `actual_output`。评估完成后，DeepTeam：

1. 将分数、理由、错误和成本写回 `RTTestCase`；
2. 按漏洞子类型聚合；
3. 按攻击方法聚合；
4. 计算通过率和风险分数；
5. 构造 `RiskAssessment`。

默认 `ignore_errors=True`，部分生成、增强或评估异常会记录在测试用例中，而不是立即终止整个任务。调试接入问题时应考虑将其设为 `False`，避免错误被结果文件吸收后不易察觉。

## 6. 主要能力

### 6.1 漏洞覆盖

README 列出了 50 余种漏洞，主要分为：

- **数据隐私**：PII Leakage、Prompt Leakage；
- **负责任 AI**：Bias、Toxicity、Fairness、Ethics；
- **安全**：BFLA、BOLA、RBAC、SQL Injection、SSRF、Tool Metadata Poisoning；
- **内容安全**：Illegal Activity、Graphic Content、Personal Safety；
- **业务风险**：Misinformation、Intellectual Property、Competition；
- **Agent 风险**：Goal Theft、Recursive Hijacking、Excessive Agency、Tool Orchestration Abuse、Inter-Agent Communication Compromise、Autonomous Agent Drift 等；
- **自定义风险**：通过自定义漏洞和指标扩展。

### 6.2 攻击覆盖

单轮攻击包括提示注入、角色扮演、编码转换、多语言、权限升级、目标重定向、上下文污染等。

多轮攻击包括：

- Linear Jailbreaking；
- Tree Jailbreaking；
- Crescendo Jailbreaking；
- Sequential Jailbreak；
- Bad Likert Judge。

多轮能力不仅改变输入文本，还会根据目标响应决定后续攻击路径，因此更接近有状态的 Agent 交互测试。

### 6.3 安全框架映射

DeepTeam 可以将安全框架中的风险类别映射到对应漏洞和攻击，当前 README 列出：

- OWASP Top 10 for LLMs 2025；
- OWASP Top 10 for Agents 2026；
- NIST AI RMF；
- MITRE ATLAS；
- BeaverTails；
- Aegis。

框架模式适合建立覆盖面基线；针对具体业务缺陷的深入验证仍应使用自定义漏洞和测试用例。

### 6.4 Guardrails

Guardrails 是独立于红队编排的生产检查模块，提供输入和输出两个检查方向。README 列出：

- `ToxicityGuard`；
- `PromptInjectionGuard`；
- `PrivacyGuard`；
- `IllegalGuard`；
- `HallucinationGuard`；
- `TopicalGuard`；
- `CybersecurityGuard`。

红队测试用于发现风险，Guardrails 用于请求链路中的快速分类。Guardrails 的存在不代表可以替代完整授权、隔离、审计和应用层安全控制。

## 7. Python API

### 7.1 安装

```bash
pip install -U deepteam
```

根据分析基线的 `pyproject.toml`：

- Python 要求为 `>=3.9,<3.14`；
- 核心评估依赖为 `deepeval>=3.6.2`；
- CLI 入口为 `deepteam.cli.main:app`；
- Codex、Claude Code、Cursor 等 harness 支持为可选依赖。

### 7.2 最小示例

```python
from deepteam import red_team
from deepteam.vulnerabilities import Bias
from deepteam.attacks.single_turn import PromptInjection


async def model_callback(input: str) -> str:
    # 替换为实际的 LLM 应用调用
    return await my_application.ainvoke(input)


risk_assessment = red_team(
    model_callback=model_callback,
    vulnerabilities=[Bias(types=["race"])],
    attacks=[PromptInjection()],
)

risk_assessment.save("./results")
```

使用默认 OpenAI 模拟和评审模型时，需要配置相应 API 凭据。若使用其他模型，应通过 DeepEval 的模型接口显式传入。

### 7.3 关键参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `model_callback` | 必填 | 待测系统回调、模型对象或模型字符串 |
| `vulnerabilities` | `None` | 要测试的漏洞对象列表 |
| `attacks` | `None` | 要应用的攻击增强方法列表 |
| `framework` | `None` | 使用预定义安全框架代替手工组合 |
| `simulator_model` | `gpt-4o-mini` | 攻击生成模型 |
| `evaluation_model` | `gpt-4o-mini` | 结果评审模型 |
| `attacks_per_vulnerability_type` | `1` | 每个漏洞子类型生成的基础攻击数 |
| `run_all_attacks` | `False` | 是否将每种攻击应用到全部基础样本 |
| `async_mode` | `True` | 是否使用异步执行 |
| `max_concurrent` | `10` | 最大并发任务数 |
| `ignore_errors` | `True` | 是否将异常记录到用例并继续执行 |
| `target_purpose` | `None` | 目标用途说明，用于提高攻击生成针对性 |
| `exposure` | `Level.MEDIUM` | 项目风险评分使用的暴露等级 |

## 8. 结果模型与评分语义

### 8.1 `RTTestCase`

`RTTestCase` 继承 DeepEval 的 `LLMTestCase`，主要字段包括：

| 字段 | 含义 |
| --- | --- |
| `vulnerability` / `vulnerability_type` | 漏洞名称和子类型 |
| `input` | 最终攻击输入 |
| `actual_output` | 目标系统输出 |
| `turns` | 多轮对话记录 |
| `attack_method` | 使用的攻击增强方法 |
| `risk_category` | 安全框架风险类别 |
| `score` | 指标分数 |
| `reason` | 评审理由 |
| `error` | 生成、执行或评估错误 |
| `cvss_score` | 项目内风险分数 |
| `simulation_cost` / `evaluation_cost` | 攻击生成和评估成本 |
| `metadata` | 使用方附加元数据 |

### 8.2 通过率

当前结果聚合代码将 `score > 0` 的用例计为通过：

```text
pass_rate = passing / (total - errored)
```

错误用例不计入通过率分母。因此比较不同运行时，不能只看通过率，还应同时检查：

- 总用例数；
- 错误数和错误原因；
- 实际执行的攻击组合；
- 模拟模型与评审模型配置；
- 多轮攻击是否提前终止。

### 8.3 项目内 CVSS 评分

源码中的 `cvss.py` 使用固定权重计算 0–10 分：

```text
score = 10 × (0.6 × impact + 0.3 × exploitability + 0.1 × exposure)
```

其中 Low、Medium、High 分别映射为 0.3、0.6、0.9。当前实现将 Impact 固定为 Medium，Exploitability 根据攻击方法确定，Exposure 由运行参数指定；通过的测试用例记为 0 分。

因此，该数值应理解为 **DeepTeam 内部的简化风险排序指标**，不能直接等同于包含完整标准向量的官方 CVSS 评分。跨系统对比时应保留原始用例和评分依据。

## 9. 并发、成本与可重复性

### 9.1 并发

异步模式使用 `asyncio.Semaphore` 限制生成和增强任务的并发。`max_concurrent` 同时影响：

- 模型 API 请求压力；
- 目标系统负载；
- 总运行时间；
- 限流和失败概率。

接入真实 Agent 时，应从较低并发开始，并确保目标回调自身不会创建不受控的额外任务。

### 9.2 成本

一次完整运行可能同时产生三类成本：

1. 基础攻击生成；
2. 攻击增强及多轮推进；
3. 指标评审。

`run_all_attacks=True` 会以攻击方法数量放大后两类成本。多轮攻击还会进一步增加模型调用次数。测试预算应按完整组合数估算，而不是只按漏洞数量估算。

### 9.3 可重复性

动态模型生成、加权随机攻击选择和 LLM Judge 都会引入运行差异。用于回归测试时，建议：

- 固定 DeepTeam 与 DeepEval 版本；
- 固定模拟模型、评审模型及其生成参数；
- 保存完整 `RTTestCase`，而不只保留汇总通过率；
- 对关键缺陷补充固定测试用例；
- 同时报告样本数、错误数和攻击分布。

## 10. 数据与运行边界

“DeepTeam 在本地运行”主要指测试编排和结果处理在使用方机器上执行，并不表示整个流程默认离线。

接入敏感目标前需要检查：

- 默认模拟模型和评审模型是否调用外部 API；
- 攻击输入、目标输出及检索上下文是否被发送给第三方模型；
- 遥测与 Confident AI 平台集成是否启用，以及各自发送哪些字段；
- 结果 JSON 是否包含敏感提示词、个人信息或内部配置；
- 目标回调是否可能触发真实工具、写操作或外部请求；
- 并发测试是否会对目标服务造成超出预期的负载。

对涉及真实工具调用的 Agent，宜使用隔离凭据、受限测试环境和独立数据集。

## 11. 与当前 AI Agent 蜜罐项目的关系

### 11.1 能力互补

| DeepTeam | 当前蜜罐项目 |
| --- | --- |
| 主动模拟攻击者 | 构造诱饵并等待或引导 Agent 交互 |
| 生成单轮和多轮攻击 | 记录真实或模拟攻击轨迹 |
| 判断目标输出是否违反指标 | 分析 Agent 的侦察、利用、工具调用和决策行为 |
| 输出安全风险评估 | 输出指纹、归因、会话和行为分析 |

DeepTeam 可以作为当前项目的**攻击工作负载生成器和回归测试驱动器**，但不能直接替代蜜罐的交互记录与行为分析。

### 11.2 推荐接入方式

推荐先通过适配层连接，而不是修改 DeepTeam 内部实现：

```text
DeepTeam AttackSimulator
          │
          ▼
   model_callback 适配器
          │
          ▼
  当前项目目标 / 蜜罐交互接口
          │
          ├─ 返回诱饵响应给 DeepTeam
          │
          └─ 将完整输入、输出、轮次和工具事件写入现有遥测链路
```

适配层需要保留以下关联信息：

- DeepTeam 测试用例 ID 或本地生成的运行 ID；
- 漏洞类型和攻击方法；
- 对话轮次序号；
- 目标会话与传感器事件 ID；
- 模型、时间和错误信息。

### 11.3 评估边界

DeepTeam 的指标主要回答：

> 目标输出是否满足某个安全或内容指标？

蜜罐实验还需要回答：

> Agent 是否识别诱饵、采取侦察、尝试利用、调用工具、改变目标或传播信息？

二者不是同一个评价维度。即使诱饵输出被 DeepTeam 判为“不安全”，也不能据此推断攻击者已经上钩；同样，安全的文本响应也不代表 Agent 没有执行高风险工具调用。

因此，推荐采用双轨结果模型：

1. **DeepTrack**：沿用 DeepTeam 的漏洞分数、评审理由和攻击元数据；
2. **HoneyTrack**：沿用当前项目的会话事件、Agent 指纹、工具轨迹、诱饵命中和归因结果。

## 12. 适用场景与限制

### 12.1 适用场景

- LLM 应用上线前的安全测试；
- 系统提示词、模型或 Guardrails 变更后的回归；
- 对 Agent 工具权限和间接提示注入进行专项验证；
- 为蜜罐和靶标系统生成可配置的攻击流量；
- 按 OWASP 等框架建立初步风险覆盖清单。

### 12.2 主要限制

- LLM Judge 存在误判和运行间波动；
- 动态攻击生成不等同于固定、可完全复现的测试集；
- 默认外部模型配置可能带来数据边界和成本问题；
- 简化 CVSS 分数不宜直接作为跨组织风险结论；
- `ignore_errors=True` 可能掩盖接入、限流或生成失败；
- 文本输出指标不能完整覆盖副作用、工具调用和跨会话行为；
- 框架映射提供覆盖起点，不代表自动满足合规要求。

## 13. 建议的后续验证

在决定是否深度集成前，建议完成一个最小验证闭环：

1. 在隔离 Python 环境安装固定版本的 DeepTeam；
2. 使用单个漏洞和单轮攻击运行最小示例；
3. 检查原始 `RiskAssessment` JSON 和错误字段；
4. 将 `model_callback` 接到当前项目的测试目标；
5. 验证多轮回调的历史轮次和会话映射；
6. 对比 DeepTeam 指标与现有蜜罐行为标签；
7. 测量完整攻击组合的运行时间、模型成本和目标负载；
8. 根据结果决定采用依赖集成、适配器集成，还是仅借鉴攻击策略。

## 14. 参考资料

以下链接固定到本文分析的源码基线：

- [DeepTeam README](https://github.com/confident-ai/deepteam/blob/6306f0ff319a932955399405af82f78ee91e9370/README.md)
- [Python 包配置](https://github.com/confident-ai/deepteam/blob/6306f0ff319a932955399405af82f78ee91e9370/pyproject.toml)
- [顶层 `red_team()` API](https://github.com/confident-ai/deepteam/blob/6306f0ff319a932955399405af82f78ee91e9370/deepteam/red_team.py)
- [`RedTeamer` 核心编排](https://github.com/confident-ai/deepteam/blob/6306f0ff319a932955399405af82f78ee91e9370/deepteam/red_teamer/red_teamer.py)
- [`AttackSimulator`](https://github.com/confident-ai/deepteam/blob/6306f0ff319a932955399405af82f78ee91e9370/deepteam/attacks/attack_simulator/attack_simulator.py)
- [`BaseAttack`](https://github.com/confident-ai/deepteam/blob/6306f0ff319a932955399405af82f78ee91e9370/deepteam/attacks/base_attack.py)
- [目标回调包装与模型解析](https://github.com/confident-ai/deepteam/blob/6306f0ff319a932955399405af82f78ee91e9370/deepteam/red_teamer/utils.py)
- [`RTTestCase` 与 `RTTurn`](https://github.com/confident-ai/deepteam/blob/6306f0ff319a932955399405af82f78ee91e9370/deepteam/test_case/test_case.py)
- [`RiskAssessment` 与通过率统计](https://github.com/confident-ai/deepteam/blob/6306f0ff319a932955399405af82f78ee91e9370/deepteam/red_teamer/risk_assessment.py)
- [项目内 CVSS 计算](https://github.com/confident-ai/deepteam/blob/6306f0ff319a932955399405af82f78ee91e9370/deepteam/red_teamer/cvss.py)
