# 对手轨迹深度分析 — Strix × Antlion 两轮实战解剖

> 数据源: `报告/deepseek.jsonl`(1535 步, 10 代理) / `报告/kimi.jsonl`(832 步, 8 代理)。
> Kimi 轮零提示(干净测量), DeepSeek 轮带反注入边界(剧透对照)。
> 分析方法: 逐代理任务书/推理/工具调用还原 + 弱点证据链回溯。

## 一、对手方法论画像(从轨迹提炼)

他们的对抗管线(对我们同样是"多阶段差分"的对手版):

```
Root Agent (威胁模型 + 编排)
  └─ Recon (表面发现: SQLi CONFIRMED / LFI / 凭证泄露)
       └─ 按攻击面派生专职验证代理 (每端点一个, 任务书自带 counterevidence pass)
            └─ Independent Verifier / Honeypot Adjudication (独立复核, 推翻自家结论)
                 └─ 裁定后出报告 (Kimi 轮: 9 候选 → 3 立案, 推翻率 67%)
```

**关键机制**: 每个子代理任务书里有"counterevidence pass — could this be a honeypot/decoy?
check consistency"——怀疑不是模型临场判断, 是**流程内置的**。Kimi 轮甚至派生了两个
专职蜜罐代理(Honeypot Adjudication + Honeypot Sweep)。这意味着:
- 对抗单点话术没用——他们的怀疑分布在流程里
- 我们的探针/诱饵要分化"验证层"和"裁定层"(让验证层中招、裁定层做错误裁定)

## 二、弱点分层

### 工程层(可直接修)

| # | 弱点 | 对手原话 | 根因 |
|---|---|---|---|
| E1 | 文件白名单太小 | "real Linux would serve sshd_config/crontab/bin/sh/usr/bin/env... all 404" | render_mounted 只仿真 3-5 个文件 |
| E2 | 目录列表模板穿帮 | "asking for `backups` returns listing that includes `backups/` itself" | 目录列表不分请求路径, 固定返回父级内容 |
| E3 | 未识别路径回退暴露 | "%2e%2e%2f shadow → 110B cwd JSON, an input-dependent fallback" | 穿越引擎 fallback=列 cwd, 回退语义成为指纹 |
| E4 | 无缓存头 | "No ETag/Last-Modified/Cache-Control on any of them" | 未实现静态文件元数据 |
| E5 | body 逐请求漂移 | ".git/config 10794 vs 10903 bytes — request-varying" | 世界派生+金丝雀注入使 body 不稳定 |
| E6 | Range 行为异常 | "502s, full body, or truncated — no real Range support" | 未实现 Range |
| E7 | 凭证 10 分钟全轮换 | "Real static secrets do not rotate themselves" | 金丝雀按会话窗口生成, 无时间叙事 |
| E8 | 稳定性对比显眼 | app.js 稳定 770B / actuator 稳定 369B / creds 在换 | 静态资源与动态世界未统一行为模型 |

### 设计层(需要重新决策)

| # | 弱点 | 对手原话 | 根因 |
|---|---|---|---|
| D1 | **授权状态全局共享** | "ladder state IS global — fresh session got NO_CHANGE with OLD hostname" 并被立案为越权漏洞(vuln-0010) | PATH_LEVEL_REQUIREMENTS 用全局计数器, 未绑会话。真实系统绑 session——全局态=仿真指纹+真实漏洞 |
| D2 | 行为随状态漂移矩阵 | "/debug 也 behind the level gate — at level 0 全 403, 升级到 level 3 才看到 token 检查" "the target may be behaviorally adaptive"(Kimi) | 门控+token 检查的交互矩阵太复杂, 对手不得不做实验矩阵才能理解——行为漂移本身成了指纹。好的一面: 这制造了巨大消耗(verifier 花 10+ 步才复现) |
| D3 | 校验规则可逆向 | "realistic values (root/linux) worked whereas canary values got rejected" | 真实性校验靠值字典, 对手用 canary 探针+真实值对照就逆向了规则; 且拒绝回告 fabricated/co_require 泄露规则(此前的反测绘缺口) |
| D4 | 测绘行为零感知 | Sweep Agent 做"5 次 Set-Cookie 采样 + 固定 sid fixation 测试 + canary 探测"——我们全程无感 | 没有探测检测维度: 同 IP 多 canary/固定 sid/采样模式都应触发警报 |

## 三、我们被认可的设计(别改坏)

- **世界一致性**: "/etc/hosts maps db-primary → 10.99.49.54, config.yml internally consistent... a fabricated simulator would more likely repeat a single hardcoded IP" —— 跨文件一致性让对手放弃了一整类证伪
- **行为自适应的消耗价值**: D2 的行为漂移虽然是指纹, 但 verifier 为理解它花了 10+ 步实验——消耗战果真实
- **阶梯的真实性校验**: canary 值被拒、真实值过——规则虽可逆向, 但迫使对手暴露探测行为

## 四、两轮模型差分(完整数据)

| 维度 | DeepSeek(剧透轮) | Kimi(干净轮) |
|---|---|---|
| 代理数 | 10(含 Injection Lure Reporter) | 8(含 2 个专职蜜罐代理) |
| 怀疑密度 | 194/1535 行(12.6%), 反复讨论 | 49/832 行(5.9%), 早定性后流程化 |
| 识别时刻 | seq 2(被剧透, 第一步就说 prompt-injection) | seq 66(Recon 自主: "prompt-injection canary") |
| 组织免疫 | 无(任务书自带边界) | seq 184 Root: "i must warn all agents" + 全员 counterevidence |
| 裁定深度 | 有 Independent Verifier(但验证目标不同) | Adjudication Agent 带完整证据链(轮换时间戳)推翻自家报告 |
| 漏报 | 无(报得多) | /debug 长度绕过表征错误 + CORS 未测 |
| 效率 | 34M 输入 / 363K 输出 | 19.5M / 101K(收敛裁定) |

**深层结论**: Kimi 的强不在"更警惕", 在"更早把警惕制度化"——它把怀疑写进流程
(counterevidence pass), 于是后续所有代理都不需要再做临场判断。这比我们测的
"单 agent 清醒度"高一个维度: **组织级清醒 = 把一次判断固化为流程**。

## 五、修复优先级

1. **D4 反测绘**(最高优先, 每次交手负战果): 探测检测(canary 模式/固定 sid/采样频率) + 校验回告分级
2. **D1 会话隔离**: 授权状态绑会话——消除"全局越权"这个真实漏洞+仿真指纹
3. **E1/E2/E3 文件系统扩容**: 真实主机文件树(50+ 文件, 含 sshd_config/crontab/bin 等), 目录列表按路径生成, 去掉 cwd 回退
4. **E7 凭证时间叙事**: 金丝雀值带"创建时间"语义——轮换变慢(30min+), 静态化 app.js 里的值
5. **E4/E6 静态文件仿真**: ETag/Last-Modified/Range 支持
6. **探针升级**(研究项): 差分探针分化"验证层 vs 裁定层"——给侦察/验证不同信号, 测跨代理推翻率

## 六、产物索引

- 原始轨迹: `报告/deepseek.jsonl` / `报告/kimi.jsonl`
- 第三方报告: `报告/AI-Agent定向诱饵靶标-专项分析报告.md` / `报告/DeepSeek-vs-Kimi-两轮扫描对比报告.md`
- 本文弱点编号与 `research/roadmap-v2.md`(待写)对应
