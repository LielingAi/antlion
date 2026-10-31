# 武器插件架构与开发指南

## 1. 架构原则

arsenal v6 将武器拆成三个正交部分：

- **Manifest（`weapon.json`）**：描述插件身份、版本、能力、配置约束和遥测契约。
- **Script（`weapon.py`）**：实现提示词渲染、漏洞响应、MCP 描述、CLI 指令或 CVE 载荷行为。
- **Arsenal 记录**：保存插件引用、实例配置、激活状态、生命周期和效能档案。

核心约束：数据库和 Hive→Sensor 配置通道不保存或传输可执行源码。

```text
Hive Arsenal DB                weapon_packs                 Sensor
插件引用 + 配置 + 状态   →     版本与包哈希校验       →     WeaponRuntime
                                                        原子应用 / 路由挂载
                                                        会话版本固定 / 执行遥测
```

## 2. 目录与职责

| 位置 | 职责 |
| --- | --- |
| `core/weapon_plugins/models.py` | Manifest、调用上下文和结构化结果 |
| `core/weapon_plugins/base.py` | 生命周期与分能力接口 |
| `core/weapon_plugins/loader.py` | 包发现、导入、哈希计算、失败时保留旧定义 |
| `core/weapon_plugins/runtime.py` | 实例化、原子切换、版本固定、超时和异常隔离 |
| `core/weapon_plugins/cve.py` | CVE 目录、启停、框架和攻击族匹配 |
| `core/weapon_plugins/telemetry.py` | 结构化执行日志 |
| `core/arsenal.py` | 配置真相源、迁移、校验、试射和下发 |
| `core/arsenal_mount.py` | 漏洞路由与旧 HTTP 元组适配 |
| `weapon_packs/` | 独立武器脚本包 |

## 3. 武器包格式

```text
weapon_packs/example/
├── weapon.json
├── weapon.py
└── templates/          # 可选
```

Manifest 使用 JSON，避免为简单声明引入额外 YAML 依赖：

```json
{
  "id": "vuln.example",
  "name": "示例漏洞插件",
  "version": "1.0.0",
  "api_version": 1,
  "class": "vuln",
  "mount": "delivery",
  "stage": "sensor",
  "entrypoint": "weapon.py:Plugin",
  "config_schema": {
    "required": ["body"],
    "properties": {"body": {"type": "string"}}
  },
  "trigger": {},
  "telemetry": {"expect": ["vuln_mounted"]},
  "world_constraints": ["相同输入产生相同输出"]
}
```

`config_schema` 当前支持 `required` 和 `properties` 中的 `string`、`object`、`array`、`boolean`、`number`、`integer` 类型校验。

## 4. 插件接口

所有插件继承 `WeaponPlugin`，获得：

- `validate()`：配置校验；
- `activate(context)`：激活；
- `deactivate()`：停用；
- `manifest`、`record`、`config` 和 `weapon_id`。

按能力选择子类：

| 接口 | 方法 | 用途 |
| --- | --- | --- |
| `PromptWeaponPlugin` | `render(context)` | 单轮或多轮提示词 |
| `VulnWeaponPlugin` | `handle(context)` | 请求驱动的漏洞响应 |
| `MCPWeaponPlugin` | `describe(tools, context)` | 工具名录和描述编排 |
| `CLIWeaponPlugin` | `next_instruction(context)` | sensor/deep 阶段指令 |
| `CVEWeaponPlugin` | `craft_payload(beacon_server, **kwargs)` | CVE 载荷生成 |

最小漏洞插件：

```python
from core.weapon_plugins.base import VulnWeaponPlugin
from core.weapon_plugins.models import WeaponResult


class Plugin(VulnWeaponPlugin):
    def handle(self, context):
        body = str(self.config["body"])
        return WeaponResult.http(body, content_type="text/plain")
```

插件不得直接操作 socket 或 HTTP writer。`main.py` 负责协议写出，插件只返回 `WeaponResult`。

## 5. Arsenal 实例配置

一条武器记录通过 `plugin` 引用实现：

```json
{
  "id": "VULN-EXAMPLE-1",
  "name": "示例武器",
  "class": "vuln",
  "type": "vuln",
  "stage": "sensor",
  "mount": "delivery",
  "enabled": false,
  "lifecycle": "staged",
  "plugin": "vuln.example",
  "plugin_version": "1.0.0",
  "config": {"body": "example response"},
  "vuln": {
    "program": "example-service",
    "deploy": {"world_endpoint": "/api/example"}
  }
}
```

简单静态文本不需要独立 Python 包，可使用：

- `builtin.template_prompt`
- `builtin.template_http`
- `builtin.template_cli`
- `builtin.static_mcp_description`

声明式 EXP 链继续由 `core/exp_tracker.py` 执行，不强制包装成 Python 插件。

## 6. 加载、激活与热重载

执行顺序：

```text
发现 → Manifest 校验 → 导入与接口校验 → 配置校验 → 激活 → 路由/挂载
```

加载器先构建新定义表，再原子替换。某个包损坏时：

- 其他包不受影响；
- 损坏包保留上一次可用定义；
- 错误通过 `/api/weapon_plugins` 和控制台暴露。

运行时同样先准备完整武器快照再切换。无效实例进入 `snapshot.errors`，不会把已有有效实例清空。

多轮会话第一次调用武器时固定 `插件版本 + 配置哈希`。热重载后：

- 旧会话继续使用固定版本；
- 新会话使用新版本；
- `release_session(session_id)` 释放固定关系并回收无用实例。

## 7. 包哈希与下发

加载器对包内文件计算 SHA-256。Hive 下发激活武器时附带：

- `plugin`
- `plugin_version`
- `package_hash`
- `config`
- `enabled`
- `lifecycle`

Sensor 发现本地包哈希与下发值不一致时拒绝激活该实例并记录错误。配置通道不执行源码，也不自动安装依赖。

Python 插件属于可信代码，包审查和制品分发必须在进入插件目录前完成。

## 8. 超时、异常与遥测

每次执行返回结构化元数据：

- `weapon_id`
- `plugin_version`
- `session_id`
- `mount`
- `duration`
- `ok`
- `error`

执行日志写入 `cm_actions`，`detail` 以 `[weapon:id]` 开头，后附 JSON。插件自定义事件放在 `events` 中，不将敏感载荷写入默认元数据。

超时通过受控线程执行器实现，超时后调用方收到 `plugin execution timeout`。Python 无法安全强杀任意线程，因此耗时后台调用可能继续至自然结束；插件不得借此实现不受控任务。

## 9. 管理 API

`POST /api/arsenal` 支持：

- `save`：保存声明与实例配置；
- `toggle`：校验后激活或停用；
- `delete`：删除记录；
- `validate`：校验插件和配置；
- `test_fire`：在独立运行时试射；
- `reload`：重新发现插件包并应用当前记录。

`GET /api/weapon_plugins` 返回插件版本、包哈希、加载错误和激活错误。

`POST /api/weapon_plugins/upload` 供管理员上传 ZIP 包，JSON 字段为 `filename` 和 `content_base64`。服务端执行以下校验：

- ZIP 最大 1 MiB、最多 32 个文件，解压后最大 2 MiB；
- 拒绝绝对路径、目录穿越、符号链接和已有包覆盖；
- 必须包含唯一的 `weapon.json` 和 manifest 指定的入口 Python 文件；
- 入口源码语法检查及临时目录加载检查；
- 原子安装并热重载，失败时清理临时文件。

## 10. 新增武器步骤

可以通过控制台或直接写包：

1. 编写 `weapon.json` 和能力接口实现，并打成 ZIP；也可直接在 `weapon_packs/` 新建包目录。
2. 为插件增加独立测试，覆盖配置错误、执行结果和异常。
3. 在武器库点击“上传包”安装，或点击“重载插件”加载本地目录。
4. 新建武器，在“实现插件”下拉框中选择上传的插件。
5. 创建 Arsenal 记录并调用 `validate`。
6. 调用 `test_fire`，检查世界一致性和结构化结果。
7. 激活记录，验证 Hive→Sensor 哈希和挂载状态。
8. 检查执行日志、错误率和效能数据后再扩大使用。

## 11. 验证命令

```bash
py -3.13 -m pytest tests/test_weapon_plugins.py -q
py -3.13 -m pytest tests/test_engines.py -q
py -3.13 -m pytest -q
node --check static/js/views.js
```
