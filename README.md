# agent-trace-redactor

面向 AI Agent 开发者的 trace 脱敏工具。它可以读取 Codex、Claude Code、Cursor、自研 Agent 的会话 trace、工具调用日志、终端输出、文件片段、JSON/JSONL transcript，检测并脱敏 secret、PII、内部路径、客户域名、私有 repo URL，同时保留足够的调试上下文，输出 redacted bundle、安全 diff、审计报告和机器可读 JSON。

本项目优先使用 Python 标准库实现，兼容 Python 3.9+，可作为 CLI 使用，也可作为可导入 API 接入 CI、Agent 框架或内部安全流程。

## 典型场景

- 将 Agent 失败会话发给开源项目维护者前，移除 token、邮箱、私有仓库地址和本机路径。
- 在 CI 中扫描 AI 工具日志，发现敏感信息时用退出码阻断上传。
- 把 Codex、Claude Code、Cursor 或内部 Agent transcript 打包成可共享的 redacted bundle。
- 为安全审计生成 Markdown 报告和 JSON 报告，统计命中规则、类别、文件和占位符指纹。

## 安装

```bash
python -m pip install .
```

开发模式：

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
```

不依赖外网包。CLI 安装后提供两个命令名：

```bash
agent-trace-redactor --version
atr --version
```

## CLI 使用

扫描文件或目录并写出 bundle：

```bash
agent-trace-redactor scan examples -o redacted-bundle
```

输出 JSON 报告：

```bash
agent-trace-redactor scan examples --json --no-write
```

从 stdin 读取 JSONL transcript：

```bash
type examples\agent-session.jsonl | agent-trace-redactor scan --stdin --stdin-name session.jsonl --json --no-write
```

在 CI 中发现敏感信息时失败：

```bash
agent-trace-redactor scan . --fail-on-findings
```

校验配置：

```bash
agent-trace-redactor check-config examples/config.json
```

生成默认配置：

```bash
agent-trace-redactor default-config --pretty > redactor.config.json
```

### 退出码

- `0`：运行成功。
- `2`：启用 `--fail-on-findings` 且发现敏感信息。
- `3`：配置错误。
- `4`：输入错误，例如文件不可读、二进制文件或超过大小限制。
- `5`：其他运行时错误。

## 输出结构

默认 bundle 目录包含：

```text
redacted-bundle/
  manifest.json
  redacted/
    ...
  diffs/
    *.diff
  reports/
    report.json
    report.md
```

`redacted/` 保存脱敏后的文件。`diffs/` 是安全 diff，只展示 redacted 行和统计，不包含原始 secret。`reports/report.json` 是机器可读审计报告，包含文件摘要、命中规则、类别统计、稳定占位符和不可逆 fingerprint。

占位符示例：

```text
<SECRET_6E1C0D4CC4B8>
<PII_8C32E6DFD157>
<INTERNAL_PATH_2AD89F2E1221>
```

同一配置的 `hash_salt` 下，同一个敏感值会得到稳定占位符，便于复现调试；报告默认不包含原始敏感值。

## 规则配置

配置文件为 JSON：

```json
{
  "context_chars": 48,
  "hash_salt": "team-specific-salt",
  "preserve_json": true,
  "strict_json": false,
  "max_file_bytes": 10485760,
  "include_extensions": [".json", ".jsonl", ".log", ".txt", ".md", ".env"],
  "ignore_dirs": [".git", ".venv", "node_modules"],
  "disable_rules": ["phone"],
  "rules": [
    {
      "name": "internal_ticket",
      "pattern": "\\bACME-[0-9]{4,}\\b",
      "category": "internal_id",
      "description": "Internal ticket id",
      "flags": [],
      "enabled": true
    }
  ]
}
```

支持的 regex flags：`IGNORECASE`、`MULTILINE`、`DOTALL`。配置校验会拒绝未知字段、重复规则名、非法正则和类型错误。

默认规则覆盖：

- Secret：OpenAI/Anthropic 风格 API key、GitHub token、AWS key、Bearer token、常见 password/token/secret 赋值、PEM private key。
- PII：邮箱、电话号码。
- 内部网络：私有 IPv4。
- 内部路径：Windows 用户目录、Unix home、workspace/repo/src/tmp 路径。
- Repo：SSH/HTTPS 私有 repo URL。
- 客户或内部域名：包含 `corp`、`internal`、`customer`、`client`、`tenant`、`prod`、`staging`、`dev` 等提示词的域名。

## Python API

```python
from agent_trace_redactor import Redactor, redact_text

result = redact_text("Authorization: Bearer demoBearerTokenForDocsOnly123456")
print(result.text)
print(result.report.to_dict()["stats"])

redactor = Redactor()
bundle = redactor.write_bundle(["examples"], "redacted-bundle", zip_bundle=True)
print(bundle.output_dir, bundle.zip_path)
```

## CI / Agent 集成

GitHub Actions 示例：

```yaml
name: Redact agent traces
on: [pull_request]
jobs:
  redact:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install .
      - run: agent-trace-redactor scan agent-logs --fail-on-findings --json --no-write
```

Agent 工作流建议：

- 在上传失败 trace、工具调用日志或终端输出前运行 `agent-trace-redactor scan`。
- 对共享对象使用 `reports/report.json` 做二次 gate，例如禁止出现 `secret` 类命中。
- 为团队设置固定 `hash_salt`，让同一敏感值跨运行保持同一占位符，方便调试引用。
- 不要在 CI 中启用 `--reveal-placeholder-map`；该选项只用于本地排障，会把原始值写入报告。

## 限制

- 默认规则是保守启发式，不能保证发现所有 secret 或 PII。
- 正则规则可能误报，尤其是内部域名和 token-like 字符串。
- JSON/JSONL 会解析字符串叶子并重写格式；无效 JSON 在非 strict 模式下按普通文本脱敏。
- 二进制文件默认跳过并写入警告。
- 本工具负责降低共享 trace 的风险，不替代 secret rotation、访问控制或合规审查。

## 开发指南

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
python -m agent_trace_redactor.cli scan examples --json --no-write
```

项目结构：

```text
src/agent_trace_redactor/
  cli.py          CLI 与退出码
  api.py          可导入 API
  config.py       配置加载与校验
  defaults.py     默认规则
  engine.py       规则引擎与占位符替换
  formats.py      JSON/JSONL/文本解析
  io.py           输入扫描与 bundle 写出
  reporting.py    JSON/Markdown 报告
tests/            unittest 测试
examples/         安全样例数据
```

新增规则时请添加对应测试，确保报告不泄露原始敏感值，并确认 `--fail-on-findings` 的退出码行为。

---

# English

`agent-trace-redactor` is a Python 3.9+ CLI and importable API for redacting AI agent traces before they are shared. It targets Codex, Claude Code, Cursor, custom agents, tool-call logs, terminal output, file snippets, JSON transcripts, and JSONL transcripts.

It detects and redacts secrets, PII, internal paths, customer domains, private repository URLs, and private network hints while preserving reproducible debugging context. It writes a redacted bundle, safe diffs, a Markdown audit report, and a machine-readable JSON report.

## Use Cases

- Share a failed AI agent session with an open-source maintainer without leaking tokens, emails, paths, or private repos.
- Gate trace uploads in CI using a stable exit code.
- Package Codex, Claude Code, Cursor, or internal-agent transcripts into a safe redacted bundle.
- Produce audit reports for security review and downstream automation.

## Install

```bash
python -m pip install .
```

For development:

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
```

No third-party runtime dependencies are required.

## CLI

```bash
agent-trace-redactor scan examples -o redacted-bundle
agent-trace-redactor scan examples --json --no-write
agent-trace-redactor scan . --fail-on-findings
agent-trace-redactor check-config examples/config.json
agent-trace-redactor default-config --pretty
```

Read from stdin:

```bash
cat examples/agent-session.jsonl | agent-trace-redactor scan --stdin --stdin-name session.jsonl --json --no-write
```

Exit codes:

- `0`: success.
- `2`: findings detected when `--fail-on-findings` is enabled.
- `3`: invalid config.
- `4`: input error.
- `5`: runtime error.

## Configuration

Config files are JSON. You can disable defaults and add custom regex rules:

```json
{
  "context_chars": 48,
  "hash_salt": "team-specific-salt",
  "preserve_json": true,
  "strict_json": false,
  "disable_rules": ["phone"],
  "rules": [
    {
      "name": "internal_ticket",
      "pattern": "\\bACME-[0-9]{4,}\\b",
      "category": "internal_id",
      "description": "Internal ticket id",
      "flags": [],
      "enabled": true
    }
  ]
}
```

Supported flags are `IGNORECASE`, `MULTILINE`, and `DOTALL`. Validation rejects unknown keys, duplicate rule names, invalid regexes, and wrong value types.

## Python API

```python
from agent_trace_redactor import Redactor, redact_text

result = redact_text("token" + "=" + "demoTokenForDocsOnly123")
print(result.text)
print(result.report.to_dict()["stats"])

redactor = Redactor()
bundle = redactor.write_bundle(["examples"], "redacted-bundle")
print(bundle.output_dir)
```

## CI and Agent Integration

Use `agent-trace-redactor scan <trace-dir> --fail-on-findings` before uploading or publishing trace artifacts. Store `reports/report.json` as an audit artifact, and gate on categories such as `secret` if your workflow needs stricter policy.

Do not use `--reveal-placeholder-map` in CI; it intentionally includes original values and is only meant for local debugging.

## Limitations

The default rules are conservative heuristics and cannot guarantee full secret or PII discovery. Regex rules can produce false positives. JSON/JSONL inputs are parsed and reserialized when `preserve_json` is enabled. Binary files are skipped with warnings. This tool reduces trace-sharing risk but does not replace credential rotation, access control, or compliance review.
