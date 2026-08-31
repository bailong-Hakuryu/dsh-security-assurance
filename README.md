# DSH Security Assurance

> DeepSeek Harness 的策略驱动仓库安全评估插件 · 中文默认，English below

[![Release](https://img.shields.io/github/v/release/bailong-Hakuryu/dsh-security-assurance?display_name=tag)](https://github.com/bailong-Hakuryu/dsh-security-assurance/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

<p align="center">
  <img src="assets/hero-security-assurance.png" alt="安全评估主视觉" width="100%">
</p>

## 中文

### 这是什么

<code>dsh-security-assurance</code> 为 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) 提供证据驱动的仓库安全评估。它通过公开的 Harness/Cordis 接口接入，不修改 Harness Core，并把评估过程封装为可查询、可恢复、可审计的版本化结果。

这是一个安全保障插件，不是通用漏洞扫描器。当前内建策略针对 Node 项目的 <code>package.json</code> 安装生命周期键存在性进行检查。

### 当前版本

- 版本：<code>0.1.0-rc.10</code>
- 状态：Release Candidate（预发布版）
- 适配：DeepSeek Harness <code>0.1.2-alpha.1</code>
- GitHub：[v0.1.0-rc.10 Release](https://github.com/bailong-Hakuryu/dsh-security-assurance/releases/tag/v0.1.0-rc.10)

### 支持范围

| 项目 | 当前状态 |
| --- | --- |
| 评估模式 | <code>REPOSITORY</code> |
| 支持 Subject | <code>git_revision</code>、<code>workspace_snapshot</code> |
| <code>CHANGE</code> 模式 | 暂不支持 |
| <code>TARGETED</code> 模式 | 暂不支持 |
| 默认策略 | <code>security/node-package-lifecycle</code> |
| 默认档案 | <code>security/standard</code> |
| 支持平台 | Windows、Linux、macOS |

评估会先读取当前 Host 注册的 Repository 和 Catalog；只有 Service 返回的精确 ID、模式、Subject、Target、Profile 和强化控制才能用于启动，不允许模型猜测路径或标识符。

### 安装（Harness Web）

兼容 DeepSeek Harness <code>0.1.2-alpha.1</code>，要求 Node.js <code>^22.19.0 || >=24.0.0</code> 和 Harness CLI。将终端当前目录设为要评估的 Git 仓库，然后直接安装 GitHub Release 中已经构建的包：

~~~powershell
dsh plugin --profile web add https://github.com/bailong-Hakuryu/dsh-security-assurance/releases/download/v0.1.0-rc.10/dsh-security-assurance-0.1.0-rc.10.tgz
dsh --profile web --dump-config
dsh web
~~~

也可以先在 Release 页面下载 <code>dsh-security-assurance-0.1.0-rc.10.tgz</code>，再把上面 URL 换成本地文件的绝对路径。

如果还要使用工程 Mission 门禁，请先安装 [Engineering Control Plane](https://github.com/bailong-Hakuryu/dsh-engineering-control-plane/releases/tag/v0.1.9)，再安装本插件：

~~~powershell
dsh plugin --profile web add D:\Downloads\dsh-engineering-control-plane-0.1.9.tgz
dsh plugin --profile web add https://github.com/bailong-Hakuryu/dsh-security-assurance/releases/download/v0.1.0-rc.10/dsh-security-assurance-0.1.0-rc.10.tgz
dsh --profile web --dump-config
dsh web
~~~

插件会把启动时的工作目录注册为 <code>current-workspace</code>。启动后建议先用 <code>dsh --profile web --dump-config</code> 检查组合；如果端口已被占用，请在 Harness Profile 中选择其他空闲端口。

### 用户如何调用

插件同时支持被动路由和主动指令：

**被动调用（推荐）**：直接描述目标，模型会先获取可用仓库和评估目录，再按服务返回的选择启动评估。

~~~text
请对当前仓库进行安全评估，并报告最终 Verdict 和 Findings。
检查当前项目的 package.json 安装生命周期配置。
~~~

**主动调用**：在 Harness Web 或 CLI 输入：

~~~text
/security 评估当前仓库
/security 检查当前仓库的包安装生命周期
~~~

### 工具工作流

| 顺序 | 工具 | 作用 |
| --- | --- | --- |
| 1 | <code>security_repositories</code> | 列出当前会话可见的已授权仓库 |
| 2 | <code>security_catalog</code> | 获取指定仓库支持的模式、Subject、Profile 和控制 |
| 3 | <code>security_assessment_start</code> | 用精确选择启动一次持久化评估 |
| 4 | <code>security_assessment_status</code> | 读取版本化状态、Coverage 和 Verdict |
| 5 | <code>security_assessment_findings</code> | 分页读取脱敏 Finding 摘要 |
| 6 | <code>security_assessment_resume</code> | 仅按服务公布的合法动作恢复阻塞评估 |
| 7 | <code>security_assessment_cancel</code> | 按精确 revision 取消并等待外部工作静默 |
| 8 | <code>security_assessment_export</code> | 请求固定格式、固定目标的官方导出 |

推荐顺序是 <code>repositories → catalog → start → status → findings</code>。变更操作使用服务返回的精确 <code>revision</code> 和新的 <code>idempotency_key</code>；旧请求不会被自动重放。

### 返回结果与安全边界

- 所有公共操作返回统一的 <code>SecurityResult&lt;T&gt;</code> envelope。
- 命令返回不可变、带版本的 Receipt；查询返回按身份和 revision 绑定的 Snapshot。
- Findings、Evidence 和导出内容遵循宿主授权、用途和脱敏规则。
- 模型参数不接受凭据、数据库句柄、绝对路径或可执行对象；身份和权限由 Host 当前会话解析。
- Registry、Assessment、Evidence 和导出状态保存在插件私有 SQLite 中，使用幂等键与 revision CAS 防止重复执行。
- 缺失授权、状态冲突、超时、取消或外部失败会 fail closed，不会伪造满足结论。
- <code>workspace_snapshot</code> 只应对用户明确授权的仓库运行；祖先符号链接/联结会被拒绝，Subject 符号链接只登记不解引用，Git 通过 Harness 受管子进程边界执行。详见 [SECURITY-REVIEW.md](SECURITY-REVIEW.md)。

### 与 Engineering Control Plane 联用

两插件联用时，Control Plane 负责 Mission、工程 Evidence 和最终 Quality Gate；本插件只负责外部安全义务及其证据提交。安全评估失败或不确定会阻塞 Gate，但不会被转换成工程批准。

安装两者后，Control Plane 的可选 Provider 会按精确的 Provider ID、版本和 <code>current-workspace</code> 绑定本插件。两个插件不共享 SQLite、可写 Evidence 路径、事务或 Kernel 对象。

### 公开入口

| 入口 | 作用 |
| --- | --- |
| <code>dsh-security-assurance</code> | 根 Security Assurance Service |
| <code>dsh-security-assurance/tools</code> | 八个严格模型工具 |
| <code>dsh-security-assurance/contracts</code> | 版本化公共契约 |
| <code>dsh-security-assurance/analyzer</code> | 内建分析器接口 |
| <code>dsh-security-assurance/evaluation</code> | 纯函数 Metrics Engine |
| <code>dsh-security-assurance/host-repository-provider</code> | Host Repository 注册适配器 |
| <code>dsh-security-assurance/control-plane-provider</code> | 可选 Control Plane 适配器 |
| <code>dsh-security-assurance/invariant</code> | 启动就绪诊断 |
| <code>dsh-security-assurance/workbench-remote</code> | 需要部署方认证解析器，默认禁用 |

### 常见排查

**仓库列表为空**：从目标 Git 仓库目录启动 Harness，并确认 Host Repository Provider 已加载；不要手工编造 Repository ID。

**Catalog 显示 UNSUPPORTED**：当前只支持 <code>REPOSITORY</code> 模式；确认使用的是已授权仓库和 <code>security/standard</code> Profile。

**端口冲突**：关闭占用端口的旧 Harness 进程，或在 Web Profile 中改用空闲端口后重新启动。

**评估为 BLOCKED**：先读取 <code>security_assessment_status</code> 的 <code>legalNextActions</code>，只执行服务允许的 <code>resume</code> 或 <code>cancel</code>。

### 开发与验证

~~~powershell
pnpm install
pnpm lint
pnpm typecheck
pnpm build
pnpm test
pnpm pack:dry-run
pnpm pack:profile-smoke
pnpm release:check
~~~

当前 <code>main</code> 分支发布门禁已通过：70 个测试文件、349 个测试，静态检查、类型检查、构建、打包和 Harness Profile smoke 均通过。

完整领域模型见 [CONTEXT.md](CONTEXT.md)，安全政策见 [SECURITY.md](SECURITY.md)，候选版审查见 [SECURITY-REVIEW.md](SECURITY-REVIEW.md)。

<details>
<summary>English</summary>

## What it is

<code>dsh-security-assurance</code> is an evidence-backed repository security assessment plugin for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness). It integrates through public Harness and Cordis seams without modifying Harness Core, and exposes versioned, queryable, recoverable assessment results.

This is an assurance plugin, not a general vulnerability scanner. The built-in policy currently checks the presence of Node package install-lifecycle keys in <code>package.json</code>.

## Current release

- Version: <code>0.1.0-rc.10</code>
- Status: release candidate
- Target Harness: <code>0.1.2-alpha.1</code>
- Release: [v0.1.0-rc.10](https://github.com/bailong-Hakuryu/dsh-security-assurance/releases/tag/v0.1.0-rc.10)

## Support matrix

| Item | Status |
| --- | --- |
| Assessment mode | <code>REPOSITORY</code> |
| Subjects | <code>git_revision</code>, <code>workspace_snapshot</code> |
| <code>CHANGE</code> | Not currently supported |
| <code>TARGETED</code> | Not currently supported |
| Default policy | <code>security/node-package-lifecycle</code> |
| Default profile | <code>security/standard</code> |
| Platforms | Windows, Linux, macOS |

The Service resolves authorized repositories and catalog choices first. Models must use the exact returned identifiers; paths and IDs are never guessed.

## Install in Harness Web

Compatible with DeepSeek Harness <code>0.1.2-alpha.1</code>. Requires Node.js <code>^22.19.0 || >=24.0.0</code> and the Harness CLI. Install the prebuilt GitHub Release package directly:

~~~powershell
dsh plugin --profile web add https://github.com/bailong-Hakuryu/dsh-security-assurance/releases/download/v0.1.0-rc.10/dsh-security-assurance-0.1.0-rc.10.tgz
dsh --profile web --dump-config
dsh web
~~~

Alternatively, download <code>dsh-security-assurance-0.1.0-rc.10.tgz</code> from the Release page and pass its absolute local path to the same command.

When both plugins are installed, install Engineering Control Plane first because it supplies the shared invariant registry. The launcher working directory is registered as <code>current-workspace</code>.

## Invocation

Natural-language requests are routed through the catalog-first workflow. Users can also run:

~~~text
/security Assess the current repository and report the final verdict and findings.
~~~

The eight tools are <code>security_repositories</code>, <code>security_catalog</code>, <code>security_assessment_start</code>, <code>security_assessment_status</code>, <code>security_assessment_findings</code>, <code>security_assessment_resume</code>, <code>security_assessment_cancel</code>, and <code>security_assessment_export</code>. The normal order is repositories, catalog, start, status, and findings. Mutations require the exact Service revision and a fresh idempotency key.

## Results and safety

All public operations return a typed <code>SecurityResult&lt;T&gt;</code> envelope. Commands return immutable versioned Receipts; queries return identity- and revision-bound Snapshots. Host authority resolves identity and permissions; model arguments never carry credentials, paths, database handles, or executable objects. Missing authorization, conflicts, timeouts, cancellation, and external failures fail closed.

Run <code>workspace_snapshot</code> only for repositories the user explicitly authorizes. Ancestor links are rejected, Subject symlinks are inventoried without dereference, and Git runs through the Harness-managed subprocess boundary. See [SECURITY-REVIEW.md](SECURITY-REVIEW.md).

## Control Plane integration

Engineering Control Plane owns the Mission, engineering Evidence, and final Quality Gate. Security Assurance owns the external security obligation and its evidence. An unavailable, failed, or indeterminate security result blocks the Gate; it is never converted into approval. The two plugins do not share SQLite files, writable Evidence paths, transactions, or Kernel objects.

## Development

~~~powershell
pnpm install
pnpm lint
pnpm typecheck
pnpm build
pnpm test
pnpm pack:dry-run
pnpm pack:profile-smoke
pnpm release:check
~~~

The current <code>main</code> branch gate passes with 70 test files and 349 tests, including linting, typecheck, build, packaging, and Harness profile smoke.

</details>

## License

[MIT](LICENSE)
