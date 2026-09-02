# DSH Security Assurance

> DeepSeek Harness 的策略驱动仓库安全评估插件 · 中文默认，English below

[![Release](https://img.shields.io/github/v/release/bailong-Hakuryu/dsh-security-assurance?display_name=tag)](https://github.com/bailong-Hakuryu/dsh-security-assurance/releases)
[![Harness Compatibility](https://github.com/bailong-Hakuryu/dsh-security-assurance/actions/workflows/harness-compat.yml/badge.svg)](https://github.com/bailong-Hakuryu/dsh-security-assurance/actions/workflows/harness-compat.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

<p align="center">
  <img src="assets/hero-security-assurance.png" alt="安全评估主视觉" width="100%">
</p>

## 中文

### 这是什么

<code>dsh-security-assurance</code> 为 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) 提供证据驱动的仓库安全评估。它通过公开的 Harness/Cordis 接口接入，不修改 Harness Core，并把评估过程封装为可查询、可恢复、可审计的版本化结果。

这是一个安全保障插件，不是通用漏洞扫描器。当前内建能力包括 Node 项目的 <code>package.json</code> 安装生命周期检查，以及对冻结 <code>npm-audit.json</code> 报告的纯归一化与独立验证。

### 当前版本

- 版本：<code>0.1.0-rc.10</code>
- 状态：Release Candidate（预发布版）
- 适配：DeepSeek Harness <code>0.1.2-alpha.1</code>（主目标）；<code>0.1.2-alpha.2</code> ~ <code>0.1.2-alpha.4</code> 经兼容矩阵验证
- GitHub：[v0.1.0-rc.10 Release](https://github.com/bailong-Hakuryu/dsh-security-assurance/releases/tag/v0.1.0-rc.10)

### 支持范围

| 项目 | 当前状态 |
| --- | --- |
| 评估模式 | <code>REPOSITORY</code>、精确提交或 Mission 产出工作区的 <code>CHANGE</code> |
| 支持 Subject | <code>git_revision</code>、<code>workspace_snapshot</code>、<code>change</code>（精确 base/head）；Control Plane 可使用 Host 专用 <code>workspace_change</code> |
| <code>CHANGE</code> 模式 | 支持精确已提交的 base→head，以及 Control Plane 冻结的 baseline→produced workspace；均扫描完整结果树 |
| <code>TARGETED</code> 模式 | 暂不支持 |
| 默认策略 | <code>security/node-package-lifecycle</code> |
| 可选 npm audit 策略 | <code>security/npm-dependency-audit</code> |
| 默认档案 | <code>security/standard</code> |
| Harness 版本 | <code>0.1.2-alpha.1</code>（主）、<code>0.1.2-alpha.2</code>、<code>0.1.2-alpha.3</code>、<code>0.1.2-alpha.4</code> |
| Node.js | <code>^22.19.0 \|\| >=24.0.0</code>（CI 覆盖 22 与 24） |
| 支持平台 | Windows、Linux、macOS |

评估会先读取当前 Host 注册的 Repository 和 Catalog；只有 Service 返回的精确 ID、模式、Subject、Target、Profile 和强化控制才能用于启动，不允许模型猜测路径或标识符。

Harness 支持窗口是一个显式的已验证集合：每日 [Harness Compatibility](https://github.com/bailong-Hakuryu/dsh-security-assurance/actions/workflows/harness-compat.yml) 工作流自动发现官方仓库标签，对主目标在 Ubuntu、macOS、Windows 上、对其余版本在 Ubuntu 上执行双插件联合 E2E（Mission → Developer 工作区变更 → CHANGE Assessment → sealed submission → Quality Gate）和打包 fresh Profile 安装加 Web 探针。新标签会自动进入验证，但未通过矩阵验证前不会被声明支持（ADR 0310）。

独立工具与 Workbench 的 Catalog 契约保持不变，只向模型提供精确提交 <code>change</code>。当 Control Plane 完成 Developer 与 Implementation Evidence 后，Provider 会从不可伪造的执行上下文接收 Host 专用 <code>workspace_change</code>，同时核对分支、baseline HEAD、Git 状态指纹、逐字节产出变更指纹与完整结果树；任何漂移都会在创建 Assessment 前 fail closed。

### 安装（Harness Web）

兼容 DeepSeek Harness <code>0.1.2-alpha.1</code> ~ <code>0.1.2-alpha.4</code>（显式已验证集合，见上方支持范围），要求 Node.js <code>^22.19.0 || >=24.0.0</code> 和 Harness CLI。将终端当前目录设为要评估的 Git 仓库，然后直接安装 GitHub Release 中已经构建的包：

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

### npm audit 报告适配

npm audit 由 Host、CI 或操作者在评估外部执行；插件不会在 PURE 分析边界内启动 npm、访问 Registry 或读取实时网络状态。先生成 UTF-8 报告，并确保它在评估启动前包含于所选 Subject：

~~~powershell
npm audit --json | Set-Content -Encoding utf8 npm-audit.json
~~~

将 Repository 的策略绑定设为 <code>security/npm-dependency-audit</code>。适配器会按冻结字节和摘要读取 <code>npm-audit.json</code>：干净且完整的报告得到 <code>SATISFIED</code>；经独立契约复核的漏洞得到阻塞 Finding 和 <code>FAILED</code>；报告缺失、格式不受支持、Coverage 不完整或 Evidence 被篡改时得到 <code>INDETERMINATE</code>。报告新鲜度仍由生成报告的 Host/CI 负责。

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
| <code>dsh-security-assurance</code> | 根 Security Assurance Service；同时导出 npm audit 归一化契约 |
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

**Catalog 显示 UNSUPPORTED**：确认使用的是已授权仓库、<code>security/standard</code> Profile，以及 Catalog 为当前策略返回的模式。独立启动的 <code>CHANGE</code> 接受精确已提交的 base/head；未提交工作区只由 Control Plane 的 Host 专用 Subject 接入。<code>TARGETED</code> 尚未支持。

**端口冲突**：关闭占用端口的旧 Harness 进程，或在 Web Profile 中改用空闲端口后重新启动。

**评估为 BLOCKED**：先读取 <code>security_assessment_status</code> 的 <code>legalNextActions</code>，只执行服务允许的 <code>resume</code> 或 <code>cancel</code>。

### 开发与验证

~~~powershell
pnpm install
pnpm lint
pnpm build
pnpm typecheck
pnpm test
pnpm pack:dry-run
pnpm pack:profile-smoke
pnpm release:check
~~~

当前开发树发布门禁已通过：74 个测试文件、387 个测试，静态检查、类型检查、构建、打包和 Harness Profile smoke 均通过。公开 CI 在 Ubuntu、macOS 和 Windows 上从两个 tarball 重建 fresh Profile 并执行 Web 探针；每日兼容矩阵另对全部已声明 Harness 版本执行双插件联合 E2E 与打包安装探针。

完整领域模型见 [CONTEXT.md](CONTEXT.md)，安全政策见 [SECURITY.md](SECURITY.md)，候选版审查见 [SECURITY-REVIEW.md](SECURITY-REVIEW.md)。

<details>
<summary>English</summary>

## What it is

<code>dsh-security-assurance</code> is an evidence-backed repository security assessment plugin for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness). It integrates through public Harness and Cordis seams without modifying Harness Core, and exposes versioned, queryable, recoverable assessment results.

This is an assurance plugin, not a general vulnerability scanner. Built-in capabilities include the Node <code>package.json</code> install-lifecycle check and pure normalization plus independent validation of a frozen <code>npm-audit.json</code> report.

## Current release

- Version: <code>0.1.0-rc.10</code>
- Status: release candidate
- Target Harness: <code>0.1.2-alpha.1</code> (primary); <code>0.1.2-alpha.2</code> ~ <code>0.1.2-alpha.4</code> verified by the compatibility matrix
- Release: [v0.1.0-rc.10](https://github.com/bailong-Hakuryu/dsh-security-assurance/releases/tag/v0.1.0-rc.10)

## Support matrix

| Item | Status |
| --- | --- |
| Assessment mode | <code>REPOSITORY</code>; exact-commit or Mission-produced-workspace <code>CHANGE</code> |
| Subjects | <code>git_revision</code>, <code>workspace_snapshot</code>, exact base/head <code>change</code>; Host-only Control Plane <code>workspace_change</code> |
| <code>CHANGE</code> | Exact committed base-to-head pairs or Control Plane-frozen baseline-to-produced workspaces; scans the complete resulting tree |
| <code>TARGETED</code> | Not currently supported |
| Default policy | <code>security/node-package-lifecycle</code> |
| Optional npm audit policy | <code>security/npm-dependency-audit</code> |
| Default profile | <code>security/standard</code> |
| Harness versions | <code>0.1.2-alpha.1</code> (primary), <code>0.1.2-alpha.2</code>, <code>0.1.2-alpha.3</code>, <code>0.1.2-alpha.4</code> |
| Node.js | <code>^22.19.0 \|\| >=24.0.0</code> (CI covers 22 and 24) |
| Platforms | Windows, Linux, macOS |

The Service resolves authorized repositories and catalog choices first. Models must use the exact returned identifiers; paths and IDs are never guessed.

The Harness support window is an explicit, verified set: a daily [Harness Compatibility](https://github.com/bailong-Hakuryu/dsh-security-assurance/actions/workflows/harness-compat.yml) workflow discovers official repository tags, then runs the dual-plugin joint E2E (Mission → Developer workspace change → CHANGE Assessment → sealed submission → Quality Gate) and a packed fresh-profile installation with a live Web probe — on Ubuntu, macOS, and Windows for the primary target, and on Ubuntu for the remaining versions. New tags enter verification automatically but are not claimed as supported until the matrix passes (ADR 0310).

Exact-commit <code>CHANGE</code> mode freezes the resolved base and head identities, raw diff digest, and complete head tree. The bundled policies evaluate their complete relevant input sets in that tree, which is a conservative superset of the Policy impact cone.

The standalone tool and Workbench catalog remains backward compatible and exposes only exact-commit <code>change</code> to models. After a Control Plane Developer run publishes Implementation Evidence, its Provider receives a Host-only <code>workspace_change</code> from the unforgeable execution context. Security Assurance independently matches branch, baseline HEAD, Git-status fingerprint, byte-exact produced-change fingerprint, and the complete resulting tree before creating an Assessment; any drift fails closed.

## Install in Harness Web

Compatible with DeepSeek Harness <code>0.1.2-alpha.1</code> ~ <code>0.1.2-alpha.4</code> (an explicit, verified set; see the support matrix above). Requires Node.js <code>^22.19.0 || >=24.0.0</code> and the Harness CLI. Install the prebuilt GitHub Release package directly:

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

## npm audit report adapter

The Host, CI job, or operator runs npm audit outside the Assessment. The plugin never starts npm, contacts the Registry, or reads live network state from its PURE Analyzer boundary. Generate a UTF-8 report and make sure it is part of the selected Subject before the Assessment starts:

~~~powershell
npm audit --json | Set-Content -Encoding utf8 npm-audit.json
~~~

Bind the Repository to <code>security/npm-dependency-audit</code>. The adapter reads the exact frozen report bytes and digest. A complete clean report yields <code>SATISFIED</code>; independently validated vulnerabilities yield blocking Findings and <code>FAILED</code>; a missing or unsupported report, incomplete Coverage, or tampered Evidence yields <code>INDETERMINATE</code>. Report freshness remains the responsibility of the Host or CI job that produced it.

## Results and safety

All public operations return a typed <code>SecurityResult&lt;T&gt;</code> envelope. Commands return immutable versioned Receipts; queries return identity- and revision-bound Snapshots. Host authority resolves identity and permissions; model arguments never carry credentials, paths, database handles, or executable objects. Missing authorization, conflicts, timeouts, cancellation, and external failures fail closed.

Run <code>workspace_snapshot</code> only for repositories the user explicitly authorizes. Ancestor links are rejected, Subject symlinks are inventoried without dereference, and Git runs through the Harness-managed subprocess boundary. See [SECURITY-REVIEW.md](SECURITY-REVIEW.md).

## Control Plane integration

Engineering Control Plane owns the Mission, engineering Evidence, and final Quality Gate. Security Assurance owns the external security obligation and its evidence. An unavailable, failed, or indeterminate security result blocks the Gate; it is never converted into approval. The two plugins do not share SQLite files, writable Evidence paths, transactions, or Kernel objects.

## Development

~~~powershell
pnpm install
pnpm lint
pnpm build
pnpm typecheck
pnpm test
pnpm pack:dry-run
pnpm pack:profile-smoke
pnpm release:check
~~~

The current development tree gate passes with 74 test files and 387 tests, including linting, typecheck, build, packaging, and Harness profile smoke. Public CI rebuilds a fresh Profile from both tarballs and probes Web on Ubuntu, macOS, and Windows; the daily compatibility matrix additionally runs the dual-plugin joint E2E and the packed-installation probe across every declared Harness version.

</details>

## License

[MIT](LICENSE)
