---
name: cicd-web-auth-audit
description: 面向 CI/CD 平台、Web 应用/API、Kubernetes Operator/Controller 源码的鉴权漏洞审计知识库。覆盖认证绕过、越权访问（IDOR/RBAC 缺陷）、凭据与密钥泄露、会话管理缺陷、CSRF 与来源校验缺失、路径规范化绕过、混淆副手（Confused Deputy）、CR 目标域校验、RBAC 收敛、admission webhook 缺陷。为 AutoCVE 多 Agent 审计流水线（Recon/Scan/Triage/Finding/Verification）提供各阶段的鉴权专项方法与检查清单，也可独立用于单 Agent 白盒审计。不用于黑盒渗透测试，不覆盖通用注入类漏洞（SQLi/XSS/反序列化本身）。
---

# CI/CD 与 Web 鉴权漏洞审计

面向源码的鉴权漏洞审计知识库。方法基于 86 条 CI/CD 鉴权 CVE 的三维度拆解与 139 条鉴权相关 CWE（v4.20）的精确落点。

## 本 Skill 如何接入 AutoCVE

本 Skill 是**垂直领域知识层**，不重建流程——AutoCVE 已固化 Orchestrator → Recon → Scan → Triage → Finding → Verification 编排。鉴权知识按阶段垂直嵌入：每个 Agent 读取本 SKILL.md 后，按下表跳到自己的小节，并**只加载该阶段需要的 references**（渐进式披露）。

综合审计模式（Scan → Triage + **Finding**）下，鉴权面的主战场是 **Finding**（深度确认与结构化提交），Scan/Triage 负责候选来源与误报过滤。

### Agent 路由表

| Agent | 鉴权视角的阶段目标 | 产出 / handoff | 加载的 references |
| --- | --- | --- | --- |
| Orchestrator | 判定目标是否含鉴权面；项目含 K8s Operator/Controller 时确保 F 类检查启用 | 阶段启用决策 | 本 SKILL.md |
| **Recon** | 画出信任域图；建**入口台账**；识别认证机制与授权模型 | 攻击面清单、优先审计路径、入口台账 | [references/code-signals.md](references/code-signals.md) |
| **Scan** | 用 grep/规则集定位鉴权候选，做 CWE 初判 | 带初判 CWE 的候选列表 | [references/code-signals.md](references/code-signals.md) |
| **Triage** | 误报过滤、证据补齐、去重 | 可信候选（附最小证据） | 对应 [check-*.md](references/check-authz.md) 与 [references/cwe-map.md](references/cwe-map.md) |
| **Finding** | 深挖确认、构造攻击链、按契约提交 | `FinalizeFinding` payload | [check-*.md](references/check-authz.md)、[references/cve-patterns.md](references/cve-patterns.md)、[references/cwe-map.md](references/cwe-map.md) |
| **Verification** | PoC 动态验证，判定 confirmed/needs_validation | 验证状态与补充证据 | 对应 [check-*.md](references/check-authz.md)、[references/report-template.md](references/report-template.md) |

逐 Agent 的详细操作（输入契约、产出格式、本阶段禁止事项）见 [references/agent-playbook.md](references/agent-playbook.md)。

## 核心心智模型

CI/CD 的本质是一条跨越多个信任域的流水线，鉴权漏洞几乎都出在信任域交界处：

```
外部贡献者 ──PR──→ 仓库 ──Webhook──→ CI引擎 ──RPC──→ Agent/Runner ──产物──→ 部署引擎 ──→ 集群
  (不可信)        (半可信)            (可信)            (半可信)                      (高特权)
```

Web 应用同理：外部请求 → 网关/代理 → 认证过滤器 → 业务逻辑 → 数据层，每层之间都是信任边界。

K8s Operator/Controller 是另一条高特权信任链：

```
用户 CR ──→ API Server（认证+RBAC）──→ Operator（高特权 SA 调谐）──→ 集群资源/Secret
 (低权限)         (守门人，但只看 RBAC)      (混淆副手高发区)              (高特权)
```

Operator 以自身 ServiceAccount 权限代替用户执行操作：API Server 只校验了"用户能否创建 CR"，CR 里引用的目标命名空间、Secret、镜像、URL 是否该用户可及，API Server 不知道——必须由 Operator 在调谐时自行校验，否则即混淆副手。

### 三维度提问

每个信任边界上按三个维度提问：

| 维度 | 核心问题 | 典型失守 |
| --- | --- | --- |
| 上下文转换 | 请求跨越信任域时是否重新校验？ | 未认证 Webhook/端点、Agent 自报身份被信任、跨命名空间不校验目标域 |
| 权限操作 | 权限在继承、重用、委托时是否忠于原始授权意图？ | Read 级权限解锁敏感端点、Token scope/audience 不校验、高权限委托无约束 |
| 执行失效 | 关键操作执行前是否重新校验身份、来源、协议字段？ | 认证后不再校验身份、无 CSRF/来源校验、JWT/SAML 字段漏校验、会话不刷新 |
| Operator 专项 | CR 引用目标域是否校验？Operator 权限是否收敛？ | secretRef/namespace/镜像/URL 未校验即代执行、cluster-admin SA、webhook `failurePolicy: Ignore` |

经验规律（86 条 CVE 统计）：78% 涉及执行失效，56% 涉及权限操作；**CVSS ≥ 9.0 的全部涉及执行失效**，且多数同时具备"不可信输入直达高特权执行域"的上下文转换特征。排查优先级按此分配。

### 检查类别（Finding/Triage 按类加载）

| 类别 | 参考文件 | 主要 CWE 族 |
| --- | --- | --- |
| A. 认证缺陷（协议实现、端点暴露、路径绕过认证、身份冒充、密码重置） | [references/check-authn.md](references/check-authn.md) | 287/306/288/302/290/303/304/345 |
| B. 权限控制缺陷（检查缺失、粒度不足、IDOR、继承过宽、委托失控、跨租户） | [references/check-authz.md](references/check-authz.md) | 862/863/639/283/1220/269/272 |
| C. 会话管理缺陷（会话固定、过期不足、Cookie 属性） | [references/check-session-credential.md](references/check-session-credential.md)（前半） | 384/613/614/1004/1275 |
| D. 凭据与密钥管理（存储、传输、展示掩码、作用域、隔离） | [references/check-session-credential.md](references/check-session-credential.md)（后半） | 256/798/321/1259/598/532 |
| E. 来源校验与路径绕过（CSRF、Origin/CORS、SSRF 凭据捕获、规范化顺序） | [references/check-origin-path.md](references/check-origin-path.md) | 352/346/942/551/647/425 |
| F. Operator/Controller 专项（RBAC 收敛、混淆副手、admission webhook、自身端点、凭据与事件泄露） | [references/check-operator-k8s.md](references/check-operator-k8s.md) | 441/807/862/272/306/636 |

目标含 K8s Operator/Controller（存在 Reconcile 循环、CRD、controller-runtime 依赖）时 F 类必查；其余目标跳过。

## 证据要求（Finding 提交前自检）

每条 `confirmed` 发现必须齐全以下五要素，缺任何一个就降级为 `needs_verification`：

| 编号 | 证据点 | 要求 |
| --- | --- | --- |
| E1 位置 | 文件:行号 + 关键代码片段 | 不接受"某函数可能存在问题"式描述 |
| E2 入口路径 | 从外部请求到缺陷代码的完整链路 | 路由 / 中间件 / 过滤器逐层列出 |
| E3 前置条件 | 未认证 / 任意认证用户 / 特定权限 | 精确到权限名（如 `Overall/Read`、`project:write`） |
| E4 缺陷机制 | 缺失或错误校验的具体描述 | 写清"应该校验什么、实际校验了什么、哪条路径漏了" |
| E5 CWE 落点 | 从 [references/cwe-map.md](references/cwe-map.md) 选精确编号 | **禁止**使用 CWE-284/693/265/1396/1018 等视图类编号（668 审慎） |

### 提交字段映射（→ FinalizeFinding）

Finding 阶段用 `FinalizeFinding` 终止并提交结构化结果。字段对应关系：

| FinalizeFinding 字段 | 来源 | 说明 |
| --- | --- | --- |
| `title` / `description` | E4 | 一句话标题 + 缺陷机制详述 |
| `vulnerability_type` | 检查类别（A–F） | 如 `Authorization Bypass`、`Missing Authorization` |
| `file_path` / `line_start` / `line_end` / `code_snippet` | E1 | 精确定位 |
| `source` | E2 | 入口（外部可达点） |
| `sink` | E4 | 缺陷发生点（缺失/错误的校验处） |
| `severity` | 定级 | 参考 [references/cve-patterns.md](references/cve-patterns.md) 同型 CVE 的 CVSS 倾向 |
| `confidence` / `verdict` | E3+E4 验证结论 | 三态判定 |
| `needs_verification` | 三态判定 | `needs_verification` 状态置 true |
| `impact` | 影响闭环 | 攻击者实际拿到什么（凭据/越权/RCE/供应链投毒） |
| `exploit_chain` | 攻击链 | 单点+组合路径（见 cve-patterns.md 末节） |
| `poc` | Verification 阶段 | PoC 或复现步骤 |
| `cve_justification` | 模式对照 | 命中的已知 CVE 模式 |
| `suggestion` | 修复 | 具体到代码层面 |
| `verification_notes` | Verification | 验证说明与残留不确定性 |

去重键（Orchestrator 合并时）：`file_path + line_start + vulnerability_type`。Finding 提交前先用该键自检是否重复。

## 高危优先信号（时间有限时先查这十项）

1. 无认证可到达的状态变更端点或敏感数据端点（认证配置为默认放行型）
2. JWT 签名验证可被配置分支（匿名/调试/缓存）跳过；OIDC 不校验 `aud`/`iss`；SAML 不校验时间窗口与断言唯一性
3. 认证后的授权决策使用客户端自报身份字段（`agent_id`、`team_name`、commit 作者、`X-Forwarded-For`、请求头角色）
4. Read 级权限可访问：凭据明文/枚举、配置修改、审批执行、脚本执行端点
5. 密码重置 / 令牌签发流程的身份绑定可被请求参数篡改（多 email 参数注入）
6. 表单验证 / 脚本预览端点绕过沙箱直接执行用户脚本
7. GET 请求可触发状态变更（CSRF 直通车）
8. URL 先做权限判断后做解析归一化（`../`、编码、尾缀、大小写绕过过滤器）
9. CR 中的 secretRef / namespace / 镜像 / URL 字段未校验目标域，Operator 以高权限 ServiceAccount 代执行（混淆副手）
10. Operator RBAC 通配符 / cluster-admin、secrets 全集群可读；admission webhook 无认证或 `failurePolicy: Ignore`

## 反模式（禁止行为）

- **Triage 阶段**：不验证证据充分性就放行，或用 `needs_verification` 条目不注明缺失信息
- **Finding 阶段**：不建/不读入口台账就直接按关键词报漏洞（必然漏报 + 高误报）；不验证可达性，把"危险函数出现"直接报为漏洞
- 用 CWE-284/693/265/1396/1018 等不可映射编号作漏洞落点
- 展开注入 / XSS / SSRF 的利用细节（超出本 skill 范围；SSRF 仅在与凭据捕获、来源校验相关时纳入鉴权范畴）
- 审计 Operator 时只看 API Server 侧 RBAC（"用户能否创建 CR"），漏掉 Operator 以自身高权限代执行的操作面（CR 引用目标的二次校验）
- Finding 未调用 `FinalizeFinding` 就在自然语言里声称"审计完成"（会被 runtime 标记 incomplete）
