# Agent 逐阶段鉴权审计 Playbook

本文件是 [SKILL.md](../SKILL.md) 的配套操作手册。AutoCVE 的每个 Agent 读完后，跳到自己的小节执行。每节给出：**输入 → 目标 → 动作 → 产出/handoff → 本阶段禁止事项**。

综合审计模式（Scan → Triage + Finding）下五个 Agent 全部参与。

---

## 1. Recon —— 画边界、建台账

**输入**：项目源码、语言标签、任务配置（目标文件 / 排除规则）。

**目标（鉴权视角）**：产出一张**信任域图**与一份**入口台账**，作为后续所有阶段的覆盖度基准。

**动作**：

1. 识别技术栈：语言、框架、路由机制、认证机制（Session/OAuth/OIDC/SAML/JWT/mTLS/API Token）、授权模型（RBAC/ACL/权限矩阵）、会话实现、凭据存储位置。方法见 [code-signals.md](code-signals.md) 对应语言小节。
2. 绘制信任域图：标注全部信任边界——外部 Webhook/PR、用户会话、Agent/Runner、Controller/Server、部署目标、多租户/命名空间、网关与后端；有 K8s Operator 时加 Operator 信任链（CR→API Server→高特权 SA→集群资源）。
3. **枚举全部入口点**：HTTP 路由（含框架按命名约定自动暴露的，如 Jenkins `doXxx`、Spring Actuator）、RPC/gRPC 方法、CLI 通道、Webhook 接收器、表单验证/测试连接端点、消息队列消费者、定时触发器、Reconcile 循环。
4. 建**入口台账**，每行：入口、信任域、认证要求、权限要求、是否状态变更、目标域、覆盖判定。格式见 [code-signals.md](code-signals.md) 末节。
5. 判定全局认证策略：默认拒绝+白名单 vs 默认放行+黑名单。后者标记为高风险，逐端点核对。

**产出 / handoff**：信任域图 + 入口台账 + 优先审计路径（按高危信号排序）。handoff 给 Scan 与 Finding。

**本阶段禁止**：报具体漏洞。Recon 只交付攻击面，不下结论。

---

## 2. Scan —— 定位候选、CWE 初判

**输入**：Recon 的攻击面与优先路径。

**目标**：用确定性手段（grep/规则集/依赖扫描/密钥扫描）产出**鉴权候选列表**，每个候选带初判 CWE 与代码位置。Scan 不判断真假，只定位。

**动作**：

1. 跑 [code-signals.md](code-signals.md) 中各语言的快筛命令（鉴权挂载点、危险信号 grep 集合）。
2. 按检查类别 A–F 归类候选，做 CWE 初判（对照 [cwe-map.md](cwe-map.md) 速查表）。
3. 密钥/凭据扫描：硬编码密钥、配置文件明文、URL 传参 Token。
4. 每个候选记录：入口、`file:line`、触发信号、初判 CWE、所属类别。**不写利用过程**。

**产出 / handoff**：候选列表（→ Triage）。同时把候选位置回填入口台账的"覆盖判定"列。

**本阶段禁止**：下"这是漏洞"的结论；补充运行时不存在的细节。

---

## 3. Triage —— 误报过滤、证据补齐

**输入**：Scan 的原始候选。

**目标**：把候选压到"值得 Finding 深挖"的可信集合：过滤明显误报，为存疑候选补最小证据。Triage 是候选的守门人，不是最终认定者。

**动作**（对每个候选回答）：

1. **可达性**：未认证/低权限请求真能到达这段代码吗？逐层确认过滤器链、中间件、框架默认行为——不允许假设。
2. **校验存在性**：上下文里是否已有校验（注解/装饰器/中间件/`checkPermission`）？有校验则判断覆盖是否完整。
3. **证据充分性**：证据是否足以支撑进入 Finding？不足则标记 `needs_verification` 并注明**缺什么信息**（运行时配置/部署形态/组件版本）。
4. **去重**：按 `file_path + line_start + vulnerability_type` 合并重复候选。

**动作（误报过滤规则，鉴权专项）**：

| 常见误报 | 判定 |
| --- | --- |
| 危险函数出现，但该路径不可外部到达 | 过滤 |
| 有认证过滤器覆盖，但 Triage 未验证过滤器链 | 转 Finding 验证，不直接过滤 |
| `needs_verification` 但未注明缺失信息 | 打回补证据 |
| 报的是通用注入/SQLi/XSS 本身 | 移出本 Skill 范围 |

**产出 / handoff**：可信候选（→ Finding），每个附最小证据 + 缺口说明。

**本阶段禁止**：用 `needs_verification` 却不写清缺什么；给未确认候选分配最终严重级别。

---

## 4. Finding —— 深挖、确认、结构化提交

**输入**：Triage 的可信候选 + Recon 的入口台账。

**目标**：把候选升级为**带源码证据、可复现路径、有优先评级的已确认漏洞**，产出符合 CVE 申报条件的结构化结果。

**动作**：

1. **对照入口台账**确认该入口的认证/权限/目标域判定，复现 E2 入口路径。
2. **按类别加载检查清单**深挖：
   - A 认证 → [check-authn.md](check-authn.md)
   - B 授权 → [check-authz.md](check-authz.md)
   - C 会话 / D 凭据 → [check-session-credential.md](check-session-credential.md)
   - E 来源/路径 → [check-origin-path.md](check-origin-path.md)
   - F Operator → [check-operator-k8s.md](check-operator-k8s.md)
3. 逐条执行该类清单的"证明义务"，凑齐 E1–E5 证据契约（见 SKILL.md）。
4. 对照 [cve-patterns.md](cve-patterns.md) 同型模式定级，填写 `cve_justification`。
5. **攻击链评估**：单点低危能否与其它发现串成链（见 cve-patterns.md 末节）？填 `exploit_chain`。
6. CWE 落点从 [cwe-map.md](cwe-map.md) 选精确编号。
7. 用 `FinalizeFinding` 提交，字段映射见 SKILL.md 与 [report-template.md](report-template.md)。

**三态判定**：

| 状态 | 含义 | 字段处理 |
| --- | --- | --- |
| `confirmed` | E1–E5 齐全，入口→缺陷→影响全程有 `file:line` 支撑 | `verdict=confirmed`，分配 severity |
| `needs_verification` | 静态无法确认（依赖运行时配置/部署/组件版本） | `needs_verification=true`，**不分配 severity**，`verification_notes` 注明缺什么 |
| `rejected` | 验证后排除 | 不入库，记录排除原因防重复上报 |

**产出 / handoff**：`FinalizeFinding` payload（→ Verification，若启用）。

**本阶段禁止**：E1–E5 缺项却报 `confirmed`；不读入口台账直接凭 grep 命中下结论；未调用 `FinalizeFinding` 就用自然语言声称完成。

---

## 5. Verification —— 动态验证

**输入**：Finding 的 `confirmed` / `needs_verification` 发现。

**目标**：在沙箱/受控工具链中用 PoC 动态验证，给出确定状态与补充证据。**保守可靠**优先于覆盖广度。

**动作**：

1. 逐条验证 Finding 提交的发现（优先高严重级别）：
   - 复现 E2 入口路径，确认可达性
   - 构造 PoC 触发 E4 缺陷，观察是否达到预期 `impact`
   - 对 `needs_verification` 项，重点补齐缺失的运行时信息
2. 判定：
   - 验证成功 → `verdict=confirmed`，填 `poc` 与 `verification_notes`
   - 验证失败（缺陷不成立）→ 标记 `rejected`，记录反证
   - 无法验证（环境不具备）→ 保持 `needs_verification`，写明缺什么环境
3. 按 [report-template.md](report-template.md) 生成漏洞报告（Summary/Details/POC/Impact/Remediation/CVE/CWE）。

**产出 / handoff**：验证状态与补充证据（→ Merge/Finalize）。

**本阶段禁止**：把"环境不具备"当成"漏洞不成立"；对未验证项伪造 PoC；开发超出本 Skill 范围（通用注入/XSS）的利用。

---

## 附：各阶段加载 references 速查

| 阶段 | 必读 | 按需 |
| --- | --- | --- |
| Recon | code-signals.md | — |
| Scan | code-signals.md | cwe-map.md |
| Triage | cwe-map.md | 对应 check-*.md |
| Finding | 对应 check-*.md + cwe-map.md | cve-patterns.md |
| Verification | report-template.md | 对应 check-*.md |
