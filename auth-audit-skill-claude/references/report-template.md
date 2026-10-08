# 报告模板：FinalizeFinding 提交 与 漏洞报告

Finding/Verification 阶段的输出格式。分两层：**① `FinalizeFinding` 结构化提交**（机器可读，去重入库）与 **② 漏洞报告**（人工/CVE 申报可读）。

---

## ① FinalizeFinding 提交契约

Finding 阶段必须通过 `FinalizeFinding` 终止并提交。字段与证据契约（E1–E5）对应如下，缺项会被 `finalization_rejected`：

```yaml
title: <一句话标题：缺陷 + 影响>
vulnerability_type: <Missing Authorization | Authorization Bypass | Improper Access Control | Improper Authentication | Credential Exposure | CSRF | ...>
severity: <Critical | High | Medium | Low>     # needs_verification=true 时留空
description: |
  <E4 缺陷机制：应该校验 X，实际校验了 Y，Z 路径/分支漏了>
file_path: <path/to/file.ext>
line_start: <int>
line_end: <int>
code_snippet: |
  <关键代码片段，标注缺陷行>
source: <E2 入口：未认证/低权限请求可达的外部点>
sink: <E4 缺陷点：缺失或错误校验发生处>
confidence: <high | medium | low>
needs_verification: <true | false>
verdict: <confirmed | needs_verification | rejected>
exploit_chain: |
  <单点：前置权限 → 触发 → 影响>
  <组合：发现A → 发现B → 端到端目标>（见 cve-patterns.md 攻击链）
poc: |
  <Verification 阶段产出的 PoC 或复现步骤；未验证则写 needs_verification>
impact: <攻击者实际拿到什么：凭据窃取/越权/RCE/供应链投毒>
cve_justification: <命中的 cve-patterns.md 模式名 + 同型代表 CVE + CVSS 倾向>
suggestion: <具体到代码层面的修复建议>
verification_notes: <验证说明；needs_verification 时注明缺什么信息/环境>
```

**提交前自检**：
- E1–E5 是否齐全？缺项 → 降级为 `needs_verification`。
- 去重键 `file_path + line_start + vulnerability_type` 是否与已有发现重复？
- CWE 落点是否来自 [cwe-map.md](cwe-map.md) 且不在黑名单？
- `needs_verification=true` 的是否已注明缺失信息且未分配 severity？

---

## ② 漏洞报告结构

Audit 页面「初步报告」展示：漏洞标题、风险等级、漏洞类型、置信度、文件路径与行号、漏洞描述、Source/Sink、影响说明、利用链、PoC、验证说明——即上面 FinalizeFinding 字段的渲染，无需另写。

漏洞管理中的「漏洞报告」用于人工研判与 CVE 申报，含中文报告 / English Report / CVE 报告三份。正文结构：

```markdown
## Summary
<一句话概述：产品 X 版本 Y 中，因 Z 缺陷，攻击者可在前置条件下实现影响>

## Details
<技术细节：信任域/入口 → 缺陷机制（应校验 X，实际 Y）→ CWE 落点 → 受影响代码位置>

## POC
<复现步骤 / 请求样例 / PoC 代码；注明前置权限>

## Impact
<影响闭环：攻击者拿到什么、影响范围（单租户/跨租户/集群级）>

## Remediation
<修复建议：具体到代码层面>

## Affected products
<产品名 + 受影响版本区间>

## CVSS
<向量字符串 + 分值，如 AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N = 8.8>

## CWE
<CWE-xxx（+ 组合 CWE）>

## Suggested description of the vulnerability for use in the CVE
<可直接用于 CVE 申报的英文描述>

## Disclosure Notes
<披露说明：遵循目标 SECURITY.md / GitHub Advisories / CNA 流程；给出修复版本或缓解措施>
```

---

## 写作纪律

- 严重级别只给 `confirmed`；`needs_verification` 不评级。
- 每条 `confirmed` 必须 E1–E5 五要素齐全；缺任何一个降级为 `needs_verification`。
- CWE 编号只能从 [cwe-map.md](cwe-map.md) 选，禁止黑名单编号（284/693/265/1396/1018）。
- 影响描述写"攻击者实际拿到什么"，不写"可能存在安全隐患"。
- Finding 未调用 `FinalizeFinding`，不得在自然语言中声称"审计完成"。
