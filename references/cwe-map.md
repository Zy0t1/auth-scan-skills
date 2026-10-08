# CWE 落点映射表

证据契约 E5 的选号依据。数据与《鉴权漏洞相关CWE分类.md》（MITRE CWE v4.20 官方数据机械提取）一致。

## 1. 不可映射黑名单（禁止使用）

| CWE | 名称 | 原因 |
| --- | --- | --- |
| CWE-284 | Improper Access Control | Pillar，官方 DISCOURAGED |
| CWE-693 | Protection Mechanism Failure | Pillar，官方 DISCOURAGED |
| CWE-265 | Privilege Issues | Category，官方 PROHIBITED |
| CWE-1396 | Comprehensive Categorization: Access Control | Category，PROHIBITED |
| CWE-1018 | Manage User Sessions | Category，PROHIBITED |
| CWE-668 | Exposure of Resource to Wrong Sphere | Class，ALLOWED 但需审慎，优先用其子类 |

## 2. Web 站点 / API 核心清单（42 条）

```
认证:       CWE-287, CWE-306, CWE-288, CWE-302, CWE-290, CWE-307, CWE-1392
授权:       CWE-285, CWE-862, CWE-863, CWE-639, CWE-283, CWE-1220, CWE-269, CWE-272, CWE-732
会话:       CWE-384, CWE-613, CWE-1004
凭据:       CWE-256, CWE-798, CWE-321, CWE-1259, CWE-522, CWE-598
CSRF/来源:  CWE-352, CWE-346
路径绕过:   CWE-551, CWE-647, CWE-22
签名/加密:  CWE-347, CWE-916, CWE-330
信息泄露:   CWE-200, CWE-209, CWE-532, CWE-203, CWE-1230
边界/失效:  CWE-441, CWE-807, CWE-636, CWE-501
```

## 3. CI/CD 平台核心清单（31 条）

```
认证与通道: CWE-306, CWE-288, CWE-290, CWE-291, CWE-302, CWE-345, CWE-523, CWE-419, CWE-420
授权与隔离: CWE-862, CWE-283, CWE-1220, CWE-266, CWE-272, CWE-250, CWE-276
凭据与令牌: CWE-798, CWE-321, CWE-1394, CWE-1259, CWE-1270, CWE-1188, CWE-598
来源校验:   CWE-346, CWE-940
信任边界:   CWE-441, CWE-501, CWE-807, CWE-636
信息泄露:   CWE-532, CWE-1230
```

## 4. K8s Operator / Controller 核心清单

```
RBAC 收敛:    CWE-272, CWE-266, CWE-250, CWE-1188
混淆副手:     CWE-441, CWE-807, CWE-862
跨命名空间:   CWE-283, CWE-863, CWE-1220
admission webhook: CWE-306, CWE-346, CWE-636
泄露面(Events/status/日志): CWE-532, CWE-209, CWE-201, CWE-1230
```

## 5. 发现类别 → 首选落点速查

| 检查发现 | 首选 CWE | 备选 |
| --- | --- | --- |
| 端点完全无认证 | CWE-306 | CWE-288（备用路径）、CWE-425（强制浏览） |
| JWT/OIDC/SAML 字段漏校验 | CWE-347（签名）/ CWE-303（实现错误） | CWE-304（缺关键步骤）、CWE-345 |
| 认证后信任客户端自报身份 | CWE-290 / CWE-302 | CWE-807 |
| 以 IP/Referer 作认证依据 | CWE-291 / CWE-293 | CWE-350（rDNS） |
| 密码重置身份绑定缺陷 | CWE-620 / CWE-287 | CWE-304 |
| 认证暴力破解无限制 | CWE-307 | CWE-645（锁定过严 DoS） |
| 端点无权限检查 | CWE-862 | CWE-285 |
| 权限检查逻辑错误 | CWE-863 | CWE-280（失败后继续执行） |
| IDOR / 改 ID 越权 | CWE-639 | CWE-99、CWE-566（SQL 主键） |
| 归属未校验 / 跨租户 | CWE-283 | CWE-863、CWE-1220 |
| 权限粒度过粗 | CWE-1220 | CWE-285 |
| Read 级解锁敏感操作 | CWE-863（检查错）或 CWE-862（没检查） | CWE-1220 |
| 高权限委托无约束 / 混淆副手 | CWE-441 | CWE-250、CWE-272 |
| 默认高权限角色/默认入组 | CWE-266 / CWE-842 | CWE-1188 |
| Token scope/audience 不校验 | CWE-1259 | CWE-1270 |
| 凭据明文存储/配置文件 | CWE-256 / CWE-260 | CWE-312、CWE-522 |
| 硬编码凭据/密钥 | CWE-798 / CWE-321 | CWE-547、CWE-1394 |
| 凭据进日志/错误/Diff/响应 | CWE-532 / CWE-209 / CWE-201 | CWE-1230（元数据） |
| URL query 传 Token | CWE-598 | CWE-319 |
| 会话固定 | CWE-384 | CWE-613（过期不足） |
| Cookie 缺 Secure/HttpOnly/SameSite | CWE-614 / CWE-1004 / CWE-1275 | CWE-315、CWE-565 |
| CSRF | CWE-352 | CWE-346（Origin 校验错误） |
| CORS 任意源带凭据 | CWE-942 | CWE-346 |
| 鉴权先于 URL 归一化 | CWE-551 | CWE-647、CWE-41 |
| 代理与后端解析差异 | CWE-436 | CWE-647 |
| 校验异常时默认放行 | CWE-636 | CWE-754 |
| Operator CR 引用越权目标代执行 | CWE-441 | CWE-862、CWE-283 |
| Operator RBAC 通配符 / secrets 全集群可读 | CWE-272 / CWE-266 | CWE-250 |
| admission webhook 无认证 / Fail Open | CWE-306 / CWE-636 | CWE-346 |
| Events / status / 日志回写凭据 | CWE-532 / CWE-201 | CWE-209、CWE-1230 |
| 密码弱哈希 | CWE-916 | CWE-328 |
| 令牌可预测/熵不足 | CWE-330 | CWE-337、CWE-341 |
| 用户名枚举（响应/时序差异） | CWE-203 | CWE-209 |

## 6. 复合漏洞组合映射

| 漏洞场景 | 推荐 CWE 组合 |
| --- | --- |
| JWT 伪造管理员身份 | CWE-347 + CWE-287 + CWE-327 |
| 路径变形绕过认证过滤器 | CWE-647 + CWE-288（或 CWE-551 + CWE-288） |
| 会话固定导致账户接管 | CWE-384 + CWE-613 |
| 重放 / 欺骗绕过认证 | CWE-294 + CWE-290 |
| IDOR 越权访问他人资源 | CWE-639 + CWE-862 |
| 跨租户资源越权 | CWE-283 + CWE-863 + CWE-1220 |
| CSRF 创建管理员 | CWE-352 + CWE-862 |
| 凭据明文存储并泄露 | CWE-256 + CWE-522 + CWE-200 |
| 硬编码密钥导致令牌伪造 | CWE-321 + CWE-798 + CWE-347 |
| CI Token 权限过宽被滥用 | CWE-1259 + CWE-272 + CWE-862 |
| Agent 被当作代理滥用（混淆副手） | CWE-441 + CWE-807 + CWE-501 |
| Webhook 未验签触发流水线 | CWE-345 + CWE-940 + CWE-306 |
| 构建日志泄露凭据 | CWE-532 + CWE-1230 + CWE-522 |
| 校验异常时默认放行 | CWE-636 + CWE-754 + CWE-863 |
| Operator 混淆副手窃取跨租户凭据 | CWE-441 + CWE-283 + CWE-272 |

## 7. 与 OWASP Top 10 / API Top 10 的对应

| 类别 | 对应 CWE |
| --- | --- |
| A01 Broken Access Control | 285、862、863、639、283、1220、425、441、352 |
| A02 Cryptographic Failures | 319、327、328、347、916、330、256 |
| A04 Insecure Design | 209、256、807 |
| A07 Identification and Authentication Failures | 287、306、307、384、521、522、620、290、302、1392 |
| A08 Software and Data Integrity Failures | 345、347 |
| A09 Logging & Monitoring Failures | 532 |
| API1 BOLA | 639、99、566、283 |
| API2 Broken Authentication | 287、306、603、620 |
| API5 BFLA | 285、863、1220 |
