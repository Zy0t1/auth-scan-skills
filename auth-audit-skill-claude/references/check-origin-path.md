# E 类检查清单：CSRF、来源校验与路径绕过

> 根因：状态变更端点未校验请求来源，诱导已认证主体（浏览器、Agent）发出非预期请求；或通过备用路径、非规范 URL、解析顺序差异绕过认证/授权过滤器。
> 对应 CVE 簇：其他类型中的 CSRF 3 条 + 认证缺陷中的路径绕过子簇。

## E1. CSRF（CWE-352）

- [ ] 对照入口台账筛选全部**状态变更端点**（创建/修改/删除/触发/审批类），逐个核对：
  - 是否要求 POST（或变更类方法）？**GET 可触发状态变更即漏洞**。
  - 是否有 CSRF Token 校验 / `@RequirePOST` / `protect_from_forgery` / `csurf`？
- [ ] 重点高危目标（CSRF 收益最大的端点）：
  - 创建管理员 / 修改用户权限（Jenkins CVE-2017-1000356：CSRF 创建管理员）
  - 修改安全配置、安装插件、更改 API Token
  - 账户设置变更 → 账户接管（GitLab CVE-2022-0427）
- [ ] API 端点若接受 Cookie 认证却无 CSRF 防护，同样可被打（`skip_forgery_protection` 但接受 Cookie 的 Rails API）。
- [ ] SameSite=None 的 Cookie 是否使 CSRF Token 防线成为唯一防线？（与 check-session-credential.md C3 联动）

## E2. Origin / Referer 与 CORS（CWE-346 / 942 / 1021 / 1022）

- [ ] 状态变更端点是否校验 `Origin` / `Referer` 头？校验逻辑是否严格匹配（前缀匹配 `https://example.com.evil.com` 绕过）？
- [ ] 注意反向：用 Referer/Origin **作为认证依据**也是漏洞（CWE-293）。
- [ ] CORS 配置：`Access-Control-Allow-Origin` 为 `*` 或反射请求 Origin，且 `Allow-Credentials: true` → 任意站点可带凭据读响应。
- [ ] Webhook / Agent 回调是否校验请求方来源身份？（CWE-940）
- [ ] 管理页面是否可被 iframe 嵌套（缺 `X-Frame-Options` / CSP `frame-ancestors`）→ Clickjacking（CWE-1021）？

## E3. SSRF 型凭据捕获（鉴权相关子集，CWE-918 场景 → 落点 441 / 807）

> 本 skill 只审 SSRF 的鉴权维度：平台是否被诱导以自身身份/凭据连接攻击者控制的 URL。

- [ ] 所有**连接外部 URL 的功能**逐一排查：测试连接（`doTestConnection`）、导入、Webhook 配置、插件更新源、制品源。
  - URL 是否白名单校验？是否禁止内网地址 / 云元数据地址（169.254.169.254）？
  - 连接时是否自动携带平台存储的凭据？（Jenkins GitHub Plugin CVE-2018-1000600、Job Import CVE-2019-1003016：低权限用户指定 URL → 平台带凭据连接 → 凭据被捕获）
- [ ] 触发这类端点需要什么权限？Read 级可触发即高危。

## E4. 路径规范化与过滤器绕过（CWE-551 / 647 / 424 / 425 / 436 / 41 / 22）

核心问题：**鉴权决策用的路径** 与 **最终路由到的资源** 是否一致？

- [ ] 行为顺序：权限判断在 URL 解析/归一化之前？→ 编码变形绕过（CWE-551）。
- [ ] 授权决策是否基于非规范 URL 路径？（CWE-647：`/admin;.js` 绕过 Filter）
- [ ] 变形测试矩阵：

| 变形 | 示例 | 针对 |
| --- | --- | --- |
| 路径穿越 | `/public/../admin` | 过滤器前缀匹配 |
| 分号参数 | `/admin;jsessionid=x`、`/admin;.js` | Servlet 容器 |
| 双重编码 | `/adm%252Ein` | 多层解码 |
| 尾斜杠/双斜杠 | `/admin/`、`//admin` | 路由匹配差异 |
| 大小写 | `/ADMIN` | 大小写不敏感后端 |
| 下划线/特殊字符域名 | `evil_example.com` | URL 白名单解析歧义（Spinnaker CVE-2026-25534） |
| 空字节/截断 | `/admin%00.css` | 混合栈 |

- [ ] 代理层（Nginx/Envoy/网关）与后端的 URL 解析规则是否一致？多层解析差异 = CWE-436。
- [ ] 未链接出的管理 URL / 内部端点能否直接请求（强制浏览 CWE-425）？
- [ ] 备用路径：别名、软链接、备份端口是否绕开主路径上的过滤器？（CWE-288/424）

## E5. 失效开放（CWE-636 / 754）

- [ ] 认证/授权/签名校验抛异常时，catch 分支是放行还是拒绝？
- [ ] 插件加载失败、配置解析失败、缓存服务不可用时，系统进入什么状态？（插件加载失败仍继续构建 = Fail Open）
- [ ] 条件分支覆盖：匿名模式、调试模式、降级模式下校验是否被跳过？

## E6. 证明义务（每条候选必须回答）

1. 诱导谁（管理员浏览器 / Agent / 平台自身）发出了什么请求？
2. 该请求缺少的校验具体是哪一项（Token / Origin / 签名 / 路径归一化）？
3. 请求以什么身份执行、造成什么状态变更？
