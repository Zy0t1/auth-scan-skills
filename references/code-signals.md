# 代码信号库：路由枚举、鉴权挂载点与 grep 快筛

阶段 1（侦察）与阶段 2（入口建账）的操作手册。按目标语言/框架定位对应小节，先枚举入口，再核对鉴权挂载，最后跑危险信号快筛。

> 通用原则：**路由的暴露方式决定漏检面**。显式注册的路由（Go、Express）容易枚举；命名约定自动绑定的路由（Jenkins Stapler、Rails）容易遗漏——优先审计后者。

---

## 1. Java — Jenkins（Core / 插件，Stapler 框架）

Jenkins 是鉴权漏洞重灾区（86 条 CVE 中 40+ 条），且路由由**命名约定自动绑定**，最容易漏检。

### 路由枚举（命名约定即路由）

| 方法签名 | 暴露的 URL | 风险 |
| --- | --- | --- |
| `public void doXxx(...)` | `/xxx` | 动作端点，状态变更高发 |
| `public HttpResponse doXxx()` | `/xxx` | 同上 |
| `public ListBoxModel doFillXxxItems(...)` | 表单下拉填充端点 | 常泄露凭据 ID 枚举 |
| `public FormValidation doCheckXxx(...)` | 表单校验端点 | 常缺权限检查与 `@RequirePOST` |
| `public FormValidation doTestConnection(...)` | 测试连接端点 | SSRF 捕获凭据高发点 |
| `public Object getXxx()` | `/xxx` 属性暴露 | 可能返回内部对象图（Stapler 递归暴露） |
| `getDynamic(...)` / `StaplerProxy` / `StaplerFallback` | 动态路由 | 可把内部无保护对象挂到 URL 空间 |

枚举命令：

```bash
grep -rn "public .*\bdo[A-Z]\w*(" --include="*.java"
grep -rn "public .*get[A-Z]\w*()" --include="*.java"   # 重点看返回复杂对象的
grep -rn "StaplerProxy\|StaplerFallback\|getDynamic" --include="*.java"
```

### 鉴权挂载点核对

| 检查项 | 安全基线 | 危险信号 |
| --- | --- | --- |
| 权限检查 | 每个 `doXxx` 显式调用 `checkPermission(精确权限)` | 完全无检查；只查 `Overall/Read`/`Job/Read` 却执行敏感操作 |
| 对象级归属 | `item.checkPermission(...)` 在具体对象上调用 | 只在 `Jenkins.get()` 全局对象上检查 |
| CSRF | 状态变更端点有 `@RequirePOST` | `doXxx` 无 `@RequirePOST` 且修改状态 |
| 表单端点 | `doFillXxxItems`/`doCheckXxx` 有权限检查 | 凭据填充端点无检查 → 凭据枚举 |
| 全局认证策略 | `Jenkins.isAuthenticationEnabled()`、SecurityRealm 配置 | 存在 `ANONYMOUS` 放行分支 |

快筛：

```bash
grep -rn "checkPermission\|hasPermission" --include="*.java" | wc -l   # 与 doXxx 数量对比，差值即嫌疑面
grep -rn "Overall/Read\|Overall\.READ" --include="*.java"
grep -rn "@RequirePOST" --include="*.java" | wc -l
```

### Jenkins 特有高危信号

- `ACL.impersonate(ACL.SYSTEM)` / `ACL.system`：以系统权限执行，审查调用前的触发者校验
- `ScriptApproval` / `GroovyShell` / `CpsScript`：脚本执行路径是否全部过 Script Security 沙箱
- `Secret.toString()` / `Secret.getPlainText()`：凭据解密点，追踪返回值是否进日志/响应/config.xml
- `HudsonPrivateSecurityRealm` / 密码重置相关：身份绑定校验
- CLI 通道（`CLICommand`、`hudson.cli`）：与 Web 端点是否同等认证强度

---

## 2. Java — Spring / Shiro（通用 Web）

### 路由枚举

```bash
grep -rn "@RequestMapping\|@GetMapping\|@PostMapping\|@PutMapping\|@DeleteMapping" --include="*.java"
grep -rn "actuator\|management.endpoint" --include="*.properties" --include="*.yml" --include="*.yaml"
```

### 鉴权挂载点

| 机制 | 位置 | 危险信号 |
| --- | --- | --- |
| Spring Security | `SecurityFilterChain` Bean、`authorizeHttpRequests` 规则 | 规则顺序错误（宽规则在前）；`permitAll` 范围过宽；`requestMatchers` 用了非规范化路径 |
| 方法级 | `@PreAuthorize` / `@Secured` | Controller 有注解但 Service/内部入口没有 |
| Shiro | `shiro.ini` 或 `ShiroFilterChainDefinition`（`anon`/`authc`/`perms`） | 过滤器链按顺序匹配，宽路径在前导致后面的 `authc` 失效；`/** = anon` |
| 路径匹配 | AntPathMatcher vs PathPattern 解析差异 | `;/`、`..;`、尾斜杠变形绕过 |

---

## 3. Go（ArgoCD / Tekton / Flux / Woodpecker / 云原生 Web）

### 路由枚举

```bash
grep -rn "\.GET(\|\.POST(\|\.PUT(\|\.DELETE(\|\.Handle(\|\.HandleFunc(" --include="*.go"
grep -rn "func (.*) \(.*Context\|gin\.Context\|echo\.Context\)" --include="*.go"   # handler 函数
ls **/*.proto 2>/dev/null; grep -rn "Register\w*Server" --include="*.go"           # gRPC 服务
```

### 鉴权挂载点

| 机制 | 位置 | 危险信号 |
| --- | --- | --- |
| HTTP 中间件 | `router.Use(...)`、`Group` 上挂中间件 | 中间件挂在父 group 但敏感路由注册在全局；中间件顺序在 handler 之后 |
| gRPC 拦截器 | `grpc.UnaryInterceptor` / `StreamInterceptor` | 拦截器中对某些方法名做白名单跳过认证；`agent_id` 等身份字段从 `metadata` 客户端自报读取而非从已认证连接绑定 |
| JWT | `jwt.Parse` / `ParseWithClaims` | `Keyfunc` 返回 nil/弱密钥；不校验 `aud`/`iss`；`Valid` 判断被配置分支跳过 |
| TLS | `tls.Config` | `InsecureSkipVerify: true` |

快筛：

```bash
grep -rn "InsecureSkipVerify" --include="*.go"
grep -rn "jwt.Parse\|VerifyAudience\|VerifyIssuer" --include="*.go"
grep -rn "metadata.FromIncomingContext" --include="*.go"   # gRPC 客户端自报字段
```

---

## 4. Python（Flask / FastAPI / Django / 自研 CI）

### 路由枚举

```bash
grep -rn "@app\.route\|@bp\.route\|@.*\.route(" --include="*.py"          # Flask
grep -rn "@router\.\(get\|post\|put\|delete\|patch\)\|@app\.\(get\|post\)" --include="*.py"   # FastAPI
cat **/urls.py 2>/dev/null                                                  # Django
```

### 鉴权挂载点

| 框架 | 位置 | 危险信号 |
| --- | --- | --- |
| Flask | `@login_required`、`before_request`、装饰器 | 装饰器漏挂（路由有、装饰器无）；`before_request` 中对某些路径 return 跳过 |
| FastAPI | `Depends(get_current_user)`、`APIRouter(dependencies=[...])` | 依赖挂在 router 级但个别路由用裸 `app.` 注册 |
| Django | `MIDDLEWARE` 设置、`@permission_required`、`LoginRequiredMixin` | 中间件顺序；`@csrf_exempt`；API 视图缺 `permission_classes` |
| DRF | `DEFAULT_PERMISSION_CLASSES` | 默认 `AllowAny`；视图级未覆盖 |

快筛：

```bash
grep -rn "verify=False\|verify =False" --include="*.py"                    # TLS 校验关闭
grep -rn "jwt.decode" --include="*.py" -A2                                  # 看 options={"verify_signature": False}
grep -rn "algorithms=\[.*none\|\"none\"" --include="*.py"
grep -rn "@csrf_exempt\|AllowAny\|permission_classes = \[\]" --include="*.py"
grep -rn "check_password\|constant_time_compare\|==" --include="*.py" | grep -i "token\|secret\|password"   # 时序侧信道
```

---

## 5. Ruby — Rails（GitLab / GoCD / 自研平台）

### 路由枚举

```bash
cat config/routes.rb                          # 主路由表
grep -rn "mount\|namespace\|scope" config/routes.rb   # 引擎/命名空间挂载
grep -rn "def \(create\|update\|destroy\)" app/controllers/   # 状态变更动作
```

### 鉴权挂载点

| 机制 | 位置 | 危险信号 |
| --- | --- | --- |
| 认证 | `before_action :authenticate_user!` | 基类挂、子类 `skip_before_action` 跳过 |
| 授权 | `authorize!`（CanCanCan）、Pundit `authorize` | controller 动作未调用；`skip_authorization_check` |
| CSRF | `protect_from_forgery` | API controller 全局 `skip_forgery_protection` 但接受 Cookie 认证 |
| 参数 | strong parameters | `params.permit!` 全放行 → 批量赋值改角色 |

快筛：

```bash
grep -rn "skip_before_action\|skip_authorization\|skip_forgery" --include="*.rb"
grep -rn "params.permit!" --include="*.rb"
grep -rn "protect_from_forgery" --include="*.rb"
```

---

## 6. JS / TS（Express / Nest / Koa / Next.js API）

### 路由枚举

```bash
grep -rn "\.\(get\|post\|put\|delete\|patch\|use\)('\|\.route(" --include="*.js" --include="*.ts"
grep -rn "pages/api\|app/api" -l    # Next.js 文件系统路由
```

### 鉴权挂载点

| 机制 | 位置 | 危险信号 |
| --- | --- | --- |
| Express 中间件 | `app.use(auth)`、`router.use` | **顺序即安全**：路由注册在 `app.use(auth)` 之前即裸奔；中间件忘调 `next()` 或错误分支放行 |
| Passport | `passport.authenticate(...)` | 策略回调中不校验 token 字段 |
| JWT | `jsonwebtoken` 的 `jwt.verify` | 用 `jwt.decode`（不验签）当认证；`algorithms` 未限定 → alg=none / RS256→HS256 混淆 |
| CORS | `cors()` 配置 | `origin: true`/`origin: '*'` 且 `credentials: true` |

快筛：

```bash
grep -rn "jwt.decode\|algorithms" --include="*.js" --include="*.ts"
grep -rn "origin: *true\|origin: *'\*'\|credentials: *true" --include="*.js" --include="*.ts"
grep -rn "req.headers\['x-forwarded-for'\]\|req.ip" --include="*.js" --include="*.ts" | grep -i "trust\|auth\|allow"
```

---

## 7. K8s Operator / Controller（Go / controller-runtime / kubebuilder / Operator SDK）

Operator 的"入口"不是 HTTP 路由而是 Reconcile 循环；其"认证"发生在 API Server 侧（创建 CR 时的 RBAC），**Operator 内部的二次校验才是审计主体**。

### 入口枚举

```bash
grep -rn "func (.*) Reconcile(" --include="*.go"                          # 全部调谐入口
grep -rn "+kubebuilder:rbac" --include="*.go"                             # RBAC 声明收集
ls config/crd/bases/ deploy/ helm/ 2>/dev/null                            # CRD 定义与部署清单
grep -rn "SetupWithManager\|NewControllerManagedBy" --include="*.go"      # controller 注册
```

### 高危信号快筛

```bash
# CR 引用字段（混淆副手通道）
grep -rn "SecretRef\|ConfigMapRef\|secretKeyRef\|TargetNamespace\|targetNamespace" --include="*.go"
grep -rn "ServiceAccountName" --include="*.go" --include="*.yaml"

# 委托检查手段（缺失即嫌疑）
grep -rn "SubjectAccessReview\|SelfSubjectAccessReview\|Impersonate" --include="*.go"

# 自身端点暴露
grep -rn "MetricsBindAddress\|PprofBindAddress\|HealthProbeBindAddress\|:8081\|:9443" --include="*.go"

# 泄露面：Events / status / 日志
grep -rn "recorder.Event\|Eventf(" --include="*.go"
grep -rn "Status\.\(Message\|Reason\) *=" --include="*.go"
grep -rn "log.*\(Secret\|Token\|Password\|Authorization\)" --include="*.go" -i
```

### RBAC 声明审查

- `+kubebuilder:rbac` 注解中出现 `resources=*` / `verbs=*` / `resources=secrets` 且为 ClusterRole → 高危
- YAML 清单中 `cluster-admin` 绑定、`escalate`/`impersonate`/`bind` 动词、`pods/exec` → 高危
- Role vs ClusterRole：命名空间级需求用了 ClusterRole 即未收敛

### Admission webhook

```bash
grep -rn "failurePolicy\|sideEffects" --include="*.yaml" --include="*.go"
grep -rn "admission\|ValidatingWebhook\|MutatingWebhook" --include="*.go" -l
```

- `failurePolicy: Ignore`（校验型 webhook）= Fail Open
- webhook 端点是否验证请求来自 API Server（双向 TLS）

---

## 8. 跨语言通用危险信号

| 信号 | 模式 | 含义 |
| --- | --- | --- |
| 默认凭据 | `admin/admin`、`changeme`、`password123`、出厂 Token | CWE-1392/1393 |
| 硬编码密钥 | `secret = "`、`api_key = '`、私钥 PEM 块 | CWE-798/321 |
| URL 传凭据 | `?token=`、`?api_key=`、`?password=` 拼 URL | CWE-598 |
| 信任客户端身份头 | `X-Forwarded-For`、`X-Real-IP`、`X-User`、`X-Roles` 参与鉴权决策 | CWE-290/807 |
| Referer 鉴权 | `referer`/`referrer` 出现在权限判断分支 | CWE-293 |
| 认证异常放行 | catch 到认证异常后 `return true` / `pass` / 继续执行 | CWE-636（Fail Open） |
| 随机数弱 | `Math.random`、`random.randint`、`time()` 做 token 种子 | CWE-330/337 |
| 密码哈希弱 | `md5(`、`sha1(` 处理密码 | CWE-328/916 |
| 日志打印凭据 | `log.*(password\|token\|secret\|Authorization)` | CWE-532 |
| 配置文件明文 | `.env`、`config.xml`、`*.properties` 中 `password=` 明文 | CWE-260/256 |

---

## 9. 入口台账模板（阶段 2 产出格式）

| # | 入口（路径/方法/RPC） | 信任域 | 认证要求 | 权限要求 | 状态变更? | 目标域 | 覆盖判定 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `POST /api/builds` | 外部→CI 引擎 | Token | `build:create` | 是 | 项目 P | 充分 / 存疑 / 缺失 |

覆盖判定为三选一：**充分**（认证+权限+目标域均校验）、**存疑**（有校验但粒度/路径存疑，转阶段 3）、**缺失**（裸奔，直接转阶段 4 验证）。
