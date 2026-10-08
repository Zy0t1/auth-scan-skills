# F 类检查清单：Kubernetes Operator / Controller 专项

> 适用条件：目标存在 Reconcile 循环、CRD 定义、controller-runtime / client-go / Operator SDK 依赖。Tekton、Flux CD、ArgoCD、cert-manager、各类数据库 Operator 均属此类。
> 核心风险模型：Operator 以自身高权限 ServiceAccount 代替用户执行操作。API Server 只校验了"用户能否创建/更新 CR"——**CR 里引用的目标命名空间、Secret、镜像、URL 是否该用户可及，API Server 不知道，必须由 Operator 在调谐时自行校验**。不校验即混淆副手（CWE-441）。
> 对应 CVE：Flux CD 授权不充分（CVE-2026-23990）、ArgoCD 跨命名空间（CVE-2023-22736）、Tekton 系统 Token 共享存储（CVE-2026-40161）。

## F1. RBAC 收敛（CWE-272 / 266 / 250 / 1188）

- [ ] 收集 Operator 的全部 RBAC 声明（`+kubebuilder:rbac` 注解、deploy/ 下的 ClusterRole/Role YAML、Helm chart rbac 模板），逐项评估是否最小权限。
- [ ] 高危信号：
  - `resources: ["*"]` 或 `verbs: ["*"]` 通配符
  - ClusterRole 绑定 cluster-admin
  - `secrets` 资源具有 `get`/`list`/`watch` 且作用域为 ClusterRole（全集群 Secret 可读 → 等价于全集群凭据泄露）
  - `pods/exec`、`pods/portforward`、`escalate`、`impersonate`、`bind` 动词
- [ ] 权限是否按命名空间收敛（Role vs ClusterRole）？Operator 只需管理少数命名空间却持 ClusterRole 即未收敛。
- [ ] Operator  Deployment 自身是否以 root / 特权模式运行？（CWE-250）
- [ ] 默认安装即开放的权限是否安全？（CWE-1188：资源以不安全默认值初始化）

## F2. 混淆副手：CR 引用目标域校验（CWE-441 / 807 / 862 / 283）

Reconcile 函数中逐字段审查 CR spec 里的**引用类字段**：

- [ ] **secretRef / configMapRef**：引用的命名空间是否限定？用户在自己命名空间建 CR，引用 `kube-system` 或其他租户的 Secret，Operator 是否以自身权限读取并回写/使用？（典型：Tekton 系统级 Git Token 被 TaskRun 用户窃取，CVE-2026-40161）
- [ ] **namespace / targetNamespace 字段**：CR 指定目标命名空间时，Operator 是否校验 CR 创建者对该命名空间的权限？（ArgoCD sharding 下漏检，CVE-2023-22736；Flux CD 超授权范围操作，CVE-2026-23990）
- [ ] **镜像 / chart / URL / git repo 字段**：Operator 是否以自身凭据（imagePullSecret、deploy token）去拉取用户指定的任意地址？→ 凭据泄露给攻击者控制的服务器 + 供应链投毒入口。
- [ ] **ServiceAccount 指定字段**：用户 CR 能否指定 Pod 使用某个高权限 SA？（等价于直接提权）
- [ ] 校验手段是否存在且有效：
  - `SubjectAccessReview`（SAR）/ `SelfSubjectAccessReview` 委托检查——Operator 代 API Server 问"这个用户对那个资源有权限吗"
  - impersonation：以 CR 创建者身份执行下游操作
  - 命名空间白名单 / ownerReference 链校验
- [ ] 若以上全部缺失：**Reconcile 就是一条从"低权限用户写 CR"到"高权限 SA 执行"的直达通道**，逐项列出可造成的操作。

## F3. Admission Webhook（CWE-306 / 346 / 636）

- [ ] webhook 端点是否要求认证（APIServer 双向 TLS），还是对任何来源开放？
- [ ] `failurePolicy` 是 `Fail` 还是 `Ignore`？`Ignore` = webhook 挂了请求照样放行（Fail Open，CWE-636），校验型 webhook 必须为 `Fail`。
- [ ] `sideEffects` 声明是否与实际行为一致？有副作用却声明 `None` 可被干跑（dry-run）绕过。
- [ ] validating webhook 的校验逻辑是否可被 CR 字段变形绕过（大小写、前导零、Unicode 同形、命名空间默认补全时机）？
- [ ] mutating webhook 注入的内容（sidecar、env、volume）是否可被用户 CR 间接控制？

## F4. Operator 自身端点（CWE-306 / 200）

controller-runtime 默认监听的端点是常漏面：

- [ ] `--metrics-bind-address`（默认 `:8080`）：是否绑定 `0.0.0.0` 且无认证？metrics 内容是否含敏感信息（CR spec、错误详情）？
- [ ] `--health-probe-bind-address`：健康探针是否泄露版本/内部状态？
- [ ] **pprof**：`PprofBindAddress`（默认关闭，但若开启绑 `:8081`）是否无认证暴露？pprof 可导出全部内存 profile → 凭据/Token 泄露。
- [ ] leader election 端口、webhook 端口（`:9443`）的暴露面。
- [ ] Operator 是否还带自己的 HTTP API（如 ArgoCD API Server、Tekton Dashboard）？有则回到阶段 2 当作普通 Web 入口建账。

## F5. 凭据与事件泄露（CWE-532 / 209 / 201 / 1230）

- [ ] **Events**：`recorder.Event(...)` / `Eventf(...)` 的 message 是否拼接了 Secret 值、Token、带凭据的 URL？Events 是集群内低权限可读的——写进 Event 等价于公开。
- [ ] **日志**：Reconcile 日志是否打印 CR 全量 spec（可能含内嵌凭据字段）、Secret data、错误响应体（云 API 错误常回显 Authorization 头）？
- [ ] **status 回写**：`status.conditions` / `status.message` 是否回写 Secret 内容或内部错误详情？status 与 spec 同样对所有有 get 权限的用户可见。
- [ ] **错误路径**：调谐失败的错误信息（`err.Error()`）直接进入 Event/log/status 的路径是否经过脱敏？
- [ ] Operator 管理的下游资源（Pod spec、ConfigMap）中是否被写入明文凭据，且其 RBAC 读取面比 Secret 更宽？

## F6. 证明义务（每条候选必须回答）

1. **谁能触发**：创建/更新该 CR 需要什么 RBAC 权限？（精确到 verb + resource + namespace）
2. **谁被执行**：Operator 的 ServiceAccount 实际持有什么权限？（列出 RBAC 清单证据）
3. **跨越了什么**：CR 哪个字段跨越了命名空间/凭据/信任域？Operator 在 Reconcile 哪一行消费该字段而未校验？
4. **拿到了什么**：攻击者最终获得的是其他租户的 Secret、高权限 SA 的执行面，还是集群资源控制权？
