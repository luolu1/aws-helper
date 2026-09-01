# AWS 小助手

AWS 管理面板，覆盖 **EC2 / Lightsail / Bedrock** 三类服务。
一键开机、换 IP、开机脚本注入、终止清理，按账号独立 SOCKS 代理，自动换 IP 监控。

现有的多云面板里 AWS 基本都是"顺带支持"：能列实例但注入不了开机脚本，能开机但换不了 IP，
更没有 IP 被墙后自动更换。这个工具只做 AWS，把这几件事做完整。

数据存 **Postgres**，两种一键部署都会自动装好并初始化数据库：
**systemd（Python 虚拟环境隔离）** 和 **Docker Compose**，可并存于不同端口。

```bash
git clone https://github.com/luolu1/aws-helper.git
cd aws-helper
sudo bash deploy/install.sh          # 交互选择部署方式
```

---

## 三类服务

左侧目录按 AWS 服务分三个大类，功能作为子项挂在各自下面：

```
┌──────────────────┬─────────────────────────────
│ EC2   按需虚拟机  │
│   实例            │
│   一键开机        │      内容区
│   开机脚本        │
│   自动换 IP       │
├──────────────────┤
│ Lightsail 轻量    │
│   轻量实例        │
│   创建实例        │
├──────────────────┤
│ Bedrock  大模型   │
│   模型清单        │
│   调用测试        │
├──────────────────┤
│ 通用              │
│   账号 / 日志     │
│   用户面板        │
└──────────────────┴─────────────────────────────
```

目录常驻，任何页面都能一步跳到其他服务。窄屏（≤900px）折叠成抽屉，点左上 ☰ 展开。

三类服务各自独立的资源模型和 API：

| 服务 | 定位 | 面板能做什么 |
|---|---|---|
| **EC2** | 按需虚拟机 | 一键开机、换 IP、开机脚本、自动换 IP、终止清理 |
| **Lightsail** | 打包定价轻量服务器 | 套餐/蓝图选择、创建、电源操作、静态 IP 管理 |
| **Bedrock** | 托管大模型 API | 模型清单、可用性探测、调用测试 |

三者不通用：Lightsail 的实例、镜像（蓝图）、IP 都是独立体系，套餐按月打包计费；
Bedrock 没有实例概念，只有模型和 token 计费。所以各栏有自己的二级导航。

## 功能

| 功能 | 说明 |
|---|---|
| 一键开机 | 系统类别 → 架构 → 镜像 → 规格 四级选择，镜像和规格实时从 AWS 拉取 |
| Windows 支持 | Windows Server 2019/2022/2025（含简体中文），自动禁用 Linux 专属字段 |
| 开机脚本 | 走 EC2 原生 UserData，cloud-init 首次启动以 root 执行，可存模板复用 |
| 换 IP | 弹性 IP 重分配（不停机）或停机重启换动态 IP，支持 IP 段白/黑名单 |
| 自动换 IP | 后台探测端口，连续失败达阈值自动换 IP —— IP 被墙自动换新，带冷却保护 |
| 多账号代理 | 每个 AWS 账号可配独立 SOCKS5/HTTP 出站代理，互不影响 |
| 用户面板 | 改登录密码、查看和踢下线登录会话、登录记录审计 |
| 批量与 IPv6 | 一次开多台共用密钥对，可选自建 VPC + IGW + v4/v6 双栈路由 |
| 计费保护 | 终止实例时连带清理弹性 IP、残留卷、安全组、自建 VPC，防止继续计费 |
| 账号探测 | 分项检查凭据、账号状态、开机权限、vCPU 配额与当前用量 |

安全设计：AWS Secret Key 和代理地址用 Fernet 加密落盘，登录密码走 PBKDF2-SHA256
加盐哈希（26 万次迭代），会话令牌只存 SHA-256 摘要。同一 IP 连续 5 次密码错误锁定 15 分钟。

---

## 关于 API 调用与自动换 IP

所有 EC2 操作走 boto3 官方 SDK，共 24 个 API，参数和行为对照 AWS 官方文档实现。
几处容易踩坑的地方说明一下：

**换 IP 的两种策略对应 AWS 的两种机制**

`eip` 策略用 `AllocateAddress` → `AssociateAddress`（带 `AllowReassociation`）→
`ReleaseAddress`。官方文档说明关联新 EIP 时旧 EIP 会自动解绑但**仍保留在账户下**，
所以必须显式释放，否则按小时计费。代码里先确认新地址生效再释放旧的 ——
顺序反过来一旦绑定失败会同时丢掉两个地址。

`dynamic` 策略靠 stop/start。官方文档明确列出**三种例外**，这些情况下重启不会分配新地址，
工具会在停机之前就拦住并提示改用 `eip`：

1. 实例绑定了弹性 IP（EIP 在 stop/start 期间保持关联）
2. 实例有辅助网卡
3. 实例有关联了 EIP 的辅助私有 IPv4

**自动换 IP 的判断逻辑**

探测方式是 TCP 连指定端口（默认 22）。这里有个前提要清楚：**探测失败不等于 IP 被墙**，
服务挂了、安全组改了、实例负载过高都会导致同样的结果。工具做不到区分，所以设计上偏保守：

- 单次探测内部重试 2 次，避开瞬时抖动
- 连续失败要达到你设的阈值（默认 3 次）才动手
- 换过 IP 后有 30 分钟冷却期，期间即使继续失败也不再换

冷却期是必要的：新 IP 的路由生效和服务启动都需要时间，此时探测仍然失败是正常现象。
没有冷却会连续换掉整个弹性 IP 配额（**默认每区域只有 5 个**），还把实例反复停机。

如果你的判断标准比端口连通性更精确（比如从境内节点探测、或检测特定服务响应），
建议关掉自动换 IP，改用外部监控调用面板的换 IP 接口。

**Lightsail 与 EC2 的差异**

Lightsail 的资源模型和 EC2 完全不同，所以是独立一栏而非复用 EC2 的抽象：

| | EC2 | Lightsail |
|---|---|---|
| 计费 | 规格、磁盘、流量分开计 | 套餐打包按月，含流量额度 |
| 镜像 | AMI | 蓝图（blueprint），分纯系统和预装应用 |
| 规格 | 实例类型（241 种起） | 套餐（bundle），实测 ap-east-1 有 100 个 |
| 网络 | 安全组 + 弹性 IP | 实例级防火墙 + 静态 IP |
| 区域 | 全部区域 | 实测 19 个区域，比 EC2 少 |

创建时按「蓝图类别 → 蓝图 → 套餐」选择，Windows 蓝图会自动只列 Windows 套餐
（含 `_win_`，价格不同）并禁用 Linux 启动脚本。

删除实例时会一并释放其上的静态 IP —— 未附加的静态 IP 按月计费，和 EC2 的弹性 IP 一样是隐性支出。

**Bedrock 的区域差异**

Bedrock 未在所有区域开放，且同一区域的模型数量相差数倍。用真实账号实测：

```
us-east-1        121 个模型      eu-west-2         71 个模型
us-west-2        114 个模型      ap-northeast-1    68 个模型
us-east-2         90 个模型      sa-east-1         60 个模型
ap-south-1        73 个模型      af-south-1        11 个模型
ap-east-1（香港）  没有 Bedrock 端点
```

区域清单的来源是 **AWS 官方文档《Amazon Bedrock endpoints and quotas》∪ botocore
内置的 endpoint 数据**，不是靠实测账号推断：

- 只靠手写清单会随 AWS 开新区域而过期
- 只靠 botocore 会滞后 —— 实测 `af-south-1` / `eu-north-1` / `ap-northeast-3`
  能正常返回模型清单，但当前 botocore 版本并未收录
- 只靠实测更不行 —— 那只反映当次账号的可见范围，换个账号结论就变

GovCloud 需单独准入流程，已排除；香港没有端点，也排除。

要强调的是：**能列出不等于你的账号能用。** 部分区域可能完全无权访问
（实测 `eu-central-2` / `eu-south-1` / `il-central-1` 返回 AccessDenied）。
页面上的「可用性探测」会实际调一次 API 确认，这才是账号维度的结论。

模型清单会标出调用方式：`ON_DEMAND` 可直接按需调用，`INFERENCE_PROFILE`
必须通过推理配置文件。`LEGACY` 状态的模型 AWS 已计划下线，会单独标记。

**两类模型都能测。** Claude Opus 4/4.1、Sonnet 4.x 这些新模型 AWS 只通过
跨区域推理配置文件开放，`inferenceTypesSupported` 里没有 `ON_DEMAND` ——
直接拿基础模型 id 调会被拒：

```
ValidationException: Invocation of model ID anthropic.claude-opus-4-1-20250805-v1:0
with on-demand throughput isn't supported.
```

所以面板会先调 `ListInferenceProfiles` 建一张「基础模型 → 配置文件 id」映射表，
选到这类模型时自动换成带地理前缀的 id（`us.` / `eu.` / `apac.` / `global.`）：

```
anthropic.claude-opus-4-1-20250805-v1:0     ->  us.anthropic.claude-opus-4-1-20250805-v1:0
```

前缀不能硬算。同一个模型可能同时有 `us.` 和 `global.` 两个配置文件，也可能只有其中一个
（实测 Opus 4.1 就没有 `global.`），所以只认 API 返回的实际清单，优先挑与当前区域同地理组的，
没有则退到 `global.`。缺 `bedrock:ListInferenceProfiles` 权限时按前缀猜一个并由调用报错兜底 ——
猜错只是报错，把模型直接藏起来才是真的没法测。

手动粘贴裸的基础模型 id 也能用：收到上面那个 `ValidationException` 后会自动解析配置文件重试一次。

调用走 Converse 统一接口 —— 各厂商模型的原生请求体格式不同
（Anthropic 要 `anthropic_version`、Amazon 要 `inputText`），Converse 免去逐家维护模板。
`modelId` 同时接受基础模型 id、配置文件 id/ARN 和预置吞吐量 ARN，所以换 id 不用换调用路径。

**终止实例会连带清理，防止残留计费**

按 AWS 官方文档，终止实例后这些**仍然计费或占配额**：

| 资源 | 终止后状态 | 处理 |
|---|---|---|
| 弹性 IP | 解绑但仍分配在账户下，**未绑定按小时计费** | 释放 |
| EBS 卷 | `DeleteOnTermination=false` 的会保留并**持续计费** | 删除 |
| 安全组 | 保留，不计费但占配额 | 删除（本工具创建的） |
| 密钥对 | 保留 | 删除（仅 `awshelper-` 前缀的） |
| 自建 VPC | 保留，堆积后无法创建新 VPC | 删除（仅 IPv6 双栈自建的） |

点终止会弹出确认框列清要删什么，然后走后台任务（要等实例真正 terminated 才能删卷），
进度弹窗实时显示清理过程，结束后给出清理明细。

**不会误删**：默认 VPC、默认安全组、用户自己的密钥对、还有其他实例在用的 VPC。
某一项删不掉会记进"未能清理"而不中断整体流程 —— 尽最大努力止损。

需要保留资源时可以调 API 传 `cleanup: false`。

**账号探测与配额查询**

账号列表每行都有「检测」按钮，也可以点「检测全部账号」批量跑。
检测结果直接显示在表格的**状态**和 **vCPU 配额 / 已用**两列上：

```
备注名   Access Key      默认区域    出站代理    状态                     vCPU 配额/已用
test-li  AKIA****KTKT   ap-east-1  socks5h://  异常 账号身份、vCPU配额   0 / 0  受限
```

配额为 0 会标红并注明「账号受限」—— 这是账号未完成验证或被 AWS 限制的明确信号。
已用接近上限时标黄。

点检测后，完整明细直接展开在**该账号那一行下面**（多账号并排检测互不覆盖），
头部标出区域、实际出口 IP 和是否走代理，然后分项检查：

```
✓ 凭据与网络    可访问 19 个区域
✗ 账号身份      arn:aws:iam::xxx:root（root 凭据风险高，建议换 IAM 用户）
✓ 开机权限      DryRun 通过
✗ vCPU 配额     读到 5 项，其中 5 项为 0（账号未激活或被限制）
```

同时显示各族 vCPU 配额和当前用量（运行中 vCPU、卷容量、空闲弹性 IP）。

为什么要分项：账号被 AWS 封禁时（`Blocked` 错误）**只读接口全部正常，DryRun 也会通过** ——
只有真实写操作才会暴露。分项探测能定位到底是凭据错、权限缺、还是账号本身被限制。
vCPU 配额全为 0 是账号未完成验证或被限制的明确信号。

配额查询需要 `servicequotas:GetServiceQuota` 权限，缺失时只有这一项标为未通过。

**减少 AWS 调用（避免限流与风控）**

频繁调 AWS 除了慢，还容易撞限流和风控。各类数据按变化频率分别缓存：

| 数据 | 缓存粒度 | TTL | 依据 |
|---|---|---|---|
| 实例规格 `DescribeInstanceTypes` | 区域 + 架构 | 6 小时 | 只有 AWS 上新机型才变 |
| Lightsail 套餐 / 蓝图 | 账号 + 区域 | 6 小时 | 基本不变，实测 100 个套餐 |
| Bedrock 模型清单 | 账号 + 区域 | 15 分钟 | 模型访问是控制台申请的，开通后要尽快可见 |
| 实例列表 `DescribeInstances` | 账号 + 区域 | 10 秒 | 用户盯着看的东西，窗口必须短于反应时间 |
| 镜像清单 | 本地静态 | 不调 AWS | 不需要缓存 |

**改了状态就立刻失效，不等 TTL。** 开机、关机、重启、终止、换 IP、创建轻量实例
之后都会主动清掉对应缓存 —— 否则 10 秒窗口正好把变更前的快照端回来，
用户看到「明明关机了却还显示 running」。换密钥或换代理会清掉该账号全部缓存，
因为出口 IP 和权限都可能变了。

**这些一律不缓存**：账号探测、代理连通性测试、Bedrock 可用性探测、弹性 IP 列表。
前四个是「现在就检查一次」的动作，缓存等于取消了它的意义；弹性 IP 列表用来决定
释放哪些地址，给旧数据可能误删刚绑上的 IP，或漏掉正在计费的泄漏。

页面会如实标出数据新鲜度（「数据缓存于 12 秒前」），旁边有强制刷新，不假装是刚拉的。

**自动换 IP 的调用去重**

同一 (账号, 区域) 下的多条规则共用一次 `DescribeInstances`。原先每条规则各拉一次，
而规则是无人值守一直跑的 —— 20 条规则就是每轮 20 次调用，这是最容易触发风控的地方。

共享清单超过 30 秒就重拉：一轮里每条失败规则要跑两次 5 秒 TCP 探测，整轮可能上百秒，
拿旧 IP 去探测会记一次假失败，累积到阈值就白换一次 IP、白烧弹性 IP 配额。
换过 IP 之后立即作废本轮清单和页面缓存。

**关于出口 IP 与 AWS 风控**

探测会报出 AWS 实际看到的出口 IP —— 这一项常被误解。你在浏览器里看到的自己的 IP、
面板服务器的 IP、以及面板调 AWS 时的出口 IP，可能是三个不同的地址：

| 通路 | 出口 |
|---|---|
| 你的浏览器 → 面板 | 你的宽带 IP |
| 面板 → AWS（未配代理） | 面板服务器 IP |
| 面板 → AWS（配了代理） | 代理服务器 IP |

配了账号级代理后，**所有** AWS API 调用都走代理，包括开机、换 IP、查配额。
所以 AWS 眼里这个账号的活动全部来自代理 IP，跟你浏览器用什么 IP 登录面板无关。

风控层面要注意：数据中心 IP 段（云厂商、IDC）比住宅 IP 更容易被判定为异常，
尤其配合新账号 + 短时间内频繁 launch/terminate。如果出口 IP 显示的是数据中心地址
而账号又被限制，两件事可能相关。

**镜像和规格都从 AWS 实时拉取**

开机表单是四级级联：**系统类别 → 架构 → 镜像 → 规格**。

系统类别分 Linux / UNIX 和 Windows，架构分 64 位（x86）和 64 位（ARM），
选完后镜像和规格列表实时刷新：

- 镜像按系统 + 架构筛选，Windows + ARM64 组合为空（AWS 没发布该镜像）
- 规格来自 `DescribeInstanceTypes`，**按架构过滤且按区域查询**。
  实测 ap-east-1 有 241 种 x86_64 规格，us-east-1 有 949 种 —— 写死清单必然出错
- 免费额度机型会标注，默认自动选中

但**不会每次切下拉都重新拉一遍**。规格清单按 (区域, 架构) 缓存 6 小时，
前端再按 (账号, 区域, 系统, 架构) 记一层，来回切系统和架构不产生任何 AWS 调用 ——
频繁调用除了慢，还容易撞上 AWS 的限流和风控。

镜像清单本身是本地静态数据，不碰 AWS。

选 Windows 时会自动隐藏并禁用 Linux 专属字段（开机脚本、root 密码、apt 预装包），
后端也会拒绝这些参数 —— Windows 的 cloud-init 是 EC2Launch，
传 bash 脚本上去不报错但静默不执行，比直接拒绝更难排查。
Windows 实例的结果区显示 RDP 连接方式，并提示管理员密码需用密钥在控制台解密。

**镜像解析用官方 SSM 公共参数**

Ubuntu / Amazon Linux 的 AMI ID 优先通过发行方发布的 SSM 公共参数解析，
这是 AWS 与 Canonical [推荐的官方方式](https://documentation.ubuntu.com/aws/aws-how-to/instances/find-ubuntu-images/)：

```
/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id
/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64
```

参数由发行方维护，各区域自动解析、始终指向最新版本，不会因为命名规则变更而失效。

拿不到时（IAM 缺 `ssm:GetParameter`、区域无此参数）自动退回 `DescribeImages`
名称匹配，每个系统配多个候选 pattern 依次尝试。都失败会明确提示可在
「指定 AMI ID」里手动填。

**安全组默认全部放通**

新建实例的安全组默认对 `0.0.0.0/0` 开放**全部端口和全部协议**（IPv6 双栈时同时开 `::/0`），
开箱即用不需要逐个加端口。开机表单里取消勾选「放通全部端口」可改为只放通指定端口。

这是刻意的默认值，代价要清楚：实例上任何监听端口都直接暴露在公网。
配合开机脚本里的 root 密码登录，等于一台全端口开放 + 密码登录 root 的机器。
生产环境建议取消勾选，只开实际需要的端口。

**关于测试**

测试用 [moto](https://github.com/getmoto/moto) 模拟 EC2，不碰真实账号也不产生费用。
但要说清楚：moto 是模拟器，和真实 AWS 存在行为差异 —— 开发过程中就遇到过
moto 允许多个 EIP 同时绑到一个实例、`Ipv6AddressCount` 不生效等情况。
所以涉及 AWS 语义的判断（EIP 自动解绑、stop/start 换 IP 的例外条件）都以官方文档为准，
而不是以 moto 的表现为准。**首次在生产账号使用前，建议先在测试账号上验证一遍。**

---

## 一键部署

克隆仓库后执行安装脚本，两种方式二选一：

```bash
git clone https://github.com/luolu1/aws-helper.git
cd aws-helper

# 交互选择部署方式
sudo bash deploy/install.sh

# 或直接指定
sudo bash deploy/install.sh --mode systemd     # systemd + Python 虚拟环境
sudo bash deploy/install.sh --mode docker      # Docker Compose
```

装完控制台会打印**访问地址和初始密码**，直接登录即可。

### 常用参数

| 参数 | 说明 |
|---|---|
| `--mode systemd\|docker` | 部署方式，省略则交互询问 |
| `--host ADDR` | 监听地址，默认 `127.0.0.1`。填 `0.0.0.0` 会二次确认 |
| `--port PORT` | 监听端口，默认 `8765` |
| `--password PASS` | 指定初始密码，省略则自动生成强密码 |
| `--yes` | 非交互，全部用默认值 |

例子：

```bash
# 对外暴露在 8080 端口，指定初始密码
sudo bash deploy/install.sh --mode docker --host 0.0.0.0 --port 8080 --password 'MyStr0ng!Pass'
```

脚本**幂等**，重复执行只更新程序和依赖，已有的密码、AWS 凭据、换 IP 规则都保留。

### 方式一：systemd + Python 虚拟环境

依赖装在 `/opt/aws-helper/venv`，**完全不碰系统 Python**，避免环境冲突。
以专用系统用户 `awshelper` 运行，非 root。Postgres 由脚本自动安装并初始化。

| 项目 | 路径 |
|---|---|
| 程序 | `/opt/aws-helper/aws_helper` |
| 虚拟环境 | `/opt/aws-helper/venv` |
| 数据库 | 本机 Postgres，库 `awshelper`、角色 `awshelper` |
| 加密密钥 | `/var/lib/aws-helper/secret.key`（权限 700 目录） |
| 配置 | `/etc/aws-helper/aws-helper.env`（权限 640） |
| 服务单元 | `/etc/systemd/system/aws-helper.service` |

单元里开了 `ProtectSystem=strict`、`NoNewPrivileges`、`PrivateTmp`，只有数据目录可写，
并声明 `Requires=postgresql.service` 保证启动顺序。开机自启，异常退出 5 秒后自动重启。

建库和建角色都是**幂等**的：重装会保留已有数据，数据库口令也从
`/etc/aws-helper/aws-helper.env` 沿用（重新生成就连不上已初始化的库了）。

缺 `python3-venv` 或 Postgres 时脚本会自动安装。要求 **Python 3.10+**。

### 方式二：Docker Compose

两个容器：`aws-helper`（面板）+ `aws-helper-db`（Postgres 16），
用 `depends_on: service_healthy` 保证面板在库 ready 之后才启动 ——
否则首次建表会失败。

| 卷 | 内容 |
|---|---|
| `aws-helper-db` | Postgres 数据 |
| `aws-helper-data` | Fernet 加密密钥 |

**两个卷都要备份。** 密钥和数据分开存放是有意的：库泄漏时凭据仍解不开，
但反过来说，密钥丢了数据也无法恢复。

数据库不映射主机端口，只允许 compose 网络内访问。面板容器内以 uid 999 的
`awshelper` 用户运行，带 `no-new-privileges`，内置 healthcheck。
端口默认只映射到 `127.0.0.1`，日志轮转限制 10MB × 3 份。

`POSTGRES_PASSWORD` 在 `.env` 里，卷首次初始化时写入库中，**之后不可更改**。
丢了这个值就连不上已有数据卷。

脚本会先验证 compose **真的能连上 docker 守护进程**，而不只是检查命令存在 ——
`docker-compose` 1.29 在新版 requests 环境下会抛
`Not supported URL scheme http+docker` 而完全不可用。遇到这种情况脚本会自动下载
官方 compose v2 插件。

### 两种方式并存

想同时跑两套（比如一套生产、一套试新版），换个端口装第二种即可：

```bash
sudo bash deploy/install.sh --mode systemd --port 8765
sudo bash deploy/install.sh --mode docker  --port 8766
```

两者完全隔离：

| | systemd | docker |
|---|---|---|
| 安装目录 | `/opt/aws-helper` | `/opt/aws-helper-docker` |
| 数据 | `/var/lib/aws-helper` | docker 卷 `aws-helper-data` |
| 管理命令 | `aws-helper-systemd` | `aws-helper-docker` |

两套密码、AWS 账号、脚本模板各自独立。`aws-helper` 是软链，指向最近一次安装的那套。

---

## 管理命令

两种部署共用一套命令，自动路由到 systemctl 或 docker compose：

```bash
aws-helper status            # 查看运行状态
aws-helper logs -f           # 跟踪日志
aws-helper start             # 启动
aws-helper stop              # 停止
aws-helper restart           # 重启
aws-helper reset-password    # 重置登录密码
aws-helper info              # 查看密码/会话/登录记录
aws-helper logout-all        # 下线所有登录会话
aws-helper uninstall         # 卸载
```

两种方式并存时，用带后缀的命令明确指定：`aws-helper-systemd` / `aws-helper-docker`。

---

## 忘记密码

面板不做邮件找回（多一层 SMTP 依赖，且邮箱本身可能失守）。
密码重置**必须在服务器上操作** —— 能登服务器就等于能改，这是最可靠的凭证。

### 最简单的方式

```bash
# 生成一个随机强密码
sudo aws-helper reset-password

# 或指定自己的密码
sudo aws-helper reset-password --password '你的新密码'
```

命令会打印新密码，直接用它登录。重置会**作废所有登录会话**，
也会**清掉登录失败锁定** —— 被锁在门外时用它能立刻恢复。

### 按部署方式手动操作

如果 `aws-helper` 命令不可用（比如没用安装脚本部署），按下面来。

**systemd 部署：**

```bash
sudo -u awshelper env AWS_HELPER_DATA=/var/lib/aws-helper \
    PYTHONPATH=/opt/aws-helper \
    /opt/aws-helper/venv/bin/python -m aws_helper.cli reset-password
```

**Docker 部署：**

```bash
cd /opt/aws-helper-docker    # 或你的 compose 目录
docker compose exec -T aws-helper python -m aws_helper.cli reset-password
```

**源码直接运行：**

```bash
cd /path/to/aws-helper
AWS_HELPER_DATA=~/.aws-helper python3 -m aws_helper.cli reset-password
```

### 相关命令

```bash
aws-helper info          # 查看密码更新时间、活跃会话、最近登录记录
aws-helper logout-all    # 只下线所有会话，不改密码
```

弱密码需要显式加 `--force`。密码要求至少 10 位，且包含大写、小写、数字、符号中的至少三类。

### 登录后修改密码

登录面板 → 右上「用户面板」→ 修改登录密码。需要输入当前密码，
改成功后**其他设备的登录立即失效**，当前浏览器保持登录。

同一页面还能看到所有活跃会话（IP、客户端、登录时间）并单独踢下线，以及登录成功/失败记录。

---

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `AWS_HELPER_DATABASE_URL` | `postgresql://awshelper@127.0.0.1:5432/awshelper` | Postgres 连接串 |
| `AWS_HELPER_DB_SCHEMA` | `public` | 数据库 schema，多环境共库时可分开 |
| `AWS_HELPER_DB_POOL` | `8` | 连接池上限 |
| `AWS_HELPER_PASSWORD` | 随机生成 | **仅**用作首次启动的初始密码，库里已有密码后不再生效 |
| `AWS_HELPER_DATA` | `~/.aws-helper` | 加密密钥存放目录（业务数据在数据库） |
| `AWS_HELPER_HOST` | `127.0.0.1` | 监听地址 |
| `AWS_HELPER_PORT` | `8765` | 监听端口 |
| `AWS_HELPER_SESSION_TTL` | `86400` | 会话有效期（秒） |
| `AWS_HELPER_SESSION_KEY` | 随机生成 | 会话签名密钥，不设则重启后需重新登录 |
| `AWS_HELPER_SECRET` | 自动生成 | Fernet 加密密钥，用于加密 AWS 凭据 |
| `AWS_HELPER_DOCS_URL` | 本仓库地址 | 登录页「忘记密码」链接目标 |

`AWS_HELPER_PASSWORD` 只在库里还没有密码时用作初始值 —— 否则你在面板改了密码，
重启又被环境变量覆盖回去。

---

## 数据存储

业务数据全部在 **Postgres**，`AWS_HELPER_DATA` 目录只放一个文件：`secret.key`。

| 位置 | 内容 |
|---|---|
| Postgres | AWS 账号（密文）、密钥对（密文）、代理（密文）、脚本模板、换 IP 规则、会话、日志 |
| `secret.key` | Fernet 加密密钥 |

**两者都要备份，且缺一不可**：库里的凭据用这把密钥加密，密钥丢了数据解不开；
密钥在手但库没了同样什么都没有。分开存放的意义是数据库被拖走时凭据仍然安全。

### 从旧版本（SQLite）升级

早期版本用 SQLite。升级后**首次启动会自动迁移** —— 检测到数据库为空且
数据目录里存在 `aws-helper.db` 时，把 9 张表的数据全部导入，包括加密字段
（密钥没变所以照样能解密）、密码哈希、日志。

迁移完成后旧文件改名为 `aws-helper.db.migrated`，下次启动不再处理。
如果库里已有数据，绝不会导入 —— 避免误覆盖。

`SERIAL` 序列会在迁移后校正到当前最大 id，否则下一次插入会撞主键。

### 备份

**systemd 部署：**

```bash
sudo -u postgres pg_dump awshelper > awshelper-$(date +%F).sql
sudo cp /var/lib/aws-helper/secret.key ./secret.key.bak
```

**Docker 部署：**

```bash
cd /opt/aws-helper-docker
docker compose exec -T postgres pg_dump -U awshelper awshelper > awshelper-$(date +%F).sql
docker compose exec -T aws-helper cat /data/secret.key > secret.key.bak
```

恢复时先建空库导入 SQL，再把 `secret.key` 放回数据目录。

---

## 安全须知

**面板持有你的 AWS 凭据。** 默认只监听 `127.0.0.1`。

要对外访问，强烈建议放到 HTTPS 反代之后，而不是直接 `--host 0.0.0.0`：

```nginx
server {
    listen 443 ssl;
    server_name aws.example.com;

    ssl_certificate     /etc/letsencrypt/live/aws.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/aws.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8765;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

面板会读 `X-Forwarded-For` 第一跳来做登录限流，所以反代要正确传这个头。

IAM 建议用只有 EC2 权限的独立用户，不需要账单权限。所需 API 清单见
[aws_helper/README.md](aws_helper/README.md#iam-权限)。

---

## 卸载

```bash
sudo aws-helper uninstall
```

会分两次确认：先确认卸载，再单独询问是否删除数据 —— 不会顺手把 AWS 凭据一起清掉。

---

## 开发

```bash
pip install -r requirements.txt
python3 -m aws_helper                    # 直接运行，默认 127.0.0.1:8765
```

跑测试：

测试需要一个可用的 Postgres（数据库层不做 mock，直接跑真实 SQL）：

```bash
docker run -d --name pgtest -e POSTGRES_PASSWORD=test \
    -e POSTGRES_DB=awshelper -p 15432:5432 postgres:16-alpine

pip install "moto[ec2,server]==5.0.28" pytest httpx PyYAML
python3 -m pytest tests/ -q
```

连接串默认 `postgresql://postgres:test@127.0.0.1:15432/awshelper`，
可用 `AWS_HELPER_TEST_DATABASE_URL` 覆盖。库不可达时相关测试自动 skip。

每个测试独占一个随机 schema，跑完自动 DROP —— 这样能验证真实的唯一约束、
upsert 语义和级联删除，而不是 mock 掉 SQL 假装通过。

485 个测试。AWS 侧全部用 moto 模拟，不碰真实账号；数据库侧用真实 Postgres，
不 mock SQL。覆盖开机全链路、UserData 注入与顺序、安全组端口、换 IP 两种策略、
弹性 IP 泄漏与孤儿回收、凭据与代理加密、账号编辑、密码哈希与登录锁定、
CLI 重置、SQLite 迁移与序列校正、并发写入、缓存与失效、部署脚本静态检查。

代理相关测试会起一个真实的 SOCKS5 服务器（支持 RFC 1929 认证），
断言代理端确实记录到了目标连接 —— 否则"代理生效"是无法证伪的。

想不用真实凭据看效果，跑演示环境：

```bash
bash aws_helper/demo/start.sh 127.0.0.1 8765
```

用 moto 模拟 AWS 后端并预置几台实例和脚本模板，不产生任何真实费用。

---

## 项目结构

```
aws_helper/
  auth.py             密码哈希、强度校验、登录锁定
  cli.py              密码重置 / 状态查看 / 下线会话
  store.py            Postgres 持久层（加密凭据、会话、规则、日志、SQLite 迁移）
  cache.py            进程内 TTL 缓存（压掉重复 AWS 调用）
  autoip.py           自动换 IP 监控循环
  tasks.py            后台任务与进度跟踪
  core/aws.py         boto3 客户端工厂、SOCKS 代理、区域与镜像目录、账号探测
  core/userdata.py    开机脚本渲染与校验
  core/launch.py      EC2 一键开机、实例列表、电源操作、终止清理
  core/ipchange.py    换 IP 两种策略、弹性 IP 清理
  core/lightsail.py   Lightsail 套餐、蓝图、实例、静态 IP
  core/bedrock.py     Bedrock 模型清单、可用性探测、Converse 调用
  web/app.py          FastAPI 路由
  web/templates/      左侧目录布局 + 十个页面
  demo/               演示环境（moto 后端 + 预置数据）
deploy/install.sh     一键部署（systemd / docker 两种方式）
Dockerfile            容器镜像（非 root + healthcheck）
docker-compose.yml    compose 服务定义
requirements.txt      固定版本的运行时依赖
tests/                485 项测试
```

更详细的功能说明见 [aws_helper/README.md](aws_helper/README.md)。

---

## 免责声明

本项目仅用于管理你自己拥有或已获授权的 AWS 资源。
使用者需自行遵守 AWS 服务条款和所在地法律法规，因使用不当造成的任何后果由使用者自行承担。
