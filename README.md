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
│   DDNS 解析       │
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
| 开机即部署 | 创建时可勾选自动换 IP 探测器和 DDNS，写进 cloud-init 开机自动装好 |
| Windows 支持 | Windows Server 2019/2022/2025（含简体中文），自动禁用 Linux 专属字段 |
| 开机脚本 | 走 EC2 原生 UserData，cloud-init 首次启动以 root 执行，模板可存可编辑 |
| BBR 加速 | 开机勾选即开启 BBR + fq，只改 sysctl 不换内核；也可存成模板复用 |
| 换 IP | 弹性 IP 重分配（不停机）或停机重启换动态 IP，支持 IP 段白/黑名单 |
| 自动换 IP | 实例自己朝境内探测，被墙才上报，面板换 IP；也支持面板侧探测端口 |
| 部署状态 | 自动换 IP 和 DDNS 都能在面板看部署状态，手动检测给出具体排查方向 |
| 多账号代理 | 每个 AWS 账号可配独立 SOCKS5/HTTP 出站代理，互不影响 |
| 用户面板 | 改登录密码、查看和踢下线登录会话、登录记录审计 |
| DDNS 解析 | 填好配置生成一键部署脚本给任意机器用，或交面板托管；Cloudflare，A / AAAA |
| 批量与 IPv6 | 一次开多台共用密钥对，可选自建 VPC + IGW + v4/v6 双栈路由 |
| 计费保护 | 终止实例时连带清理弹性 IP、残留卷、安全组、自建 VPC，防止继续计费 |
| CPU 积分 | T 系列强制 standard，不产生超额积分账单；已有实例可查看并一键改回 |
| 账号探测 | 分项检查凭据、账号状态、开机权限、vCPU 配额与当前用量 |

安全设计：AWS Secret Key 和代理地址用 Fernet 加密落盘，登录密码走 PBKDF2-SHA256
加盐哈希（26 万次迭代），会话令牌只存 SHA-256 摘要。同一 IP 连续 5 次密码错误锁定 15 分钟。

---

**重装系统（换根卷）**

实例列表每行有「重装」。用 EC2 的 `ReplaceRootVolume` —— 这是 AWS 上最贴近
"重装系统"的原语，只换根卷，别的都不动：

| | |
|---|---|
| 保留 | 实例 ID、私有 IP、公网/弹性 IP、安全组、网卡、挂载的数据卷、IAM 角色、实例类型 |
| 清空 | 根卷上的一切 —— 系统、已装软件、`/root` 与 `/home`、所有配置 |

对比另外两条路：终止后重开会让实例 ID 和动态公网 IP 都变、安全组要重建，
等于换了台机器；快照回滚只能回到某个时间点，装不了别的系统。

不选镜像就是用原 AMI 重铺（恢复出厂），也可以下拉换成别的系统，或直接填 AMI ID。

**架构必须匹配。** x86 实例铺 ARM 镜像 AWS 会接受请求，但换完实例起不来，
且没有明显报错 —— 用户只看到一台连不上的机器。所以点开弹窗和每次改镜像都会
预检一次，不匹配就直接禁掉确认按钮并说明原因：

```
镜像架构 arm64 与实例架构 x86_64 不匹配 —— 换上去实例起不来。
请选 x86_64 的镜像，或者先换实例类型
```

预检还会挡住已终止的实例和 instance-store 根卷（临时盘，没有卷可替换）。

**旧根卷默认删除。** 不删会一直按 EBS 容量计费，而点重装通常就是不要那些数据了。
想留一份做取证可以取消勾选，之后自己去清。

过程中实例会重启，实测 3-5 分钟不可用。任务状态是 `pending → in-progress →
succeeded`，轮询到终态为止；超时不等于失败，任务还在后台跑，报错会带上任务 ID。

`failed-detached` 这个状态要特别注意：旧卷已卸载但新卷没挂上，**实例当前没有
可启动的根卷**，需要在控制台手动挂一个或用快照恢复。只报"失败"会让人以为
什么都没发生。

**重装完会直接给出连接方式**，因为最容易卡住人的是登录用户名跟着系统变了：

```
系统          Ubuntu 24.04
公网 IP       1.2.3.4
密钥对        prod-key（原私钥继续可用）
登录用户      ubuntu
SSH 命令      ssh -i prod-key.pem ubuntu@1.2.3.4
保留的数据卷   /dev/sdf
```

Ubuntu 是 `ubuntu`、Debian 是 `admin`、Amazon Linux / RHEL 是 `ec2-user`，
换个系统就换个用户。选内置镜像时用它声明的用户；恢复出厂或手填 AMI 时从镜像
名字推断，认不出来就留空并列出常见几个，而不是给一个错的让你白试。

**原私钥继续可用。** 换根卷不影响实例的 KeyName 属性，新根卷的 cloud-init
照旧从 IMDS 取同一个公钥，不需要重新生成密钥对。

**重装时可以顺手换掉登录凭据**

弹窗里「重装后的登录凭据」三选一：

| 选项 | 做什么 |
|---|---|
| 沿用原密钥对（默认） | 什么都不改，原私钥在新系统里照旧可用 |
| 设一个 root 密码 | 重装完设密码并打开 SSH 密码登录，之后 `ssh root@IP` 即可 |
| 写入我自己的 SSH 公钥 | 把你粘的公钥**追加**进新系统的 `authorized_keys` |

**这一步走 SSM，不走 user-data。** 这不是偷懒，是只有这条路走得通：

- `ModifyInstanceAttribute` 改 user-data **要求实例处于 stopped 状态**，
  而停机会让没绑弹性 IP 的实例丢掉公网地址 —— 重装的卖点正是"IP 不变"
- 实例的 `KeyName` 属性**根本不在可修改属性列表里**，换密钥对这条路不存在

所以点开弹窗会先探一次 SSM 注册状态，用不了就把这两个选项**禁掉并显示原因**，
而不是让你填完点了才发现设不上。重装本身不受影响，确认按钮照常可用。

```
改凭据不可用  实例未注册到 SSM。需要挂带 AmazonSSMManagedInstanceCore
             的 IAM 实例配置文件（控制台「操作 → 安全 → 修改 IAM 角色」）
重装本身不受影响，原密钥对在新系统里照旧可用。
```

**顺序在这里有讲究。** 换根卷完成后 SSM Agent 要等新系统起来才重新注册，
实测 1-3 分钟，所以会轮询等它回来（上限 5 分钟）再下发命令。**等不到不算重装失败** ——
根卷已经换好了，只是凭据没设上，结果面板会标出来让你之后用「重置密码」补：

```
凭据未设上  重装成功，但等了 300s SSM Agent 仍未在新系统上注册，
           凭据没能设置。可稍后在实例页用「重置密码」重试
```

**公钥当场校验，不合法就不动根卷。** 乱填的公钥写进 `authorized_keys` 不报错，
但登录时静默失败。所以在下发换根卷之前先验：类型前缀在白名单里、主体是合法
base64、且 base64 内部声明的类型和前缀一致（把两把键拼起来能过 base64 检查）。
粘成私钥是最常见的误操作，报错会直接点明。

**写 authorized_keys 的权限必须对。** OpenSSH 的 `StrictModes` 默认开启，
`.ssh` 目录或文件属主不对、权限过宽时会**静默拒绝**该公钥，日志里只有一句
`Authentication refused: bad ownership or modes`。所以目录 700、文件 600、
属主设成目标用户，家目录从 `getent passwd` 读而不是假设 `/home/<user>`
（root 的家是 `/root`）。这些都在真实 sshd 上验证过。

**追加而不是覆盖** —— 覆盖会踢掉 AWS 密钥对注入的那把公钥，你原来的私钥就废了。
重复执行也不会堆积同一把公钥。

设了新凭据时结果面板只显示一个登录用户，不再摆镜像的默认用户 ——
「登录用户 ubuntu」和「公钥已写入 root」并排出现只会让人不知道该用哪个。

**主机密钥会重建**，旧的 `known_hosts` 记录会让连接被拒，所以结果里直接给出
要执行的清理命令：

```bash
ssh-keygen -R 1.2.3.4
```

Windows 实例给的是 RDP 地址而不是 SSH 命令，也不支持写入公钥
（EC2Launch 不读 `authorized_keys`，静默不生效比直接拒绝更难查）。

**重置实例登录密码**

实例列表每行有「重置密码」。走 Systems Manager 在实例内执行改密码 ——
这是唯一不需要"先能登进去"的路径（SSH 改密码的前提是已经能 SSH，
密码忘了正好用不上）。

**只改密码是不够的。** 官方云镜像默认 `PasswordAuthentication no`，
改完密码仍然登不进去。所以顺带打开密码认证，并且：

- Ubuntu 22.04+ 用 `Include /etc/ssh/sshd_config.d/*.conf` 覆盖主配置，
  只改主配置会被片段盖掉 —— 所以写一个高优先级片段 `00-aws-helper-password.conf`
- 云镜像的 root 账号默认是锁定状态，不 `passwd -u` 密码认证照样失败
- 重启 sshd 前先 `sshd -t` 校验，配置写坏了重启会把自己彻底关在门外，
  而这台机器的密码正是刚才要重置的那个
- 密码从 stdin 喂给 `chpasswd`，不作为命令行参数 —— 同机任何用户 `ps` 一下就能看到

**前提：实例挂了带 `AmazonSSMManagedInstanceCore` 的 IAM 实例配置文件。**
开机时没挂也能补（控制台「操作 → 安全 → 修改 IAM 角色」，附加后等 1-2 分钟
自动注册，不用重启）。点开弹窗会先探一次 SSM 注册状态，不可用时直接把
上面这段说明显示出来，而不是让你填完密码点了才发现不行。

Windows 走 `AWS-RunPowerShellScript` + `Set-LocalUser`。

密码强度按面板登录密码的同一套标准校验 —— 这个密码是要开着 SSH 密码登录用的，
弱口令等于把机器交出去。密码不写日志，也不进返回值。

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

**自动换 IP 有两种探测模式**

| 模式 | 谁在探测 | 判断的是什么 |
|---|---|---|
| `local`（面板探测） | 面板服务器 | 从面板到实例的某个端口通不通 |
| `agent`（实例探测） | 实例自己 | 从实例出网到国内站点通不通 |

**要判断「IP 被墙」必须用 agent 模式。** 墙是单向的：面板通常也在海外，
从海外连实例一直是通的，被墙了也探不出来。只有站在实例上、朝境内方向探测，
才能发现出网被拦。

`local` 模式的探测方式是 TCP 连指定端口（默认 22）。这里有个前提要清楚：
**探测失败不等于 IP 被墙**，服务挂了、安全组改了、实例负载过高都会导致同样的
结果。工具做不到区分，所以设计上偏保守：

- 单次探测内部重试 2 次，避开瞬时抖动
- 连续失败要达到你设的阈值（默认 3 次）才动手
- 换过 IP 后有 30 分钟冷却期，期间即使继续失败也不再换

冷却期是必要的：新 IP 的路由生效和服务启动都需要时间，此时探测仍然失败是正常现象。
没有冷却会连续换掉整个弹性 IP 配额（**默认每区域只有 5 个**），还把实例反复停机。

### agent 模式：实例自己判断被墙

有两条部署路径：

**A. 创建实例时勾选**（推荐，省一步）—— 在一键开机页的「开机时顺带部署服务」
卡片勾上，配好探测目标、间隔、阈值和换 IP 方式，脚本会内联进 cloud-init，
开机自动装好，规则也自动建好。不用登录机器。

**B. 给已有实例部署** —— 在自动换 IP 页选好实例，点「开启实例侧探测」，
面板生成一段一键部署脚本，复制到实例上以 root 执行。

两条路装出来的东西完全一样：一个 systemd 服务（`aws-helper-guard`），常驻循环探测。

创建时部署有个顺序问题：`user-data` 必须在 `RunInstances` 之前定稿，那时实例 ID
还不存在。所以脚本改为开机后**从 EC2 元数据服务（IMDS）自己读**实例 ID，上报时
带上，面板按 (凭证, 实例 ID) 定位规则。手工生成的脚本仍然写死 ID，两者不冲突 ——
配置里有值就用它，IMDS 只在为空时兜底。

代价说清楚：**同一批创建的实例共用一个上报凭证**。其中一台被入侵后，可以冒充
同批的另一台触发换 IP。跨批次和跨账号都拦得住，批内拦不住 —— 要批内隔离就得给
每台不同的 `user-data`，而 `RunInstances` 一次只接受一份。介意的话用路径 B，
每台单独生成。

**部署失败不会影响开机。** 部署段用 `|| echo ...` 兜住，失败只留日志在
`/var/log/aws-helper-autoip-deploy.log`，不会中止整段 `user-data` ——
否则你自己写的开机脚本（永远排在最后）就不执行了。

**Windows 不支持这两个服务**（都是 bash + systemd）。切到 Windows 镜像时勾选框
会自动取消并禁用，而不是静默忽略让你以为装好了。

**探测正常时一个包都不发。** 这是刻意的：正常状态是绝大多数时候，每次都上报
纯属浪费面板资源和流量。只在连续失败达到阈值时才 POST 一次。

但完全不通信就分不清「一切正常」和「脚本挂了」，所以另有一个**低频心跳**，
周期是探测间隔的 10 倍，只带一个时间戳。面板据此判断部署状态。

上报后脚本会**暂停探测 120 秒**：面板换 IP 要几十秒到几分钟，这期间继续探测会
立刻又达到阈值、重复上报。面板侧也有冷却，两边各一层。

**上报走独立端口（默认 8766），不是面板主端口。** 主端口上有 AWS 凭据、密钥
下载、实例登录密码，不能为了给实例开一个上报入口就把整个面板暴露给它们。
上报端口上只有 `/report` 和 `/health` 两个路由，连 OpenAPI schema 都关掉了。

鉴权用 `X-Guard-Token`，**每条规则一个独立凭证**，库里只存 SHA-256 摘要
（明文只在生成脚本那一刻返回一次）。凭证还绑定实例 ID —— 脚本被复制到别的机器
时，那台机器的网络状况不代表这台，上报会被 403 拒绝。重新生成脚本会换发凭证，
旧脚本立刻失效。

部署相关的环境变量：

```bash
AWS_HELPER_REPORT_PORT=8766                      # 上报端口，默认 8766
AWS_HELPER_REPORT_HOST=0.0.0.0                   # 监听地址
AWS_HELPER_REPORT_URL=http://面板地址:8766        # 写进脚本的上报地址
```

`AWS_HELPER_REPORT_URL` 建议显式设置。不设时面板会用自己的出站 IP 拼一个，
但那个地址在 NAT 或多网卡环境下未必是实例能连到的。

**实例的安全组不用改** —— 上报是实例主动出网，只要实例能访问面板的上报端口即可。
要改的是**面板那边**：放通上报端口的入站。

### 部署状态看得见，出问题能查

自动换 IP 和 DDNS 都有「检测」按钮，点了会给出状态判断加**具体的排查方向**，
而不是只说一句「失败」：

```
已生成脚本，但面板从未收到这台实例的上报

排查方向:
  1. 确认脚本已在实例上执行：systemctl status aws-helper-guard
  2. 确认实例能连到面板的上报端口 8766（安全组、防火墙）
  3. 在实例上手动跑一次看输出：/usr/local/bin/aws-helper-guard
```

状态判定：

| 状态 | 含义 |
|---|---|
| 未部署 | 没生成过脚本，或生成了但从未收到上报 |
| 正常 | 心跳在宽限期内 |
| 可能失联 | 超过 3 倍心跳周期没消息 —— 实例关机、脚本被卸载、链路断了 |

宽限期给到 3 倍心跳周期，是因为实例重启和网络抖动都会漏掉一两次心跳，
一次没收到就报警会天天误报。

如果你的判断标准比这更精确（比如检测特定服务的响应内容），
可以关掉自动换 IP，改用外部监控调用面板的换 IP 接口。

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

**进页面读本地快照，不调 AWS。** 实例页和 Lightsail 页把上次拉到的结果存在
浏览器 `localStorage` 里，打开页面直接渲染它 —— **刷新页面、重新登录、重开标签页、
服务重启都不产生任何 AWS 调用**。要看最新状态才点「刷新列表」。

后端那层 10 秒缓存挡不住这些场景：隔 10 秒以上按 F5 就是一次真实的
`DescribeInstances`，而缓存是进程内的，服务一重启就空。频繁调用既慢又容易撞
限流和风控，所以这里的原则是**只有用户明确要求时才打 AWS**。

浏览器实测的调用次数：

| 动作 | AWS 调用 |
|---|---|
| 首次进页面（无快照） | 0，提示点「刷新列表」 |
| 点「刷新列表」 | 1 |
| F5 刷新页面 | 0，数据仍在 |
| 退出后重新登录 | 0 |
| 新开标签页 | 0 |
| 切到没加载过的区域 | 0，提示手动加载 |
| 切回加载过的区域 | 0，显示该区域自己的快照 |
| 开关机等电源操作后 | 强制回源（状态刚变，这时拿快照是错的） |

快照按 (账号, 区域) 分别存，来回切不互相覆盖；共用一个键的话切过去再切回来
数据就没了。最多留 12 份，超了丢最旧的 —— `localStorage` 只有 5MB 左右。

**会如实标出快照年龄**，不假装是刚拉的：

```
本地快照，数据取于 8 分钟前（进页面不调用 AWS） · 刷新列表
```

登录方式那一列也一起进快照，否则走快照时整列都显示「未记录」。

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

**登录凭据会记下来，在实例面板直接看**

开机时怎么登录，面板就记下什么：

| 开机方式 | 记录内容 | 面板显示 |
|---|---|---|
| 填了 root 密码 | 用户名 + 密码（Fernet 加密） | `密码 root [查看]` |
| 没填密码（默认） | 用户名 + 密钥对名 | `密钥 ubuntu prod-key` |

**这是必须的：root 密码只存在于 user-data 里**，开完机关掉页面就再也找不回来。
密钥登录那行的密钥名是可点的下载链接。

点「查看」才返回密码明文，并且会留一条审计日志。列表接口只回
`has_password: true/false`，连密文都不送出去。

三个时机会更新这份记录：

- **重置密码后** → 登录方式改成密码，记下新密码
- **重装后** → 登录用户跟着新系统变（根卷重铺后原 root 密码也没了，改回密钥）
- **终止后** → 删掉记录。AWS 会复用实例 ID，留着会让下一台同 ID 的机器显示错的凭据

**私钥以纯文本文件下发**

开机时新建的密钥对，私钥用 Fernet 加密存 Postgres，页面上给下载链接。
下载走 `text/plain` + `Content-Disposition: attachment`，**不是 JSON** ——
JSON 会把换行转成字面量 `\n`，浏览器里看到和复制出来的都是一行带 `\n`
的字符串，`ssh -i` 直接报 invalid format。文件末尾也补上换行，
OpenSSH 少了这个同样拒绝加载。

存下来 `chmod 600` 就能直接用。

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

**T 系列强制 standard 模式，不会产生超额积分账单**

T 系列（t2/t3/t3a/t4g）是突发性能机型：平时攒 CPU 积分，需要时突发。积分耗尽后
有两种行为，取决于 `CreditSpecification`：

| 模式 | 积分用完后 | 计费 |
|---|---|---|
| `standard` | 降到基准性能（t3.micro 是 2 核各 10%） | 不会多收钱 |
| `unlimited` | 继续全速跑，透支「超额积分」 | **按超额积分额外计费** |

**AWS 的默认值是坑：** T3/T3a/T4g 默认 `unlimited`，只有 T2 默认 `standard`。
而且官方文档明确写了 —— 用 API/CLI 开机时走账号级默认值，只有控制台的选择才会
覆盖它。面板走 API，所以不显式传就是 `unlimited`。

跑满 CPU 的负载（编译、转码、被刷）在 `unlimited` 下会持续产生计划外费用，
而账单要到月底才显眼。所以面板**开机时对 T 系列显式传 `standard`**：

```
CreditSpecification={CpuCredits=standard}
```

只对 T 系列传 —— 非突发机型（c5、m6i 等）传这个参数 AWS 会直接拒绝请求。

**已有实例也能看和改。** 实例列表多了「CPU 积分」列：

```
规格        CPU 积分
t3.micro    unlimited  [改回]         ← 标红，点一下改成 standard
t3.small    standard                  ← 绿色
t3.large    未知  [改为 standard]     ← 查不到当前值，但照样能改
c5.large    —                         ← 非突发机型，没有积分概念
```

勾选多台后点「改为 standard」可批量修改，会自动过滤掉非 T 机型 ——
混在一起提交 AWS 会让整批失败。勾的全是非 T 机型时报错会**列出实际机型**
（「勾选的 c5.large 不是 T 系列」），而不是笼统一句「请勾选 T 系列」。

**是不是 T 系列由前端按机型名判断，不依赖后端字段。** 这里踩过一次：
最初只看后端返回的 `burstable`，结果老用户浏览器里的快照存于加这个字段之前，
`t3.micro` 被当成非 T，点批量改直接报「请勾选至少一台 T 系列实例」。
所以快照带了结构版本号，加字段就 +1，版本不符时丢弃并提示重新加载 ——
宁可让用户多点一次刷新，也不要用缺字段的数据渲染出错误的行。

查积分模式是单独一次 `DescribeInstanceCreditSpecifications`（`DescribeInstances`
的返回里没有这个字段），只对 T 实例发起。缺
`ec2:DescribeInstanceCreditSpecifications` 权限时显示「未知」，
但**按钮照样给** —— 不知道当前值不代表不能设成 standard。实例列表也照常显示，
不因为一个附加字段拉不到就整页失败。

**关于测试**

测试用 [moto](https://github.com/getmoto/moto) 模拟 EC2，不碰真实账号也不产生费用。
但要说清楚：moto 是模拟器，和真实 AWS 存在行为差异 —— 开发过程中就遇到过
moto 允许多个 EIP 同时绑到一个实例、`Ipv6AddressCount` 不生效等情况。
所以涉及 AWS 语义的判断（EIP 自动解绑、stop/start 换 IP 的例外条件）都以官方文档为准，
而不是以 moto 的表现为准。**首次在生产账号使用前，建议先在测试账号上验证一遍。**

---

## BBR 加速与脚本模板编辑

### BBR

一键开机页的「开机时顺带部署服务」可勾选「开启 BBR 加速」。它在首次启动时：

```conf
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
```

BBR 对跨境、高延迟、高丢包的 TCP 链路提升明显；`fq` 是配套队列规则，BBR 依赖
发包时机（pacing），只设拥塞控制算法不设 `fq`，效果会打折。

这里**只改 sysctl，不换内核、不重启**。面板支持的 Ubuntu 22/24、Debian 12、
Amazon Linux 2023 都是 5.10+，BBR 早已编译进内核。网上常见的 BBR 脚本会换内核，
那会重启、可能开不了机，不适合悄悄放进 cloud-init。

脚本先检查 `tcp_available_congestion_control` 是否有 bbr；没有就输出「当前内核不支持
BBR，已跳过」且正常退出，不会影响开机。设置后还会回读当前算法，只有真的变成
`bbr` 才报告成功。它是幂等的，重复执行不会堆积配置。

也可以在「开机脚本」页点「BBR 加速」现成脚本，填进编辑区后按需要修改、预览、保存。

### 脚本模板可编辑

原来的「载入」实际只是填回编辑区，改名后会新建一条，用户看不出自己是在编辑还是
复制。现在列表有明确的三种操作：

| 操作 | 结果 |
|---|---|
| 编辑 | 按模板 ID 更新，可改名称、内容、预装包；改名仍是同一条记录 |
| 复制一份 | 内容填回编辑区，名称自动加「副本」，保存时新建，不碰原模板 |
| 删除 | 删除模板 |

编辑改名撞上已有名称时会给出「已有同名模板」的可读错误，不会把 PostgreSQL 的
`UniqueViolation` 原始报文露给页面。

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

## DDNS 动态解析

面板部署在 IP 会变的机器上时（家宽、部分 VPS），IP 一变域名就失效。
这一栏定期探测本机公网 IP，和 DNS 上的记录比对，**变了才更新**。

和 EC2 的自动换 IP 是相反方向的两件事：

| | 自动换 IP | DDNS |
|---|---|---|
| 触发 | 实例 IP 被墙，探测失败 | 本机公网 IP 变了 |
| 动作 | 给实例换一个新 IP | 让域名指向新 IP |
| 对象 | AWS 上的实例 | 面板所在的这台机器 |

### 三种用法

**一、创建 EC2 时顺带部署**

一键开机页勾「部署 DDNS 更新器（Cloudflare）」并填好根域名、完整主机名、Token，
开机脚本会自动把 `ddns-update` 装进新实例，作为 systemd timer 运行。
**只在创建 1 台时可用**：同批实例共用一份 cloud-init，也就共用一个主机名，
多台同时跑会互相把 DNS 记录改成自己的 IP，面板会在创建前直接拒绝。

另外两种在左侧「通用 → DDNS 解析」，填 DNS 供应商、区域根域名、完整主机名、
API Token，勾选要更新 A（IPv4）还是 AAAA（IPv6）：

**二、生成一键脚本（给别的机器用）**

点「生成一键脚本」，页面直接给出一段自包含的 bash，复制或下载到目标机器上
以 root 执行即可：

```bash
bash ddns-deploy.sh
```

脚本会装好更新器（`/usr/local/bin/ddns-update`）、写好配置
（`/etc/ddns-update.env`，权限 600）、**先跑一次校验 Token 和区域**，
再挂上 systemd timer 或 cron。校验不过直接报错退出，不会留下一个跑不通的定时任务。

**目标机器不需要 Python，不需要连这个面板，也不需要数据库** —— 只要有
`curl`（没有的话脚本会自动装）。用 bash 而不是 Python 就是为了这个：
要能丢到任何一台机器上跑，包括精简系统。

定时方式可选：

| 方式 | 说明 |
|---|---|
| systemd timer（推荐） | `Type=oneshot` + timer，崩了下次自己重来；`ProtectSystem=strict` 只允许写状态目录 |
| cron | 更轻量，日志写 `/var/log/ddns-update.log`。重复部署会先删掉旧行再加，不会堆积 |

装完的常用命令：

```bash
systemctl list-timers ddns-update.timer   # 看下次执行时间
systemctl start ddns-update               # 立刻同步一次
journalctl -u ddns-update -n 50           # 看日志
/usr/local/bin/ddns-update                # 手动跑，直接看输出
```

**脚本里含明文 API Token**，等同于该区域 DNS 的修改权限。传输别走公开渠道，
部署完建议删掉脚本文件并 `history -c`。

**三、交给面板托管（更新面板这台机器）**

点「交给面板托管」，规则存进数据库，面板后台每 60 秒扫一遍，同步的是
**面板所在这台机器**的公网 IP。保存时会实际调一次 API 校验。

两者互不干扰：一键脚本部署的规则由目标机器自己跑，不会出现在面板的规则列表里。

页面顶部会显示当前探测到的本机 IPv4 / IPv6，方便确认机器到底有没有 v6 连通性。

### 取的是出站 IP，不是网卡地址

由外部服务回显它看到的源地址，等价于：

```bash
curl -4 https://ip.sb    # A 记录用这个
curl -6 https://ip.sb    # AAAA 记录用这个
```

**不读网卡。** NAT 后面、多网卡、走代理时，网卡上绑的地址和实际出站地址不同 ——
把网卡地址写进 DNS 会解析到一个外部根本连不上的内网地址。

探测点按 `ip.sb` → `cdn-cgi/trace` → `ipify` → `icanhazip` 顺序试，
单个挂了或限流就换下一个。取回的地址会用 `ipaddress` 校验版本对得上，
探测点偶尔会回错误页或另一个协议族的地址。

v4 / v6 必须用不同探测点：`api.ipify.org` 只有 A 记录，强制走 v6 会连不上，
那会被误判成"这台机器没有 v6"，AAAA 永远不更新。v6 用 `api6.ipify.org`。

地址族是在 socket 层钉住的（`getaddrinfo` 只返回指定协议族），
等价于 `curl -4` / `curl -6` —— 不钉住的话同一个域名可能解析到另一族。

### Account ID：一般不用填

**DNS 记录的增删改只需要 zone id，不需要 Account ID。** 面板留了这个可选字段，
只用于查 zone 时消歧义：

```
GET /zones?name=example.com&account.id=<32位十六进制>
```

注意过滤参数名是 `account.id`（点号），写成 `account_id` 不会生效、会静默返回
未过滤的结果。

真正需要它的场景只有一个：**一个 Token 能看到多个账号，而这些账号下存在同名域名。**
这时查询返回多条，无法确定该改哪一个。面板遇到这种情况会明确报出各自的
account id 并提示你填，而不是笼统地说"匹配到 2 个结果"。

Account ID 在 Cloudflare 控制台域名概览页右下角。

### Cloudflare Token 怎么建

用 **API Token**，不要 Global API Key —— 后者是账号级全权限，放在一台
动态 IP 的机器上风险太大。

控制台「我的个人资料 → API 令牌 → 创建令牌」，选「编辑区域 DNS」模板：

```
权限:     Zone → DNS → Edit
区域资源: 包含 → 特定区域 → 你的域名
```

Token 用 Fernet 加密后存 Postgres，页面和接口都不回传（连密文也不回）。
**保存时会实际调一次 Cloudflare API 校验**，Token 配错当场就能看到，
不用等定时任务默默失败几小时后再去翻日志。

### 几个刻意的设计

**IP 没变化不发任何更新请求。** 照发一次也能跑（PATCH 是幂等的），
但 Cloudflare 的限流额度是账号级共享的（1200 次 / 5 分钟），白烧没有意义。

**更新用 `PATCH` 而不是 `PUT`。** 这是 DDNS 实现最常见的坑：`PUT` 是整条替换，
漏传 `proxied` 或 `ttl` 会被重置成默认值 —— 用户在控制台开的橙云会被静默关掉，
自定义 TTL 也会丢。`PATCH` 只改传了的字段，所以这里只发 `{"content": 新IP}`。

**v4 和 v6 分开探测，用不同的探测点。** `api.ipify.org` 只有 A 记录，
强制走 v6 会直接连不上 —— 那不是"机器没有 v6"，而是探测点本身不支持。
v6 用 `api6.ipify.org` / `ipv6.icanhazip.com`。取回的地址还会用 `ipaddress`
校验版本对得上，探测点偶尔会回一个错误页或 v4 映射地址。

**没有 IPv6 连通性不算失败。** 很多机器就是只有 v4，把它算进失败计数会触发降频，
连 A 记录的更新也跟着变慢。

**连续失败会降频。** Token 配错时每轮都去撞，会同时触发限流和 Cloudflare 的
防爆破（连续认证失败会被临时封 IP）。连续失败 3 次后间隔放大 6 倍，上限 1 小时。

**一轮里多条规则共用一次 IP 探测。** 探测要走外部 HTTP，N 条规则各探一次
纯属浪费，而且不同规则拿到的 IP 还可能不一致。

**开了 Cloudflare 代理时 TTL 强制为自动。** 代理记录的 TTL 不可改，传数字会被拒，
所以页面上勾了代理就把 TTL 选择器禁掉。

### 换其他 DNS 供应商

供应商走 `DnsProvider` 协议（`zone_id` / `find_record` / `create_record` /
`update_record` 四个方法），加一家只要写一个类并注册进 `PROVIDERS`，
不用动监控循环和页面。目前实现了 Cloudflare。

取本机 IP 的逻辑与供应商无关，是独立的，新供应商直接复用。

## 数据存储

业务数据全部在 **Postgres**，`AWS_HELPER_DATA` 目录只放一个文件：`secret.key`。

| 位置 | 内容 |
|---|---|
| Postgres | AWS 账号（密文）、密钥对（密文）、代理（密文）、DDNS Token（密文）、实例登录密码（密文）、脚本模板、换 IP 规则、会话、日志 |
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

836 个测试。AWS 侧全部用 moto 模拟，不碰真实账号；数据库侧用真实 Postgres，
不 mock SQL。覆盖开机全链路、UserData 注入与顺序、安全组端口、换 IP 两种策略、
弹性 IP 泄漏与孤儿回收、凭据与代理加密、账号编辑、密码哈希与登录锁定、
CLI 重置、SQLite 迁移与序列校正、并发写入、缓存与失效、DDNS 解析同步、
DDNS 一键脚本（两层 bash 语法检查 + 对着假 Cloudflare 真实执行）、
SSM 重置密码（前提检查与脚本内容）、重装系统（架构校验与失败态、
重装后设密码/写公钥、SSH 公钥格式校验、authorized_keys 权限与追加语义）、
部署脚本静态检查。

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
  ddnsmon.py          DDNS 监控循环
  core/ddns.py        DNS 供应商接口 + Cloudflare 实现 + 取本机公网 IP
  core/ddns_script.py 生成自包含的 DDNS 一键部署脚本（bash + curl）
  core/guard_script.py 生成实例侧被墙探测脚本（bash + curl + systemd）
  core/launch_deploy.py 开机时把上面两个脚本内联进 cloud-init
  core/respw.py       通过 SSM 重置实例登录密码
  core/reinstall.py   重装系统（ReplaceRootVolume）+ 前置校验
  autoip.py           自动换 IP 监控循环 + 处理实例上报
  tasks.py            后台任务与进度跟踪
  core/aws.py         boto3 客户端工厂、SOCKS 代理、区域与镜像目录、账号探测
  core/userdata.py    开机脚本渲染与校验
  core/bbr.py         开启 BBR 拥塞控制（只改 sysctl，不换内核）
  core/launch.py      EC2 一键开机、实例列表、电源操作、终止清理
  core/ipchange.py    换 IP 两种策略、弹性 IP 清理
  core/lightsail.py   Lightsail 套餐、蓝图、实例、静态 IP
  core/bedrock.py     Bedrock 模型清单、可用性探测、Converse 调用
  web/app.py          FastAPI 路由
  web/report_app.py   实例上报专用端口（只有 /report 和 /health）
  web/templates/      左侧目录布局 + 十一个页面
  demo/               演示环境（moto 后端 + 预置数据）
deploy/install.sh     一键部署（systemd / docker 两种方式）
Dockerfile            容器镜像（非 root + healthcheck）
docker-compose.yml    compose 服务定义
requirements.txt      固定版本的运行时依赖
tests/                836 项测试
```

更详细的功能说明见 [aws_helper/README.md](aws_helper/README.md)。

---

## 免责声明

本项目仅用于管理你自己拥有或已获授权的 AWS 资源。
使用者需自行遵守 AWS 服务条款和所在地法律法规，因使用不当造成的任何后果由使用者自行承担。
