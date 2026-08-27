# AWS 小助手

AWS EC2 管理面板。一键开机、换 IP、开机脚本注入，附带按账号独立的 SOCKS 代理和自动换 IP 监控。

现有的多云面板里 AWS 基本都是"顺带支持"：能列实例但注入不了开机脚本，能开机但换不了 IP，
更没有 IP 被墙后自动更换。这个工具只做 AWS，把这几件事做完整。

---

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
- 规格来自 `DescribeInstanceTypes`，**按架构过滤且按区域实时查询**。
  实测 ap-east-1 有 241 种 x86_64 规格，us-east-1 有 949 种 —— 写死清单必然出错
- 免费额度机型会标注，默认自动选中

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
以专用系统用户 `awshelper` 运行，非 root。

| 项目 | 路径 |
|---|---|
| 程序 | `/opt/aws-helper/aws_helper` |
| 虚拟环境 | `/opt/aws-helper/venv` |
| 数据 | `/var/lib/aws-helper`（权限 700） |
| 配置 | `/etc/aws-helper/aws-helper.env`（权限 640） |
| 服务单元 | `/etc/systemd/system/aws-helper.service` |

单元里开了 `ProtectSystem=strict`、`NoNewPrivileges`、`PrivateTmp`，只有数据目录可写。
开机自启，异常退出 5 秒后自动重启。

缺 `python3-venv` 时脚本会自动安装。要求 **Python 3.10+**。

### 方式二：Docker Compose

构建镜像后用 compose 运行，数据存命名卷 `aws-helper-data`。

容器内以 uid 999 的 `awshelper` 用户运行，带 `no-new-privileges`，内置 healthcheck。
端口默认只映射到 `127.0.0.1`，日志轮转限制 10MB × 3 份。

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
| `AWS_HELPER_PASSWORD` | 随机生成 | **仅**用作首次启动的初始密码，库里已有密码后不再生效 |
| `AWS_HELPER_DATA` | `~/.aws-helper` | 数据目录 |
| `AWS_HELPER_HOST` | `127.0.0.1` | 监听地址 |
| `AWS_HELPER_PORT` | `8765` | 监听端口 |
| `AWS_HELPER_SESSION_TTL` | `86400` | 会话有效期（秒） |
| `AWS_HELPER_SESSION_KEY` | 随机生成 | 会话签名密钥，不设则重启后需重新登录 |
| `AWS_HELPER_SECRET` | 自动生成 | Fernet 加密密钥，用于加密 AWS 凭据 |
| `AWS_HELPER_DOCS_URL` | 本仓库地址 | 登录页「忘记密码」链接目标 |

`AWS_HELPER_PASSWORD` 只在库里还没有密码时用作初始值 —— 否则你在面板改了密码，
重启又被环境变量覆盖回去。

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

```bash
pip install "moto[ec2,server]==5.0.28" pytest httpx PyYAML
python3 -m pytest tests/ -q
```

372 个测试，全部用 moto 模拟 EC2，不碰真实 AWS 账号。覆盖开机全链路、UserData 注入与顺序、
安全组端口、换 IP 两种策略、弹性 IP 泄漏与孤儿回收、凭据与代理加密、账号编辑、
密码哈希与登录锁定、CLI 重置、部署脚本静态检查。

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
  auth.py            密码哈希、强度校验、登录锁定
  cli.py             密码重置 / 状态查看 / 下线会话
  core/aws.py        boto3 客户端工厂、SOCKS 代理支持、区域与镜像元数据
  core/userdata.py   开机脚本渲染与校验
  core/launch.py     一键开机、实例列表、电源操作
  core/ipchange.py   换 IP 两种策略、弹性 IP 清理
  store.py           SQLite 持久层（加密凭据、会话、规则、日志）
  autoip.py          自动换 IP 监控循环
  web/               FastAPI 路由与六个页面
  demo/              演示环境
deploy/install.sh    一键部署脚本
Dockerfile           容器镜像
docker-compose.yml   compose 服务定义
```

更详细的功能说明见 [aws_helper/README.md](aws_helper/README.md)。

---

## 免责声明

本项目仅用于管理你自己拥有或已获授权的 AWS 资源。
使用者需自行遵守 AWS 服务条款和所在地法律法规，因使用不当造成的任何后果由使用者自行承担。
