# AWS 小助手

一键开机、换 IP、开机脚本。Web 面板 + 后台自动换 IP 监控。

## 为什么写这个

现有的多云面板里，AWS 都是"顺带支持"：能创建实例但没有 UserData 注入，
能看列表但没有换 IP，更没有 IP 被墙后自动更换。这个工具只做 AWS，把三件事做完整。

## 一键部署

两种方式，二选一。都由同一个脚本完成，装完得到统一的 `aws-helper` 管理命令。

```bash
# 交互选择部署方式
sudo bash deploy/install.sh

# 或直接指定
sudo bash deploy/install.sh --mode systemd     # systemd + Python 虚拟环境
sudo bash deploy/install.sh --mode docker      # Docker Compose
```

常用参数：

| 参数 | 说明 |
|---|---|
| `--mode systemd\|docker` | 部署方式，省略则交互询问 |
| `--host ADDR` | 监听地址，默认 `127.0.0.1`。填 `0.0.0.0` 会二次确认 |
| `--port PORT` | 监听端口，默认 `8765` |
| `--password PASS` | 指定初始密码，省略则自动生成强密码 |
| `--yes` | 非交互，全部用默认值 |

装完控制台会打印访问地址和初始密码。脚本**幂等**：重复执行只更新程序和依赖，
已有的密码、AWS 凭据、换 IP 规则都保留 —— 这种情况下摘要会明确写「沿用原有密码」，
不会打印一个其实用不了的新密码。

### systemd 模式

在 `/opt/aws-helper/venv` 建独立 Python 虚拟环境，依赖只装在里面，不碰系统 Python。

| 项目 | 路径 |
|---|---|
| 程序 | `/opt/aws-helper/aws_helper` |
| 虚拟环境 | `/opt/aws-helper/venv` |
| 数据 | `/var/lib/aws-helper`（权限 700） |
| 配置 | `/etc/aws-helper/aws-helper.env`（权限 640） |
| 服务单元 | `/etc/systemd/system/aws-helper.service` |

以专用系统用户 `awshelper` 运行，非 root。单元里开了 `ProtectSystem=strict`、
`NoNewPrivileges`、`PrivateTmp`，只有数据目录可写。开机自启，异常退出 5 秒后重启。

缺 `python3-venv` 时脚本会自动装。要求 Python 3.10+。

### Docker Compose 模式

构建镜像后用 compose 运行，数据存命名卷 `aws-helper-data`。

容器内以 uid 999 的 `awshelper` 用户运行，带 `no-new-privileges`，
`/data` 权限 700，内置 healthcheck 打 `/healthz`。
端口默认只映射到 `127.0.0.1`，日志轮转限制 10MB × 3。

脚本会先验证 compose **真的能连上 docker 守护进程**，而不只是检查命令存在 ——
`docker-compose` 1.29 在新版 requests 环境下会抛
`Not supported URL scheme http+docker` 而完全不可用。遇到这种情况脚本会自动下载
官方 compose v2 插件。

## 管理命令

两种部署方式共用同一套命令，脚本会自动路由到 systemctl 或 docker compose：

```bash
aws-helper status            # 查看运行状态
aws-helper logs -f           # 跟踪日志
aws-helper start|stop|restart
aws-helper reset-password    # 忘记密码时重置
aws-helper info              # 查看密码/会话/登录记录
aws-helper logout-all        # 下线所有登录会话
aws-helper uninstall         # 卸载，会分别询问是否删除数据
```

卸载会移除服务/容器、安装目录和管理命令本身，数据是否删除单独确认 ——
不会顺手把你的 AWS 凭据一起清掉。

## 手动运行（开发用）

需要一个可用的 Postgres。最省事的方式：

```bash
docker run -d --name awshelper-pg -e POSTGRES_PASSWORD=dev \
    -e POSTGRES_DB=awshelper -p 5432:5432 postgres:16-alpine

pip install -r requirements.txt
export AWS_HELPER_DATABASE_URL='postgresql://postgres:dev@127.0.0.1:5432/awshelper'
python3 -m aws_helper
```

建表是自动的，不需要手工执行 DDL。首次启动会生成随机初始密码并打印到控制台，
打开 http://127.0.0.1:8765 登录，之后在「用户面板」里改成自己的密码。

用 `deploy/install.sh` 部署时不需要这些 —— 脚本会自动装好数据库并写好连接串。

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `AWS_HELPER_PASSWORD` | 随机生成 | **仅**用作首次启动的初始密码，库里已有密码后不再生效 |
| `AWS_HELPER_DATABASE_URL` | `postgresql://awshelper@127.0.0.1:5432/awshelper` | Postgres 连接串 |
| `AWS_HELPER_DB_SCHEMA` | `public` | 数据库 schema |
| `AWS_HELPER_DB_POOL` | `8` | 连接池上限 |
| `AWS_HELPER_DATA` | `~/.aws-helper` | 加密密钥目录（业务数据在数据库） |
| `AWS_HELPER_HOST` | `127.0.0.1` | 监听地址 |
| `AWS_HELPER_PORT` | `8765` | 监听端口 |
| `AWS_HELPER_SESSION_TTL` | `86400` | 会话有效期（秒） |
| `AWS_HELPER_SESSION_KEY` | 随机生成 | 会话签名密钥，不设则重启后需重新登录 |
| `AWS_HELPER_ENDPOINT_URL` | 无 | 覆盖 AWS endpoint，用于本地测试 |

`AWS_HELPER_PASSWORD` 只在库里还没有密码时用作初始值 —— 否则你在面板改了密码，
重启又被环境变量覆盖回去。

**面板持有你的 AWS 凭据。** 默认只听 127.0.0.1。要对外暴露必须放到 HTTPS 反代之后，
并设置一个强密码。

## 用户面板

登录后进「用户面板」，三件事：

**改密码** — 需要输入当前密码，新密码要求至少 10 位且包含大写、小写、数字、符号中的
至少三类。改成功后其他设备的登录立即失效，当前浏览器保持登录。有个「生成一个强密码」
按钮可以直接填。

**会话管理** — 列出所有活跃登录（IP、客户端、登录时间、最近活动），标出当前会话。
可以单独踢掉某个会话，或一键「下线其他所有会话」。当前会话不能踢自己 —— 要退出用退出按钮。

**登录记录** — 成功和失败都记，带 IP 和 User-Agent。看到大量失败说明有人在试密码。

密码经 PBKDF2-SHA256 加盐哈希（26 万次迭代）存储，不可逆。会话令牌只存 SHA-256 摘要，
数据库被读走也无法冒用登录态。每次请求都会校验令牌在库中是否仍存在，所以改密码和
踢下线能立刻生效 —— 只验 Cookie 签名做不到这点。

同一 IP 连续 5 次密码错误锁定 15 分钟，锁定期内即使密码正确也拒绝。锁定按 IP 隔离，
不影响其他来源。反代后面会读 `X-Forwarded-For` 第一跳。

## 忘记密码

不做邮件找回（多一层 SMTP 依赖，且邮箱本身可能失守）。在服务器上执行：

```bash
python3 -m aws_helper.cli reset-password              # 生成随机强密码
python3 -m aws_helper.cli reset-password --password '你的新密码'
python3 -m aws_helper.cli status                      # 查看密码/会话/登录记录
python3 -m aws_helper.cli logout-all                  # 下线全部会话
```

重置会作废所有会话，也会清掉登录锁定状态 —— 被锁在门外时用它能立刻恢复。
弱密码需要显式加 `--force`。

CLI 只读写本地数据目录，不经过网络和登录校验，面板打不开时同样可用。
用 `--data-dir` 或 `AWS_HELPER_DATA` 指定数据目录。

## 三个核心功能

### 一键开机

填个名称点创建，后台自动完成：解析最新 AMI → 创建密钥对并加密保存私钥 →
创建安全组（**默认全部端口放通**）→ RunInstances → 轮询等公网 IP。

- 支持批量（数量填 N 就开 N 台，共用密钥对和安全组）
- 支持直接指定 AMI ID，用私有/自定义镜像
- 勾选 IPv6 时自建 VPC + 子网 + IGW + v4/v6 双默认路由，并确保拿到 IPv6 地址
- 私钥只在创建时由 AWS 返回一次，工具立刻加密落库，页面可下载

### 开机脚本

写进表单的脚本由 cloud-init 在首次启动时以 root 执行。不要写 `#!/bin/bash`
开头，渲染时会自动加上——写了会被明确拒绝，而不是静默出错。

渲染顺序固定：shebang → 设置 hostname → 安装软件包 → 开启 root 登录（可选）→ **你的脚本**。
你的脚本永远在最后，前面的固定动作失败不会阻断它。

可以先点「预览最终脚本」看完整内容再创建。常用脚本可存成模板复用。

开启 root 密码登录用的是 `sshd_config.d/` drop-in 文件，不删除原有配置。
主配置里硬编码了 `PasswordAuthentication no` 且不含 `Include` 时会就地修正。

### 换 IP

两种策略：

| 策略 | 机制 | 停机 | 适用 |
|---|---|---|---|
| `eip` | 分配新弹性 IP → 绑定 → 释放旧的 | 不停机，立即生效 | 默认，推荐 |
| `dynamic` | stop → start，AWS 重新分配动态 IP | 约 1 分钟 | 不想留 EIP 时 |

绑了 EIP 的实例用 `dynamic` 不会换 IP，工具会明确报错而不是假装成功。

支持 IP 段白名单/黑名单：换出来的地址不在允许范围内会自动释放重试，
用完尝试次数才报错。整个过程不留空闲 EIP。

`eip` 策略先确认新地址生效再释放旧的——反过来会在绑定失败时同时丢掉两个 IP。

### 自动换 IP

后台每 30 秒扫一遍规则，按各自间隔探测实例 TCP 端口，
连续失败达到阈值就自动换 IP。也就是 IP 被墙后自动更换。

每条规则可配：探测端口、检查间隔、失败阈值、换 IP 策略、允许/排除的 IP 段、最大尝试次数。
探测恢复后失败计数清零，不会累积误触发。

也可以脱离 Web 单独跑：

```bash
python3 -m aws_helper.autoip
```

## DDNS 动态解析

本机公网 IP 变了自动更新 DNS 解析。域名托管在 Cloudflare，支持 A / AAAA。

和自动换 IP 方向相反：自动换 IP 是实例被墙了换新 IP，DDNS 是本机 IP 变了让域名跟上。

用 Cloudflare **API Token**（不是 Global API Key），权限 `Zone → DNS → Edit`，
区域范围只勾目标域名。Token 用 Fernet 加密存库，接口不回传明文也不回传密文。
保存时会实际调一次 API 校验，配错当场报错。

几个要点：

- **IP 没变不发写请求。** PATCH 本身幂等，但 Cloudflare 限流额度是账号级共享的
  （1200 次 / 5 分钟）
- **更新用 PATCH 不用 PUT。** PUT 是整条替换，漏传 `proxied` / `ttl` 会重置成默认值，
  用户开的橙云会被静默关掉。所以只发 `{"content": 新IP}`
- **v4 / v6 分开探测。** `api.ipify.org` 只有 A 记录，强制走 v6 会连不上；
  v6 用 `api6.ipify.org` / `ipv6.icanhazip.com`。取回后用 `ipaddress` 校验版本
- **没有 v6 连通性不算失败**，否则会拖累 A 记录的更新频率
- **连续失败 3 次后降频 6 倍**（上限 1 小时）。Token 配错时每轮硬撞会触发
  Cloudflare 的防爆破，连续认证失败会被临时封
- **一轮内多条规则共用一次 IP 探测**
- **开了代理时 TTL 强制为自动**，代理记录的 TTL 不可改，传数字会被拒

加新 DNS 供应商实现 `DnsProvider` 协议的四个方法（`zone_id` / `find_record` /
`create_record` / `update_record`）并注册进 `PROVIDERS` 即可，取本机 IP 的逻辑
与供应商无关可直接复用。

### 一键脚本

面板还能把配置渲染成一段自包含的 bash，复制到任意机器上以 root 执行即部署完成 ——
目标机器不需要 Python、不用连面板、不用数据库，只要有 curl（没有会自动装）。

用 bash 而不是 Python 就是为了这个：要能丢到任何一台机器上跑，包括精简系统。
定时可选 systemd timer 或 cron。脚本会先跑一次校验 Token 和区域，
校验不过直接报错退出，不会留下一个跑不通的定时任务。

脚本里含明文 Token，部署完建议删掉文件并清理 shell 历史。

面板自己托管的规则也能脱离 Web 单独跑：

```bash
python3 -m aws_helper.ddnsmon
```

## 减少 AWS 调用

频繁调 AWS 容易撞限流和风控。按数据变化频率分别缓存：

| 数据 | 键 | TTL |
|---|---|---|
| `DescribeInstanceTypes` | 区域 + 架构 | 6 小时 |
| Lightsail 套餐 / 蓝图 | 账号 + 区域 | 6 小时 |
| Bedrock 模型清单 | 账号 + 区域 | 15 分钟 |
| `DescribeInstances` | 账号 + 区域 | 10 秒 |

缓存在进程内（`aws_helper/cache.py`），不落库 —— 单进程下落库只是多一份写流量和
一致性负担，冷启动多几次调用不构成风控风险。

**只缓存成功结果。** 降级清单（拿不到规格时的内置列表）一旦入缓存，一次权限失败
就会粘住整个 TTL，用户修好 IAM 也得干等。

**改了状态立刻失效**：开机、关机、重启、终止、换 IP、创建轻量实例之后主动清缓存，
不等 TTL。后台任务里的失效点放在任务内部而不是提交处 —— 提交时实例还没真终止。
换密钥或换代理清掉该账号全部缓存。

**不缓存**：账号探测、代理测试、Bedrock 探测、弹性 IP 列表，以及换 IP / 开机 / 清理
流程内部的读取（那些是正确性相关的读，不是展示用的）。

前端另有一层：开机页按 (账号, 区域, 系统, 架构) 记住结果，来回切下拉不再发请求；
实例列表用指纹比对，内容没变就不回传列表，页面保留现有 DOM 和已勾选的实例。

## 多账号与独立代理

每个账号可单独配一个出站代理，该账号的所有 AWS API 请求都走它。多账号各走各的代理，互不影响。

| 协议 | 示例 |
|---|---|
| SOCKS5（域名代理端解析，推荐） | `socks5h://127.0.0.1:1080` |
| SOCKS5 + 认证 | `socks5h://user:pass@1.2.3.4:1080` |
| SOCKS4 | `socks4://1.2.3.4:9050` |
| HTTP / HTTPS | `http://proxy.local:8080` |

不写协议时按 `socks5h` 处理，必须带端口。填 `socks5` 会自动升级成 `socks5h` ——
后者让域名在代理端解析，避免本地 DNS 泄漏。留空即直连。

botocore 原生不支持 socks（它把代理 URL 交给 urllib3 的 `proxy_from_url`，
后者只认 http/https），工具内部替换了 HTTP session 层来支持。

代理地址和其中的密码与 Secret Key 同等加密存储，页面和日志只显示掩码
（`socks5h://user:***@host:port`）。

「测试代理连通性」按钮会先单独完成一次 SOCKS 握手，再通过代理实调 DescribeRegions，
所以报错能区分是代理不通、代理认证失败，还是 AWS 凭据有问题 —— botocore 默认会把这
三种都包装成同一个 endpoint 错误。

## 账号编辑

账号列表每行有「编辑」按钮，点了会把该账号载入上方表单，可改备注名、Access Key、
Secret Key、区域、代理和备注。

Secret Key 留空表示沿用原密钥，不必重新粘贴。代理留空表示清除代理改为直连。
保存前同样会实际调 AWS 校验一次（配了代理就走代理）。

## 弹性 IP 计费提醒

未绑定的 EIP 按小时计费。绑在**已终止实例**上的 EIP 同样计费，
但 `describe_addresses` 仍会返回 InstanceId，看起来像"已绑定"，很容易漏掉。

弹性 IP 面板把这两种都标为计费中，「释放全部计费中未使用的 IP」会一起清掉。

## IAM 权限

给个只有 EC2 权限的 IAM 用户就够了，不需要账单权限。用到的 API：

```
ec2:DescribeRegions          ec2:DescribeImages           ec2:RunInstances
ec2:DescribeInstances        ec2:DescribeInstanceAttribute
ec2:StartInstances           ec2:StopInstances            ec2:RebootInstances
ec2:TerminateInstances       ec2:CreateKeyPair            ec2:DescribeKeyPairs
ec2:CreateSecurityGroup      ec2:AuthorizeSecurityGroupIngress
ec2:DescribeSecurityGroups   ec2:DescribeVpcs             ec2:DescribeSubnets
ec2:AllocateAddress          ec2:AssociateAddress         ec2:ReleaseAddress
ec2:DescribeAddresses        ec2:CreateTags               ec2:DescribeVolumes
```

勾选 IPv6 还需要：`CreateVpc` `CreateSubnet` `CreateInternetGateway`
`AttachInternetGateway` `CreateRoute` `DescribeRouteTables` `AssociateRouteTable`
`ModifyVpcAttribute` `ModifySubnetAttribute` `AssociateSubnetCidrBlock` `AssignIpv6Addresses`

另外建议加上两个权限：

| 权限 | 用途 | 缺失后果 |
|---|---|---|
| `ssm:GetParameter` | 读发行方发布的官方 AMI 参数 | 退回 `DescribeImages` 名称匹配；Windows 镜像不可用 |
| `ec2:DescribeInstanceTypes` | 拉该区域真实支持的实例规格 | 降级为内置清单，可能选到该区域不支持的规格 |
| `servicequotas:GetServiceQuota` | 账号探测里查 vCPU 配额 | 探测的配额一项标为未通过，其余不受影响 |
| `sts:GetCallerIdentity` | 账号探测里确认身份、提示 root 凭据风险 | 身份检查一项失败 |

Lightsail 栏需要：`lightsail:GetRegions` `lightsail:GetBundles` `lightsail:GetBlueprints`
`lightsail:GetInstances` `lightsail:GetInstance` `lightsail:CreateInstances`
`lightsail:StartInstance` `lightsail:StopInstance` `lightsail:RebootInstance`
`lightsail:DeleteInstance` `lightsail:GetStaticIps` `lightsail:DetachStaticIp`
`lightsail:ReleaseStaticIp`

Bedrock 栏需要：`bedrock:ListFoundationModels`、`bedrock:ListInferenceProfiles`，
调用测试还要 `bedrock:InvokeModel`（Converse 走同一权限），且需在 Bedrock 控制台的
「模型访问」里为具体模型申请开通。

`ListInferenceProfiles` 用来解析只支持推理配置文件的模型（Claude Opus 4/4.1、
Sonnet 4.x 等）：它们的 `inferenceTypesSupported` 里没有 `ON_DEMAND`，
必须换成带地理前缀的配置文件 id（`us.` / `eu.` / `apac.` / `global.`）才能调用。
缺这个权限时按区域前缀猜一个，猜错会在调用时报错，不影响其他模型。

终止实例的连带清理还需要：`ec2:DeleteVolume` `ec2:DeleteSecurityGroup`
`ec2:DeleteKeyPair` `ec2:ReleaseAddress`，以及删自建 VPC 时的
`ec2:DeleteVpc` `ec2:DeleteSubnet` `ec2:DeleteInternetGateway`
`ec2:DetachInternetGateway` `ec2:DeleteRouteTable` `ec2:DisassociateRouteTable`
`ec2:DeleteNetworkInterface`。缺哪项就哪项清理不掉，会在结果里标为"未能清理"。

两者都是可选的，缺失时功能降级但不中断。Windows 镜像强依赖 `ssm:GetParameter` ——
Windows AMI 在 `DescribeImages` 里不可靠（实测 ap-east-1 返回 0 条）。

## 数据存储

业务数据全部在 Postgres，`AWS_HELPER_DATA` 目录只放 `secret.key` 一个文件。

从旧版本（SQLite）升级时首次启动会自动迁移：检测到数据库为空且数据目录里存在
`aws-helper.db`，就把 9 张表全部导入（含加密字段、密码哈希、日志），
然后把旧文件改名为 `.db.migrated`。库里已有数据时绝不导入，避免误覆盖。

备份要同时备份数据库和 `secret.key`，缺一不可 —— 库里的凭据用这把密钥加密。

```bash
# systemd 部署
sudo -u postgres pg_dump awshelper > awshelper.sql
sudo cp /var/lib/aws-helper/secret.key ./secret.key.bak

# Docker 部署
cd /opt/aws-helper-docker
docker compose exec -T postgres pg_dump -U awshelper awshelper > awshelper.sql
docker compose exec -T aws-helper cat /data/secret.key > secret.key.bak
```

## 凭据存储

AWS Secret Access Key 和代理地址用 Fernet 加密后存 Postgres，页面只显示掩码。
加密密钥取 `AWS_HELPER_SECRET`，未设置时在数据目录生成 `secret.key`（权限 0600）。

换掉密钥会导致已存凭据无法解密——工具会明确报错，不会静默失败。

面板登录密码走单向哈希，会话令牌只存摘要，两者都不可逆、也不需要 Fernet 密钥。

Access Key ID 按设计明文存储，用于展示掩码。

旧版本的数据库（没有代理列、没有会话表）打开时会自动补齐，不需要删库重建。

## 测试

数据库层不做 mock，直接跑真实 SQL，所以需要一个可用的 Postgres：

```bash
docker run -d --name pgtest -e POSTGRES_PASSWORD=test \
    -e POSTGRES_DB=awshelper -p 15432:5432 postgres:16-alpine

pip install "moto[ec2,server]==5.0.28" pytest httpx PySocks PyYAML
python3 -m pytest tests/ -q
```

连接串默认 `postgresql://postgres:test@127.0.0.1:15432/awshelper`，
可用 `AWS_HELPER_TEST_DATABASE_URL` 覆盖；库不可达时相关测试自动 skip。
每个测试独占一个随机 schema，跑完自动 DROP。

574 个测试。AWS 侧全部用 moto 模拟，不碰真实账号。覆盖开机全链路、
UserData 注入与顺序、安全组端口、换 IP 两种策略、EIP 泄漏与孤儿回收、
IP 段规则、凭据与代理加密、账号编辑、密码哈希与强度、会话生命周期、
登录锁定、CLI 密码重置、自动换 IP 触发与恢复、SQLite 迁移与序列校正、
并发写入、缓存命中与失效、DDNS 解析同步与一键脚本生成。

代理相关测试用 [tests/socks_server.py](tests/socks_server.py) 起真实 SOCKS5 服务器
（支持 RFC 1929 认证），断言代理端确实记录到了目标连接 —— 否则"代理生效"是无法证伪的。
这些测试跑在真实 HTTP 的 moto server 上，因为 `mock_aws` 在 botocore 层拦截调用，
根本不产生 socket 流量，代理永远不会被拨号。

## 代码结构

```
aws_helper/
  auth.py            密码哈希、强度校验、登录锁定判定
  cli.py             密码重置 / 状态查看 / 下线全部会话
  core/aws.py        boto3 客户端工厂、SOCKS 代理、区域与镜像目录、账号探测
  core/userdata.py   开机脚本渲染与校验
  core/launch.py     一键开机、实例列表、电源操作
  core/ipchange.py   换 IP 两种策略、EIP 清理
  core/lightsail.py  Lightsail 套餐、蓝图、实例、静态 IP
  core/bedrock.py    Bedrock 模型清单、可用性探测、Converse 调用
  store.py           Postgres 持久层（加密凭据、会话、规则、日志、SQLite 迁移）
  cache.py           进程内 TTL 缓存与失效
  ddnsmon.py         DDNS 监控循环
  core/ddns.py       DNS 供应商接口 + Cloudflare + 取本机公网 IP
  core/ddns_script.py 生成自包含的一键部署脚本（bash + curl）
  tasks.py           后台任务与进度跟踪
  autoip.py          自动换 IP 监控循环
  web/app.py         FastAPI 路由
  web/templates/     左侧目录布局 + 十一个页面
  demo/              演示环境（moto 后端 + 预置数据）

deploy/install.sh    一键部署（systemd / docker 两种方式）
Dockerfile           容器镜像（非 root + healthcheck）
docker-compose.yml   compose 服务定义
requirements.txt     固定版本的运行时依赖
```

## 两种方式并存

想同时跑两套（比如一套生产、一套试新版），换个端口装第二种即可：

```bash
sudo bash deploy/install.sh --mode systemd --port 8765
sudo bash deploy/install.sh --mode docker  --port 8766
```

两者完全隔离，互不影响：

| | systemd | docker |
|---|---|---|
| 安装目录 | `/opt/aws-helper` | `/opt/aws-helper-docker` |
| 数据 | `/var/lib/aws-helper` | docker 卷 `aws-helper-data` |
| 管理命令 | `aws-helper-systemd` | `aws-helper-docker` |

两套密码、AWS 账号、脚本模板各自独立。`aws-helper` 是软链，指向最近一次安装的那套；
要明确操作某一套就用带后缀的命令。

卸载其中一种时会检测另一种是否还在，不会删掉共享的东西，`aws-helper` 软链自动指向剩下那套。

## 端口冲突与常见问题

安装脚本会在部署前检查端口。若被**其他进程**占用会直接终止并打印占用者的 PID ——
不会装完却让服务陷入反复重启（那种情况摘要照样显示"部署完成"，
用户拿着"正确"的密码登不进去，很难排查）。重装本程序自己占的端口不受影响。

健康检查失败时脚本返回非 0 退出码，便于 CI 或上层脚本判断。

| 现象 | 处理 |
|---|---|
| 端口被占用 | 换端口 `--port 8790`，或停掉占用进程 |
| 服务启动失败 | `aws-helper logs` 看日志 |
| 忘记密码 | `aws-helper reset-password` |
| 被登录锁定 | `aws-helper reset-password`（会清掉锁定状态） |
| 改了密码想确认 | `aws-helper info` 看密码更新时间和会话 |
| `docker compose` 不可用 | 脚本会自动装 v2 插件；失败则手动装后重试 |
