<div align="center">

# LightGuard V3.6.0 终极完整版

### 五合一全栈 Windows 安全容灾审计系统

**落尘（Luochen）独立原创开发**

纯用户态 · 无驱动蓝屏 · ETW+YARA 双层勒索防御 · AES-256-GCM 加密抗勒索备份 · SMB 文件服务器审计 · Client-Server 自定义 TCP 备份 · 勒索解密 · Defender 联动

[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4)](https://dotnet.microsoft.com/)
[![Platform](https://img.shields.io/badge/Platform-Win10%2FWin11%2FServer-0078D4)](https://learn.microsoft.com/windows/)
[![Arch](https://img.shields.io/badge/Arch-x64%2Farm64%2Fx86-orange)](https://learn.microsoft.com/dotnet/core/rid-catalog)
[![License](https://img.shields.io/badge/License-Proprietary-red)](LICENSE.md)
[![Release](https://img.shields.io/badge/Release-v3.6.0-blue)](https://github.com/snqig/LightGuard/releases)

</div>

---

> © 2026 落尘（Luochen） 保留所有权利
>
> 本项目全套架构设计、加密备份分片算法、抗勒索备份机制、ETW+YARA 双层防御、文件服务器 SMB 行为审计引擎、Client-Server 自定义 TCP 备份协议、全粒度恢复系统均为落尘独立原创开发。未经作者书面许可，禁止拆分核心模块、逆向、二次封装、商用售卖、冒充自研。

---

## 目录

- [项目概述](#项目概述)
- [五大核心能力](#五大核心能力)
- [Client-Server 自定义 TCP 备份（v3.6 新增）](#client-server-自定义-tcp-备份v36-新增)
- [ETW+YARA 双层勒索防御](#etwyara-双层勒索防御)
- [加密抗勒索备份体系](#加密抗勒索备份体系)
- [勒索解密与应急（v3.0 新增）](#勒索解密与应急v30-新增)
- [Microsoft Defender 联动（v3.0/v3.4）](#microsoft-defender-联动v30v34)
- [全链路灾难恢复](#全链路灾难恢复)
- [SMB 文件服务器审计](#smb-文件服务器审计)
- [商业软件联网隔离（v3.2 新增）](#商业软件联网隔离v32-新增)
- [多语种框架（v3.0 新增）](#多语种框架v30-新增)
- [全局日志审计](#全局日志审计)
- [系统要求](#系统要求)
- [快速开始](#快速开始)
- [项目结构](#项目结构)
- [技术架构](#技术架构)
- [构建](#构建)
- [版本历史](#版本历史)
- [版权说明](#版权说明)

---

## 项目概述

LightGuard 是落尘独立原创开发的 Windows 内网轻量化安全容灾审计一体化平台，融合**防护、审计、解密、杀毒调度、企业级备份容灾**五大体系，形成「五合一全栈 Windows 安全容灾系统」。

### 解决行业五大痛点

| 痛点 | LightGuard 解决方案 |
|------|---------------------|
| 安全软件体积臃肿、驱动冲突蓝屏 | 纯用户态实现，无内核驱动，无蓝屏风险 |
| 备份工具无加密，局域网共享可随意查看 | AES-256-GCM 加密 + .lgbackup 私有格式，内网防偷看 |
| 文件服务器缺少操作追溯 | SMB 双采集审计引擎，全流程可追溯可预警 |
| 仅能事后查杀病毒，无法提前识别勒索 | ETW 行为监控 + YARA 特征核验，事前主动拦截 |
| 单机备份无法跨机器去重、集中管理 | Client-Server 自定义 TCP 备份，块级真增量跨机器 |

### 设计约束

- 不做全盘病毒扫描、不搭建程序沙箱、不使用内核 Hook 驱动
- 核心能力聚焦：异常行为检测、文件特征核验、防火墙流量管控、系统广告净化、加密分片备份、C/S 集中容灾、灾难数据恢复、服务器操作审计、勒索解密应急
- 全平台兼容 x86/x64/ARM64，适配 Win10/11 客户端、Windows Server 2019/2022 文件服务器

---

## 五大核心能力

| 能力 | 模块 | 功能描述 |
|------|------|----------|
| 防护 | Privacy / Firewall / Ransomware | 12项隐私优化 + COM 五元组防火墙 + ETW+YARA 双层勒索防御 + 勒索病毒解密 |
| 审计 | Audit / AuditLog | NTFS SACL+ETW 双采集 SMB 审计 + AES 加密全局日志报表 |
| 解密 | Decryption | 12 大勒索家族识别 + 官方解密工具库 + 应急解密流程 |
| 杀毒调度 | Defender | Microsoft Defender 四种扫描模式 + 查杀记录 + 全业务联动 |
| 备份容灾 | Backup / DatabaseBackup / Recovery / CsBackup | AES-256-GCM 加密备份 + 五层粒度 + 数据库热备 + C/S 块级增量 + 快照恢复 |

### 模块清单

| 模块 | 分类 | 功能描述 |
|------|------|----------|
| 系统隐私加固 + 防火墙 ACL | Privacy / Firewall | 12项隐私优化 + 原生 COM 五元组规则 + VPN 防绕过 + 4套预设模板 |
| ETW+YARA 双层勒索防御 | Ransomware | ETW 实时行为监控 + YARA 按需特征核验 + 进程挂起隔离 + 自动断网 |
| 全域三层广告屏蔽 | Cleanup | Hosts 域名拦截 + 防火墙流量管控 + 注册表配置 |
| 加密抗勒索分片备份 | Backup | AES-256-GCM 加密 + .lgbackup 私有格式 + 五层粒度 + SMB 容灾 |
| Client-Server 备份 | CsBackup | 自定义 TCP 协议 + 客户端本地分块加密 + 仅上传缺失块 + 快照恢复 |
| 灾难恢复系统 | Recovery | 三种恢复模式 + 裸机救援 + 版本回溯 + 在线预览 |
| 数据库冷热备份 | DatabaseBackup | SQLite/MySQL/MariaDB/SQL Server/Access 热备份 + 加密 |
| 勒索病毒解密 | Decryption | 12 大勒索家族识别 + 官方解密工具索引 + 批量解密 |
| Defender 联动 | Defender | MpCmdRun 四种扫描 + 策略联动 + 查杀历史 |
| 商业软件联网隔离 | SuiteIsolation | 指定软件内网/外网一键隔离 + 合规上网 |
| SMB 文件服务器审计 | Audit | NTFS SACL + ETW 双采集 + 风险识别 + 告警联动 |

---

## Client-Server 自定义 TCP 备份（v3.6 新增）

落尘原创的企业级集中备份方案：**业务主机本地完成分块、SHA256、AES-256-GCM 加密，服务端只存密文块**，实现跨机器块级真增量，不重复传输已存在块。

### 架构总览

```
┌── 业务主机（客户端，多台） ──────────────────┐      ┌── 备份服务器（LightGuardServer） ──┐
│  文件扫描 → 分块 → SHA256 → AES-256-GCM 加密   │      │  TCP 监听（自定义端口 + 密码认证）   │
│  发送 hash 摘要列表 ────────────────┐          │      │  blocks/{hash}.blk 密文块存储       │
│  仅上传服务端缺失的加密块           │          │      │  snapshots/{id}.json 快照元数据     │
│  快照：条目 → 块 hash 序列          │          │      │  meta.index 全局块索引（引用计数）   │
│  恢复：拉快照 → 下载密文 → 解密写回  │          │      │  并发锁保证多客户端快照安全          │
└─────────────────────────────────────┘          └──▲──┴────────────────────────────────────┘
```

### 核心特性

- **客户端本地加密**：AES-256-GCM 在业务主机完成，网络传输全密文，服务端无法解密
- **缺失块判定**：客户端只发送 hash 摘要列表，服务端本地 `meta.index` 索引判定，**不做远端备份集读取比对**，杜绝无效网络 IO
- **块级真增量**：跨机器去重，二次备份仅上传变更块（复用块零传输）
- **断线重连 + 断点续传**：自动重连重试，块级分片 `Offset` 续传游标
- **多客户端并发**：每客户端独立会话 Task + BlockStore/SnapshotStore 内部锁，防止快照损坏
- **快照回收**：按每客户端保留策略清理，引用计数归零自动删除块
- **数据库 C/S 备份**：客户端本地 mysqldump/pg_dump/sqlite 导出 → 加密流 1MB 分片上传，不落地明文临时文件
- **快照恢复**：服务端下发块密文 → 客户端解密 → 写回目标路径

### 自定义二进制协议

定长报文头 20 字节（大端）：`Magic(4)=0x4C474253 | Version(2) | Cmd(1) | Flags(1) | Seq(4) | PayloadLen(4) | Crc(4)`
负载 = `[int32 jsonLen][JSON 消息体][可选原始二进制段（块密文 / 流分片）]`，CRC32 校验防篡改。

命令码：`Hello/AuthChallenge/AuthResponse/AuthResult` 握手认证（HMAC-SHA256，密码永不过网）、`BlockExistQuery/Result` 缺失块查询、`UploadBlock/Ack` 分片上传、`SnapshotCreate/List/Get/Delete/Cleanup` 快照管理、`DownloadBlock/Data` 恢复下发。

### 工作模式切换

```ini
[ClientMode]
WorkMode = local          ; local = 原有本地/SMB 备份 | client_server = C/S 集中备份
ServerHost = 192.168.1.10 ; C/S 模式：服务端 IP
ServerPort = 17621        ; C/S 模式：服务端端口
AuthPassword = ********   ; C/S 模式：认证密码（运行时 challenge-response 认证）
ClientId = WS-01          ; 客户端标识（默认机器名）
BlockSize = 262144        ; 块大小（256KB）
ReconnectAttempts = 3     ; 断线重连次数
MaxSnapshotsPerClient = 20
```

> 原有本地/SMB 备份模式完全保留：`backup_set_root` 仍可为本地路径或 SMB 挂载路径，全部功能不变；C/S 为可选新增模式。

---

## ETW+YARA 双层勒索防御

落尘原创的轻量化勒索防御架构，区别于传统杀毒软件事后查杀模式。

### 第一层：ETW 行为监控（拦截未知勒索）

实时监控五类高危风险动作：

| 行为类型 | 检测规则 | 风险等级 |
|----------|----------|----------|
| 批量篡改文件后缀 | 10秒内修改30+文件后缀 | High |
| 短时间大量加密写入 | 10秒内对50+高价值文件写入 | High |
| 遍历全盘目录 | 30秒内遍历200+目录 | Medium |
| 删除 VSS 卷影副本 | 检测 vssadmin.exe 调用 | Critical |
| 批量移动加密文件 | 10秒内移动20+文件 | High |

风险触发后自动执行：挂起恶意进程 → 防火墙应急断网 → 弹窗高危告警 → 锁定系统卷影备份。

### 第二层：YARA 特征核验（精准识别已知勒索）

- 不进行全盘扫描，仅行为异常触发后对目标文件按需扫描，极低资源占用
- 内置离线勒索规则库（200+ 条特征），支持签名校验后的规则在线更新
- 误报优化：Windows 系统目录 + 安全软件路径白名单跳过 + 3.5s 高危 API 延迟 + 五维节流（文件遍历/ETW/VSS/进程启动/注册表）

### 双层协同

```
ETW 捕获未知异常行为
        ↓
YARA 对目标进程按需特征核验
        ↓
    综合判定
    ├─ ETW + YARA 双重确认 → Critical（立即断网+隔离）
    ├─ 仅 ETW 触发 → High（挂起进程+告警）
    └─ VSS 删除行为 → Critical（无需 YARA 核验）
```

---

## 加密抗勒索备份体系

落尘原创的局域网私有加密容灾系统，核心解决两大痛点：内网防偷看 + 抗勒索破坏。

### 加密算法套件

| 用途 | 算法 | 说明 |
|------|------|------|
| 存储加密（默认） | AES-256-GCM | 加密+完整性校验，篡改任意字节解密失败 |
| ARM/低配设备 | ChaCha20-Poly1305 | 自动切换 |
| 国密合规（可选） | SM4 | 对称加密 |
| 密钥派生 | PBKDF2-HMAC-SHA256 | 10万次迭代+32字节随机盐，抵御彩虹表 |
| 完整性校验 | SHA-256 | 分片独立哈希 + 整包全局哈希 |
| 传输加密 | SMB over TLS 1.3 | 局域网防抓包 |
| 权限隔离 | RSA-2048 | 公私钥分离，员工只能上传无法解密 |

### 抗勒索核心机制

- **私有备份格式** `.lgbackup` — 勒索病毒无法识别、无法加密、无法破坏
- **GCM 完整性校验** — 备份文件被修改后直接标记损坏，拒绝恢复
- **密钥本地存储** — 解密密钥永不存储在局域网服务器，只在本机
- **VSS 卷影快照** — 运行中文件/数据库一致性备份
- **防勒索只读隔离备份池** — 系统 ACL 权限锁定，仅凭 LightGuard 授权 token 访问
- **健康检查** — 自动 MD5 校验 + 压缩包完整性 + 快照链结构自检

### 五层全粒度备份

| 层级 | 说明 | 特性 |
|------|------|------|
| 单文件备份 | 凭证、配置、密钥 | 增量、哈希校验、版本留存 |
| 整目录备份 | 桌面、文档、项目目录 | 黑名单过滤缓存/临时文件 |
| 分区镜像备份 | C盘/D盘 | VSS 卷影副本热备份，无需关机 |
| 整块硬盘备份 | 扇区级完整镜像 | 整机迁移、硬盘报废救援 |
| 数据库备份 | SQLite/MySQL/MariaDB/SQL Server/Access | 整库/单表/事务日志增量热备份 |

### 备份策略

- **增量 + 差异双引擎**：初始全量基备份 + 每日增量字节级备份 + 每周差异快照链自动合成
- **定时/实时调度**：cron 表达式定时 + 实时文件监控触发（v3.5）
- **多版本时间快照链**：小时/日/周快照，支持时间点恢复
- **大文件断点续传**：SMB 断点续传 + 传输限速 + 离线缓存 + 上线自动同步
- **智能过滤**：排除缓存/临时/系统冗余文件
- **生命周期管理**：按保留份数/时长清理 + 核心备份锁定 + 清理审计日志
- **节流策略**：自动带宽/IO 节流，不干扰业务

### 可视化进度

备份进度：实时百分比、MB/s 速度、文件数、容量、剩余时间、加密状态、当前文件路径
恢复进度：解密进度、分片恢复、文件写入、校验进度、剩余时间

### 选择性还原（v3.3）

.lgbackup 备份内容可视化浏览，单/多文件精准还原，无需整包解压。

---

## 勒索解密与应急（v3.0 新增）

- **12 大勒索家族识别**：扩展名 / 文件头 / 勒索信三特征交叉判定
- **官方解密工具库**：JSON 工具索引（SHA256 校验），一键下载引导
- **批量解密**：先备份副本再解密，失败可回退
- **应急流程**：识别 → 隔离 → 取证 → 解密 → 恢复

---

## Microsoft Defender 联动（v3.0/v3.4）

- **四种扫描模式**：快速 / 全盘 / 自定义 / 离线，异步 CancellationToken 可取消
- **多路径检索**：MpCmdRun.exe 自动定位（固定目录 / PATH / WMI 查询）
- **状态查询**：PowerShell + WMI 双通道检测 Defender 状态与策略
- **查杀记录**：扫描历史持久化 + UI 展示
- **全业务联动**：勒索告警 → Defender 全盘联动查杀（v3.4）

---

## 全链路灾难恢复

### 强制恢复流程（不可跳过）

```
读取加密备份包 → 输入密钥/密钥文件 → AES解密 → SHA256完整性校验
→ 磁盘空间与权限检测 → 选择恢复模式 → 执行数据还原
```

### 三种安全恢复模式

| 模式 | 说明 | 场景 |
|------|------|------|
| 隔离恢复（默认） | 恢复至全新空白目录，不覆盖原文件 | 日常安全恢复 |
| 增量恢复 | 仅还原版本更新变更的文件 | 节省耗时 |
| 强制覆盖恢复 | 直接覆盖目标位置 | 系统中毒、磁盘损坏灾难场景 |

### 全场景恢复能力

单文件精准恢复、目录批量恢复、分区镜像恢复、整盘镜像恢复、数据库解密还原、跨设备 SMB 远程恢复、历史版本时间点回溯、备份包在线预览、C/S 快照恢复、PE 裸机整机救援。

---

## SMB 文件服务器审计

落尘原创的 Windows 文件服务器共享行为审计模块，部署在 Server 2019/2022 上实现全流程可追溯。

### 双采集融合方案

| 采集层 | 技术 | 作用 |
|--------|------|------|
| NTFS SACL 安全事件日志 | Windows Event Log (4663/4624/4660/4670) | 精准持久化存储，兜底审计 |
| ETW 实时事件追踪 | EventListener + EventSource | 低延迟流式采集，实时告警 |

### 可捕获操作行为

- SMB 远程登录（时间、账号、IP、主机名）
- 文件读取/写入/修改/覆盖
- 文件拷贝导出/删除/批量删除/移动/重命名
- 权限篡改/越权访问失败
- 智能风险识别：批量外泄、凌晨访问、高频删除

### 告警联动

高危行为弹窗提醒 → 同步推送风险日志至全局审计系统 → 与勒索防护/加密备份模块互通 → 备份目录异常访问直接触发 Critical 告警。

---

## 商业软件联网隔离（v3.2 新增）

- 指定软件内网/外网一键隔离，合规上网
- 防火墙规则 + ACL 双保险，防止绕过
- 与全局防火墙模块联动管理

---

## 多语种框架（v3.0 新增）

- `LangHelper`：`T() / GetText() / GetLogText()` 统一取词
- **运行时热切换**：中 / 英 / 繁体，无需重启
- JSON 资源：`lang_zh-CN.json` / `lang_en-US.json` / `lang_zh-TW.json`
- 服务器模式强制英文审计日志
- `HardcodeScanner` 硬编码巡检

---

## 全局日志审计

| 功能 | 说明 |
|------|------|
| 日志分级 | 信息 / 警告 / 错误 / 高危 |
| 日志分类 | 备份、加解密、校验、SMB连接、自动清理、数据库、勒索告警、文件审计、系统、恢复、C/S备份 |
| 加密防篡改 | AES-256-GCM 加密存储，按天滚动 |
| 查询检索 | 时间轴、多条件筛选、关键词搜索 |
| 报表导出 | CSV / TXT 格式 |
| 双副本归档 | 本地 + SMB 远端自动同步 |
| 保留策略 | 默认90天自动清理 |

---

## 系统要求

| 项目 | 要求 |
|------|------|
| 操作系统 | Windows 10 1903+ / Windows 11 / Server 2019 / Server 2022 |
| 架构 | x64 (Intel/AMD) / ARM64 (Snapdragon) / x86 (32位) |
| 权限 | 管理员权限（UAC 自动提权） |
| 磁盘 | ~70MB（单文件包含 .NET 运行时） |
| 内存 | 运行时约 20-30MB |

---

## 快速开始

### 单机使用（本地/SMB 备份）

1. 从 [Releases](https://github.com/snqig/LightGuard/releases) 下载 `LightGuard.exe`
2. 右键 → **以管理员身份运行**
3. 首次启动跟随引导选择模式即可

> 单文件绿色版，无需安装，解压即用。配置存储在 `%APPDATA%\LightGuard\`。

### 企业集中备份（Client-Server 模式）

1. **备份服务器**：部署 `LightGuardServer.exe`，运行初始化：

```powershell
.\LightGuardServer.exe setup        # 交互设置端口 + 认证密码（生成 server.json）
.\LightGuardServer.exe              # 启动 TCP 服务（默认 17621）
.\LightGuardServer.exe hashset <pwd> # 手动生成密码哈希写入 server.json
```

2. **业务主机**：LightGuard.exe → 配置 `ClientServer.WorkMode = client_server`，填写服务端 IP / 端口 / 认证密码
3. 执行备份：客户端本地分块加密，仅上传缺失块；服务端保存密文块 + 快照，支持恢复下发

---

## 项目结构

```
src/
├── LightGuard/                  # 客户端主程序（WinForms）
│   ├── Core/                    # 核心框架
│   │   ├── Interfaces/IModule.cs       # 模块接口 + 分类枚举
│   │   ├── AppState.cs                 # 全局状态单例
│   │   ├── ModuleBase.cs / ModuleManager.cs  # 模块基类 / 管理器
│   │   ├── LangHelper.cs               # 多语种框架（v3.0）
│   │   ├── AntiFalsePositive.cs        # 反误报节流引擎（v3.0）
│   │   ├── HardcodeScanner.cs          # 硬编码巡检
│   │   └── ...
│   ├── Firewall/                # 防火墙 ACL 模块
│   ├── Ransomware/              # ETW+YARA 双层勒索防御
│   ├── Backup/                  # 加密抗勒索备份引擎
│   │   ├── BackupCryptoEngine.cs       # AES-256-GCM 加密引擎
│   │   ├── LgBackupFormat.cs           # .lgbackup 私有格式
│   │   ├── BlockIncrementalEngine.cs   # 块级增量引擎
│   │   ├── IncrementalDifferentialEngine.cs  # 增量+差异双引擎
│   │   ├── VssShadowCopyEngine.cs      # VSS 卷影快照
│   │   ├── RansomwareProofBackupPool.cs # 防勒索只读隔离备份池
│   │   ├── BackupHealthVerifier.cs     # 备份健康检查
│   │   ├── ResumableBackupEngine.cs    # 大文件断点续传
│   │   ├── SnapshotChainManager.cs     # 多版本时间快照链
│   │   ├── SmartFilterEngine.cs        # 智能过滤
│   │   ├── BackupThrottleEngine.cs     # 节流策略
│   │   └── ...
│   ├── ClientServer/            # C/S 备份客户端（v3.6）
│   │   ├── ClientServerConfig.cs       # 模式/服务端/认证配置
│   │   ├── CsBackupClient.cs           # 网络层（认证/缺块/上传/快照/下载）
│   │   └── CsBackupService.cs          # 文件/数据库备份 + 快照恢复门面
│   ├── Recovery/                # 灾难恢复系统
│   ├── Database/                # 数据库备份
│   ├── Audit/                   # SMB 文件服务器审计
│   ├── Decryption/              # 勒索解密（v3.0）
│   │   ├── RansomwareFamilyDetector.cs # 12 大家族识别
│   │   ├── DecryptionToolManager.cs    # 官方工具索引
│   │   └── DecryptionToolIndex.json
│   ├── Defender/                # Microsoft Defender 集成（v3.0）
│   ├── NetworkIsolation/        # 商业软件联网隔离（v3.2）
│   ├── Modules/                 # 功能模块（20+）
│   │   ├── CsBackupModule.cs           # C/S 备份模式分发（v3.6）
│   │   ├── DecryptionModule.cs         # 勒索解密（v3.0）
│   │   ├── DefenderScanModule.cs       # Defender 扫描（v3.0）
│   │   ├── SuiteIsolationModule.cs     # 联网隔离（v3.2）
│   │   └── ...
│   ├── UI/                      # 界面层（多语种）
│   └── Program.cs
├── LightGuard.Shared/           # C/S 协议共享库（v3.6）
│   ├── CsProtocol.cs                    # 报文头/命令码/负载定义
│   └── CsTransport.cs                   # 编解码/CRC/认证辅助
├── LightGuardServer/            # C/S 备份服务端（v3.6）
│   ├── CsBackupServer.cs                # TCP 监听 + 认证 + 命令分发
│   ├── BlockStore.cs                    # 密文块存储 + meta.index 引用计数
│   ├── SnapshotStore.cs                 # 快照元数据 + 回收清理
│   ├── ServerConfig.cs / Program.cs     # 配置 + setup/hashset 命令
└── tests/SelectiveRecoveryTest/ # 端到端测试（236 项，含 C/S 全链路）
```

---

## 技术架构

```
┌─────────────────────────────────────────────────────────────┐
│                   UI 交互层 (WinForms · 多语种)               │
│        MainForm · Pages · 双主题 · 进度可视化 · 中/英/繁     │
├─────────────────────────────────────────────────────────────┤
│                模块适配层 (IModule + ModuleBase)              │
│  Privacy · Cleanup · Firewall · EtwYara · Ransomware        │
│  EncryptedBackup · DatabaseBackup · DisasterRecovery        │
│  SmbAudit · AuditLog · Update · Decryption · Defender       │
│  SuiteIsolation · CsBackup                                   │
├─────────────────────────────────────────────────────────────┤
│                安全引擎层（落尘原创）                          │
│  ETW 行为监控 · YARA 特征核验 · AES-256-GCM 加密分片         │
│  .lgbackup 抗勒索格式 · SMB 双采集审计 · RSA 签名校验        │
│  勒索家族识别 · Defender 调度 · C/S 块级增量 + 快照          │
├─────────────────────────────────────────────────────────────┤
│                网络协议层（v3.6 C/S 备份）                    │
│  20B 定长报文头 + JSON + 原始密文段 · CRC32 校验             │
│  challenge-response 认证 · 断点续传 · 多客户端并发锁          │
├─────────────────────────────────────────────────────────────┤
│                底层封装层 (COM / P/Invoke)                    │
│  INetFwPolicy2 · ETW EventListener · WMI · VSS · MpCmdRun   │
│  NtSuspendProcess · AES-GCM · RSA-2048 · SHA-256            │
│  DWM/Mica · NTFS SACL · EventLog · DNS Cache                │
└─────────────────────────────────────────────────────────────┘
```

### 五层安全防护闭环

```
ETW 勒索行为监控 → YARA 特征核验 → Defender 联动查杀
→ 防火墙应急断网 → VSS 快照保护 → 加密备份 / C/S 集中容灾
→ SMB 容灾异地保存 → 勒索病毒解密应急 → 全局日志审计归档
→ 精准解密恢复 → 裸机灾难整机救援
```

---

## 构建

```powershell
# 还原依赖
dotnet restore src/LightGuard/LightGuard.sln

# 客户端单文件 EXE — x64（含 .NET 运行时）
dotnet publish src/LightGuard/LightGuard.csproj `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:EnableCompressionInSingleFile=true `
  -o ./publish/win-x64

# C/S 备份服务端单文件 EXE — x64
dotnet publish src/LightGuardServer/LightGuardServer.csproj `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true `
  -o ./publish/server

# ARM64 / x86 同理替换 -r win-arm64 / -r win-x86

# 双版本打包（MSI + 便携版）
.\packaging\build-all.ps1 -SelfContained

# 端到端测试（236 项，含 C/S 全链路）
dotnet run --project tests/SelectiveRecoveryTest -c Release
```

> 需要 .NET SDK 8.0+

---

## 版本历史

### v3.6.0 (2026-08-08) — Client-Server 自定义 TCP 备份

- 新增 `LightGuardServer` 服务端：TCP 监听自定义端口 + challenge-response 密码认证（密码永不过网）
- 服务端本地持有完整加密备份集（`blocks/`、`snapshots/`、`meta.index`），块 hash 存在性本地判定，不做远端读取比对
- 客户端本地分块 + SHA256 + AES-256-GCM 加密，只发送 hash 摘要列表、仅上传缺失块，跨机器块级真增量
- 自定义二进制协议：20B 定长报文头 + CRC32 + JSON + 原始密文段；断线重连 + 块级分片断点续传
- 多客户端并发安全：独立会话 Task + BlockStore/SnapshotStore 内部锁
- 数据库 C/S 备份：客户端本地 dump → 加密流 1MB 分片上传，不落地明文临时文件
- 快照创建/列表/读取/删除/回收 + 快照恢复（服务端下发块，客户端解密写回）
- `WorkMode` 模式切换：`local`（原有本地/SMB 完全保留）/ `client_server`
- 新增项目：`LightGuard.Shared`（协议共享库）、`LightGuardServer`（服务端）、`ClientServer/`（客户端）
- 端到端测试 236 项全部通过

### v3.5.0 (2026-08-0x) — 备份模块迭代

- 定时/实时增量备份：cron 表达式调度 + 实时文件监控触发
- 数据库备份 cron 调度（每实例独立全量/增量周期）
- dbconfig 引导配置向导

### v3.4.0 — P1 全批次能力

- Defender 全业务集成与 UI 显示一致性修复

### v3.3.0 — 选择性还原

- .lgbackup 备份内容可视化浏览
- 单/多文件精准还原

### v3.2.0 — 商业软件联网隔离

- 指定软件内网/外网一键隔离
- 勒索监控可靠性修复

### v3.1.0 — P1 双版本分发

- Defender 查杀全业务联动
- 双版本分发架构（MSI + 便携版）+ 增量差分更新 + DPI 自适应

### v3.0.0 (2026-08-02) — P0 核心能力

- P0-1 勒索解密模块：12 大家族识别 + 官方工具索引（SHA256 校验）+ 批量解密
- P0-2 反误报重构：3.5s 高危 API 延迟 + 五维节流
- P0-3 全局多语种框架：中/英/繁热切换 + 服务器模式强制英文审计日志
- P0-4 Microsoft Defender 集成：四种扫描模式 + 状态查询 + 历史

### v2.5.0 — 终极企业级容灾备份体系

- 12 大核心能力：增量+差异双引擎、VSS 卷影快照、防勒索只读隔离备份池、健康检查、断点续传、智能过滤、多版本时间快照链、审计报表、异地容灾同步、裸机恢复、防删除权限锁、节流策略

### v2.4.0 — 文件服务器访问审计

- 审计概览/记录/风险告警/策略配置四标签页 + SACL 策略配置 + CSV 导出

### v2.3.0 — 加密备份恢复修复

- 备份列表多目录自动扫描 + 恢复/预览按钮 + 跨标签页恢复流程

### v2.2.0 — P0 安全整改

- 程序自我保护 + 配置加密 + 防火墙守护 + 文件隔离区 + 快照回滚

### v2.1.0 — 备份恢复 UI 重写

- 加密备份 / 灾难恢复 / 数据库备份 / 生命周期管理 四标签页

### v2.0.0 (2026-08-01) — 终极完整版

- ETW+YARA 双层勒索防御引擎
- AES-256-GCM 加密抗勒索备份体系（.lgbackup + 五层粒度 + SMB 容灾）
- 全链路解密灾难恢复系统
- 数据库冷热备份模块
- SMB 文件服务器审计模块
- 全局日志审计报表体系

### v1.0.1

- 离线病毒库（200+ 特征）、进程行为沙箱、RSA-2048 签名校验、多架构支持

### v1.0.0

- 初始版本：六大模块、双模式 UI、智能后台调度

---

## 版权说明

**© 2026 落尘（Luochen） 所有权利保留**

> 本项目为**保留版权的受限分发软件**，**并非 MIT/开源许可证**（详见 [LICENSE.md](LICENSE.md)）。允许个人开源自用与二次分发，但核心算法与架构的商业化使用、逆向、二次封装售卖均需作者书面授权。

LightGuard 整套软件全部核心架构由落尘 2026 年独立原创研发，原创内容包含但不限于：

- ETW+YARA 双层轻量化勒索防御架构
- 局域网 SMB 私有加密防泄露备份体系、抗勒索私有备份格式 `.lgbackup`
- 五层粒度 + 数据库一体化备份还原引擎
- Client-Server 自定义 TCP 备份协议与块级增量容灾架构
- Windows Server 文件共享审计双采集融合架构
- 内网文件外泄、批量删除等风险行为识别规则

### 版权约束条款

- 禁止拆分核心加密、审计、防御逻辑逆向破解、二次封装商用售卖
- 开源自用、二次分发场景，必须完整保留全部版权注释，显著标注原开发者：**落尘（Luochen）**
- 核心算法、架构无作者书面授权，禁止用于同类商业化安全工具开发
- 所有技术文档、源代码、程序成品著作权归属落尘

---

<div align="center">

**[下载最新版](https://github.com/snqig/LightGuard/releases)** · **[报告问题](https://github.com/snqig/LightGuard/issues)**

© 2026 落尘（Luochen） 原创开发 · 保留所有权利

</div>
