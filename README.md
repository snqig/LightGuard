<div align="center">

# LightGuard V2.0 终极完整版

### Windows 内网安全容灾审计一体化平台

**落尘（Luochen）独立原创开发**

纯用户态 · 无驱动蓝屏 · ETW+YARA 双层勒索防御 · AES-256-GCM 加密抗勒索备份 · SMB 文件服务器审计

[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4)](https://dotnet.microsoft.com/)
[![Platform](https://img.shields.io/badge/Platform-Win10%2FWin11%2FServer-0078D4)](https://learn.microsoft.com/windows/)
[![Arch](https://img.shields.io/badge/Arch-x64%2Farm64%2Fx86-orange)](https://learn.microsoft.com/dotnet/core/rid-catalog)
[![License](https://img.shields.io/badge/License-Proprietary-red)](LICENSE.md)
[![Release](https://img.shields.io/badge/Release-v2.0-blue)](https://github.com/snqig/LightGuard/releases)

</div>

---

> © 2026 落尘（Luochen） 保留所有权利
>
> 本项目全套架构设计、加密备份分片算法、抗勒索备份机制、ETW+YARA 双层防御、文件服务器 SMB 行为审计引擎、全粒度恢复系统均为落尘独立原创开发。未经作者书面许可，禁止拆分核心模块、逆向、二次封装、商用售卖、冒充自研。

---

## 目录

- [项目概述](#项目概述)
- [七大核心模块](#七大核心模块)
- [ETW+YARA 双层勒索防御](#etwyara-双层勒索防御)
- [加密抗勒索备份体系](#加密抗勒索备份体系)
- [全链路灾难恢复](#全链路灾难恢复)
- [SMB 文件服务器审计](#smb-文件服务器审计)
- [全局日志审计](#全局日志审计)
- [系统要求](#系统要求)
- [快速开始](#快速开始)
- [项目结构](#项目结构)
- [技术架构](#技术架构)
- [构建](#构建)
- [三期开发规划](#三期开发规划)
- [版本历史](#版本历史)
- [版权说明](#版权说明)

---

## 项目概述

LightGuard 是落尘独立原创开发的 Windows 内网轻量化安全容灾审计一体化平台，搭载市面开源工具不具备的自研加密备份、服务器审计、双层勒索防御三大核心能力。

### 解决行业四大痛点

| 痛点 | LightGuard 解决方案 |
|------|---------------------|
| 安全软件体积臃肿、驱动冲突蓝屏 | 纯用户态实现，无内核驱动，无蓝屏风险 |
| 备份工具无加密，局域网共享可随意查看 | AES-256-GCM 加密 + .lgbackup 私有格式，内网防偷看 |
| 文件服务器缺少操作追溯 | SMB 双采集审计引擎，全流程可追溯可预警 |
| 仅能事后查杀病毒，无法提前识别勒索 | ETW 行为监控 + YARA 特征核验，事前主动拦截 |

### 设计约束

- 不做全盘病毒扫描、不搭建程序沙箱、不使用内核 Hook 驱动
- 核心能力聚焦：异常行为检测、文件特征核验、防火墙流量管控、系统广告净化、加密分片备份、灾难数据恢复、服务器操作审计
- 全平台兼容 x86/x64/ARM64，适配 Win10/11 客户端、Windows Server 2019/2022 文件服务器

---

## 七大核心模块

全部由落尘原创设计，采用模块化架构（IModule 接口 + ModuleBase 基类）：

| 模块 | 分类 | 功能描述 |
|------|------|----------|
| 系统隐私加固 + 防火墙 ACL | Privacy / Firewall | 12项隐私优化 + 原生 COM 五元组规则 + VPN 防绕过 + 4套预设模板 |
| ETW+YARA 双层勒索防御 | Ransomware | ETW 实时行为监控 + YARA 按需特征核验 + 进程挂起隔离 + 自动断网 |
| 全域三层广告屏蔽 | Cleanup | Hosts 域名拦截 + 防火墙流量管控 + 注册表配置 |
| 加密抗勒索分片备份 | Backup | AES-256-GCM 加密 + .lgbackup 私有格式 + 五层粒度 + SMB 容灾 |
| 灾难恢复系统 | Recovery | 三种恢复模式 + 裸机救援 + 版本回溯 + 在线预览 |
| 数据库冷热备份 | DatabaseBackup | SQLite/MySQL/MariaDB/SQL Server/Access 热备份 + 加密 |
| SMB 文件服务器审计 | Audit | NTFS SACL + ETW 双采集 + 风险识别 + 告警联动 |

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

风险触发后自动执行：挂起恶意进程 → 防火墙应急断网 → 弹窗高危告警 → 锁定系统卷影备份

### 第二层：YARA 特征核验（精准识别已知勒索）

- 不进行全盘扫描，仅行为异常触发后对目标文件按需扫描，极低资源占用
- 内置离线勒索规则库（200+ 条特征），支持签名校验后的规则在线更新
- 误报优化：Windows 系统目录 + 安全软件路径白名单跳过

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

### 五层全粒度备份

| 层级 | 说明 | 特性 |
|------|------|------|
| 单文件备份 | 凭证、配置、密钥 | 增量、哈希校验、版本留存 |
| 整目录备份 | 桌面、文档、项目目录 | 黑名单过滤缓存/临时文件 |
| 分区镜像备份 | C盘/D盘 | VSS 卷影副本热备份，无需关机 |
| 整块硬盘备份 | 扇区级完整镜像 | 整机迁移、硬盘报废救援 |
| 数据库备份 | SQLite/MySQL/MariaDB/SQL Server/Access | 整库/单表/事务日志增量热备份 |

### 备份策略

全量备份、增量备份、差异备份、自动合成全量；支持 SMB 断点续传、传输限速、离线缓存、上线自动同步。

### 自动生命周期管理

- 按保留份数清理（保留最新N套全量+M天增量）
- 按时长清理（7/30/90天周期）
- 核心备份锁定保护（锁定备份不被自动删除）
- 清理全程写入审计日志

### 可视化进度

备份进度：实时百分比、MB/s 速度、文件数、容量、剩余时间、加密状态、当前文件路径
恢复进度：解密进度、分片恢复、文件写入、校验进度、剩余时间

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

单文件精准恢复、目录批量恢复、分区镜像恢复、整盘镜像恢复、数据库解密还原、跨设备 SMB 远程恢复、历史版本时间点回溯、备份包在线预览、PE 裸机整机救援。

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

高危行为弹窗提醒 → 同步推送风险日志至全局审计系统 → 与勒索防护/加密备份模块互通 → 备份目录异常访问直接触发 Critical 告警

---

## 全局日志审计

| 功能 | 说明 |
|------|------|
| 日志分级 | 信息 / 警告 / 错误 / 高危 |
| 日志分类 | 备份、加解密、校验、SMB连接、自动清理、数据库、勒索告警、文件审计、系统、恢复 |
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

1. 从 [Releases](https://github.com/snqig/LightGuard/releases) 下载 `LightGuard.exe`
2. 右键 → **以管理员身份运行**
3. 首次启动跟随引导选择模式即可

> 单文件绿色版，无需安装，解压即用。配置存储在 `%APPDATA%\LightGuard\`。

---

## 项目结构

```
src/LightGuard/
├── Core/                    # 核心框架
│   ├── Interfaces/IModule.cs       # 模块接口 + 分类枚举
│   ├── AppState.cs                 # 全局状态单例
│   ├── ModuleBase.cs               # 模块基类
│   ├── ModuleManager.cs            # 模块管理器（11个模块注册）
│   ├── HardwareDetector.cs         # 硬件检测 + 架构识别
│   ├── AuditLogSystem.cs           # 全局日志审计系统（AES加密）
│   ├── AuditLogExporter.cs         # CSV/TXT 报表导出
│   └── ...
├── Firewall/                # 防火墙 ACL 模块
│   ├── FirewallAclManager.cs       # COM API 核心管理器
│   ├── FirewallAclRule.cs          # 五元组规则实体
│   ├── FirewallPresets.cs          # 4 套预设模板
│   └── ...
├── Ransomware/              # 勒索防护引擎
│   ├── EtwBehaviorMonitor.cs       # ETW 行为监控（落尘原创）
│   ├── YaraEngine.cs               # YARA 轻量特征核验（落尘原创）
│   ├── RansomDefenseEngine.cs      # 双层防御协调器（落尘原创）
│   ├── OfflineVirusDb.cs           # 离线病毒库（200+特征）
│   └── ProcessGuard.cs             # 进程行为沙箱
├── Backup/                  # 加密抗勒索备份引擎
│   ├── BackupCryptoEngine.cs       # AES-256-GCM 加密引擎（落尘原创）
│   ├── BackupShard.cs              # 分片处理（落尘原创）
│   ├── BackupManifest.cs           # 备份清单实体
│   ├── LgBackupFormat.cs           # .lgbackup 私有格式（落尘原创）
│   ├── BackupExecutor.cs           # 五层粒度备份执行器（落尘原创）
│   ├── BackupLifecycle.cs          # 自动生命周期管理
│   └── BackupProgress.cs           # 可视化进度
├── Recovery/                # 灾难恢复系统
│   ├── RecoveryEngine.cs           # 解密恢复引擎（落尘原创）
│   └── RecoveryProgressInfo.cs     # 恢复进度
├── Database/                # 数据库备份
│   ├── DatabaseBackupEngine.cs     # 多数据库热备份引擎
│   └── DatabaseConnectionHelper.cs # 连接辅助
├── Audit/                   # SMB 文件服务器审计
│   ├── SmbAuditCollector.cs        # 双采集融合（落尘原创）
│   └── SmbRiskDetector.cs          # 风险行为识别（落尘原创）
├── Security/                # 安全校验
│   └── UpdateSignatureVerifier.cs  # RSA-2048 签名验证
├── Native/                  # Win32 API 封装
├── Modules/                 # 十一大功能模块
│   ├── PrivacyModule.cs            # 隐私加固
│   ├── CleanupModule.cs            # 广告屏蔽
│   ├── FirewallModule.cs           # 防火墙
│   ├── EtwYaraModule.cs            # ETW+YARA 双层防御
│   ├── RansomwareModule.cs         # 勒索防护（离线库+进程沙箱）
│   ├── EncryptedBackupModule.cs    # 加密抗勒索备份
│   ├── DatabaseBackupModule.cs     # 数据库备份
│   ├── DisasterRecoveryModule.cs   # 灾难恢复
│   ├── SmbAuditModule.cs           # SMB 文件服务器审计
│   ├── AuditLogModule.cs           # 全局日志审计
│   └── UpdateModule.cs             # 自动更新
├── UI/                      # 界面层
│   ├── Pages/                      # 功能页面
│   ├── MainForm.cs                 # 无边框主窗口
│   └── Theme.cs                    # 双主题系统
└── Program.cs               # 入口
```

---

## 技术架构

```
┌─────────────────────────────────────────────────────────────┐
│                   UI 交互层 (WinForms)                        │
│        MainForm · Pages · 鼠标优先 · 双主题 · 进度可视化      │
├─────────────────────────────────────────────────────────────┤
│                模块适配层 (IModule + ModuleBase)              │
│  Privacy · Cleanup · Firewall · EtwYara · Ransomware        │
│  EncryptedBackup · DatabaseBackup · DisasterRecovery        │
│  SmbAudit · AuditLog · Update                               │
├─────────────────────────────────────────────────────────────┤
│                安全引擎层（落尘原创）                          │
│  ETW 行为监控 · YARA 特征核验 · AES-256-GCM 加密分片         │
│  .lgbackup 抗勒索格式 · SMB 双采集审计 · RSA 签名校验        │
│  进程行为沙箱 · 离线病毒库 · VSS 卷影保护                    │
├─────────────────────────────────────────────────────────────┤
│                底层封装层 (COM / P/Invoke)                    │
│  INetFwPolicy2 · ETW EventListener · WMI · VSS              │
│  NtSuspendProcess · AES-GCM · RSA-2048 · SHA-256            │
│  DWM/Mica · NTFS SACL · EventLog · DNS Cache                │
└─────────────────────────────────────────────────────────────┘
```

### 全链路安全防护闭环

```
ETW 勒索行为监控 → YARA 特征核验 → 防火墙应急断网
→ VSS 快照保护 → 全粒度加密备份 → AES 内网密文存储
→ SMB 容灾异地保存 → 自动生命周期清理
→ 全局日志审计归档 → 加密解密精准恢复 → 裸机灾难整机救援
```

---

## 构建

```powershell
# 还原依赖
dotnet restore src/LightGuard/LightGuard.csproj

# 编译
dotnet build src/LightGuard/LightGuard.csproj -c Release

# 发布单文件 EXE — x64
dotnet publish src/LightGuard/LightGuard.csproj `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:EnableCompressionInSingleFile=true `
  -o ./publish

# ARM64 / x86 同理替换 -r win-arm64 / -r win-x86
```

> 需要 .NET SDK 8.0+ 或 10.0+

---

## 三期开发规划

### Phase 1：基础安全与加密底座（已完成）

- RSA 全局文件签名校验框架
- AES-256-GCM 加密备份底层引擎
- 离线勒索行为基线规则
- 全域广告屏蔽基础功能
- 全架构多平台适配底层框架

### Phase 2：核心全功能版本（当前里程碑）

- ETW 行为监控完整开发，联动 YARA 病毒检测
- 五层粒度备份引擎开发
- 数据库冷热备份还原全套功能
- 备份、还原双端进度可视化 UI
- 备份生命周期自动清理策略
- 全局日志检索、报表导出体系
- 文件服务器 SMB 审计模块全部功能落地

### Phase 3：高级优化与灾难恢复能力完善（规划中）

- PE 裸机整机离线恢复功能
- 备份版本精细化回溯管理
- 审计日志远端 NAS 自动归档
- 风险行为智能告警渠道对接
- 加解密性能深度优化
- 文件服务器高并发访问性能调优

---

## 版本历史

### v2.0.0 (2026-08-01) — 终极完整版

**落尘原创七大核心模块架构正式定稿：**

- ETW+YARA 双层勒索防御引擎（ETW 行为监控 + YARA 按需特征核验）
- AES-256-GCM 加密抗勒索备份体系（.lgbackup 私有格式 + 五层粒度 + SMB 容灾）
- 全链路解密灾难恢复系统（三种恢复模式 + 版本回溯 + 在线预览）
- 数据库冷热备份模块（SQLite/MySQL/MariaDB/SQL Server/Access 热备份）
- Windows 文件服务器 SMB 审计模块（NTFS SACL + ETW 双采集 + 风险识别）
- 全局日志审计报表体系（AES 加密防篡改 + CSV/TXT 导出 + SMB 归档）
- 备份自动生命周期管理（保留份数/时长清理 + 核心备份锁定）

### v1.0.1 (2026-08-01)

- 离线病毒库（200+ 特征）、进程行为沙箱、RSA-2048 签名校验、多架构支持

### v1.0.0 (2026-08-01)

- 初始版本：六大模块、双模式 UI、智能后台调度

---

## 版权说明

**© 2026 落尘（Luochen） 所有权利保留**

> 本项目为**保留版权的受限分发软件**，**并非 MIT/开源许可证**（仓库内已移除 MIT 徽章，详见 [LICENSE.md](LICENSE.md)）。允许个人开源自用与二次分发，但核心算法与架构的商业化使用、逆向、二次封装售卖均需作者书面授权。

LightGuard 整套软件全部核心架构由落尘 2026 年独立原创研发，原创内容包含但不限于：

- ETW+YARA 双层轻量化勒索防御架构
- 局域网 SMB 私有加密防泄露备份体系、抗勒索私有备份格式 `.lgbackup`
- 五层粒度 + 数据库一体化备份还原引擎
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
