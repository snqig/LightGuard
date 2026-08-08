# LightGuard v3.5 备份模块迭代 — 规格设计（SPEC）

> 版本：v3.5.0 迭代
> 日期：2026-08-08
> 状态：**已实现并验证**（build 0 错误 0 警告；测试 218+65 全部通过；dbconfig 入口实测正常）
> 技术栈：C# / .NET 8 / WinForms（需求原文" C 语言控制台项目"经确认按现有 C# WinForms 项目落地）

---

## 1. 背景与目标

现有 LightGuard 已具备：块级真实增量引擎（`BlockIncrementalEngine`，64KB 固定块 + SHA256 去重 + 块复用判定）、快照链管理（`SnapshotChainManager`，全量根 + 增量节点 + 保留策略清理 + 时间点恢复 + 链合并）、USN 变更检测（`UsnChangeDetector`）、五库全量加密备份（`DatabaseBackupEngine`，SQLite/MySQL/MariaDB/SqlServer/Access，AES-256-GCM）。

本迭代补齐以下缺失能力，**保留全部原有功能、不破坏现有逻辑，全部采用增量式开发（新增文件/新增类，仅最小侵入式扩展既有类）**：

1. **文件定时全量 / 定时真实增量备份**（cron 精确调度，非简单间隔）。
2. **实时文件监控增量备份**（ReadDirectoryChangesW / FileSystemWatcher，事件防抖，触发块级增量快照）。
3. **数据库定时调度接入全局单套 Cron**：每个数据库实例独立的定时全量 cron、定时增量 cron。
4. **数据库增量备份**：MySQL 使用 binlog（mysqlbinlog 流式），PostgreSQL 使用 WAL（pg_receivewal 流式采集）；SQLite 强制禁用增量（代码层拦截）。
5. **PostgreSQL 全量备份支持**（pg_dump / pg_basebackup，纳入现有统一加密备份集）。
6. **dbconfig 引导式交互配置**：分字段录入（IP/端口/用户名/密码/库名，SQLite 为文件路径），连接连通性测试，内部拼接连接参数，快捷周期选项（无需手写 cron）。
7. **任务防重入锁**：文件备份锁 + 每个数据库实例独立备份锁，运行中定时触发直接跳过。
8. **授权模块联动**：未授权状态禁用加密备份、定时任务、实时备份、数据库全部功能（配置开启也不执行）。
9. **密码策略**：配置不存明文密码，运行时交互式输入；HKDF 派生密钥；任务结束清空内存密钥（`CryptographicOperations.ZeroMemory`）。
10. **配置扩展**：沿用 JSON 体系，新增文件备份任务段与数据库备份实例段（需求"INI 段"映射为 JSON 配置节，经确认沿用 JSON）。

---

## 2. 现状差异核对（需求 vs 现有代码）

| # | 需求项 | 现状 | 本迭代动作 |
|---|--------|------|-----------|
| F1 | 单文件备份 / 目录递归备份 / 手动全量 | ✅ 已有（`BackupExecutor`） | 复用 |
| F2 | 手动块级真实增量（64KB 块、块去重、快照链） | ✅ 已有（`BlockIncrementalService` / `SnapshotChainManager`） | 复用 |
| F3 | 定时全量备份 | ⚠️ 仅 BackgroundScheduler 凌晨维护占位，无 cron 精确调度 | **新增 cron 调度** |
| F4 | 定时真实增量备份 | ⚠️ 仅手动/USN 触发 | **新增 cron 调度** |
| F5 | 实时监控触发增量 | ❌ 无（现有 FileSystemWatcher 仅用于勒索防护） | **新增监控服务** |
| F6 | 统一加密备份集 AES-256-GCM | ✅ 已有（v3 容器 / DB 引擎） | 复用 |
| F7 | 快照链自动清理 | ✅ 已有（`CleanupOldSnapshots`） | 复用 |
| F8 | 任务防重入锁 | ❌ 无 | **新增** |
| F9 | 控制台进度条 | ⚠️ 有进度事件，无控制台输出 | dbconfig 模式下输出控制台进度 |
| D1 | 数据库手动全量（5 库） | ✅ 已有 | 复用 |
| D2 | PostgreSQL 支持 | ❌ 无 | **新增** |
| D3 | 定时全量 cron（每实例独立） | ⚠️ 全局 30 分钟 tick + 简单间隔 | **新增每实例 cron** |
| D4 | 手动增量（MySQL binlog / PG WAL） | ❌ 无 | **新增增量引擎** |
| D5 | 定时增量 cron（每实例独立，SQLite 禁用） | ❌ 无 | **新增** |
| D6 | 数据库独立任务锁 | ❌ 无 | **新增** |
| D7 | 数据库备份存入统一加密备份集 | ✅ 已有（AES-256-GCM 容器） | 复用 |
| D8 | PITR 基础逻辑 | ✅ 已有（快照链时间点恢复） | 复用 |
| D9 | 授权控制（未授权禁用数据库） | ❌ 无授权体系 | **新增授权门禁** |
| D10 | 增量执行前校验存在全量快照 | ❌ 无 | **新增校验** |
| C1 | dbconfig 引导式配置 | ❌ 仅 UI 表单 + 手写连接串 | **新增 CLI 向导** |
| C2 | 连接连通性测试 | ❌ 无 | **新增** |
| C3 | 快捷周期选项（不手写 cron） | ❌ 无 | **新增** |
| C4 | 密码不落盘 + HKDF + 任务结束清空 | ❌ DPAPI 本机密钥 | **新增密码凭据管理** |

---

## 3. 总体架构

### 3.1 新增组件全景（全部新增文件，零改动现有业务逻辑）

```
src/LightGuard/
├── Backup/
│   ├── BackupCronScheduler.cs          # 全局单套 Cron 调度线程（每分钟 tick，统一调度文件+数据库）
│   ├── CronExpression.cs               # 轻量 5 段 cron 解析/匹配器（含快捷周期预设）
│   ├── FileBackupJob.cs                # 文件备份任务模型（源路径/单文件/目录/定时/实时监控开关）
│   ├── RealtimeFileWatcher.cs          # 实时监控服务（ReadDirectoryChangesW→FileSystemWatcher，防抖→块级增量）
│   ├── BackupReentryLock.cs            # 任务防重入锁（文件任务锁池 + 数据库实例锁池）
│   └── KeyDerivation.cs                # HKDF 密码派生 + 内存密钥零化（复用统一加密备份集口令）
├── Database/
│   ├── DatabaseType 扩展 PostgreSQL     # 枚举 + 后缀映射 + 备份/还原分支（最小侵入）
│   ├── DbIncrementalBackupEngine.cs    # MySQL binlog / PG WAL 流式增量（边读边加密，不落地明文）
│   ├── DbConnectionTester.cs           # 连接连通性测试（SQLite 文件有效性 / MySQL / PG）
│   └── DbConfigWizard.cs               # dbconfig 交互式引导配置（控制台，分步录入→测试→保存）
├── Core/
│   └── LicenseGuard.cs                 # 授权状态门禁（静态，未授权禁用加密备份/定时/实时/数据库）
└── Program.cs                          # 增加 "dbconfig" 参数分支（参考现有 --register-elevation-task 模式）
```

### 3.2 配置扩展（沿用 JSON，AppConfig 新增两个配置节）

```jsonc
// config.json 新增两节（等价需求"INI 段"）：
"fileBackupJobs": [           // 文件备份任务列表
  {
    "name": "工作目录备份",
    "sourcePath": "D:\\Work",
    "isSingleFile": false,
    "enabled": true,
    "fullCron": "0 2 * * 0",          // 每周日 02:00 定时全量
    "incrementalCron": "0 */2 * * *", // 每 2 小时定时增量
    "realtimeWatch": true,            // 实时监控增量开关
    "watchDebounceMs": 3000,          // 事件防抖窗口
    "chainDir": "%BACKUP%\\jobs\\work",
    "retention": { "hourly": 24, "daily": 7, "weekly": 4 },
    "passwordRef": "job_work"         // 引用运行时密码凭据（不落盘明文）
  }
],
"dbBackupInstances": [        // 数据库备份实例列表（每实例独立 cron）
  {
    "name": "生产 MySQL",
    "dbType": "MySQL",
    "host": "192.168.1.10",
    "port": 3306,
    "user": "backup",
    "database": "appdb",
    "dbFilePath": "",                 // SQLite 专用：db 文件路径
    "enabled": true,
    "fullCron": "0 1 * * *",          // 每日 01:00 定时全量
    "incrementalCron": "0 */6 * * *", // 每 6 小时定时增量（SQLite 强制忽略）
    "maxBackupCount": 20,
    "credentialRef": "db_prod_mysql"  // 密码凭据引用（交互输入，不落盘）
  }
]
```

- **密码凭据管理**：`credentialRef` / `passwordRef` 仅存凭据 ID；密码运行时交互输入，经 `KeyDerivation.DeriveKey(password, salt)`（HKDF-SHA256，每实例独立随机盐）派生 AES-256 密钥，用于统一加密备份集口令。任务完成/超时 `ZeroMemory` 清空。
- **授权门禁**：`license.activated`（JSON）为 false 时，`LicenseGuard.IsBackupEnabled()` 恒 false，定时调度跳过、实时监控不启动、dbconfig 拒绝保存启用型配置（仅允许查看）。

### 3.3 全局 Cron 调度线程（BackupCronScheduler）

- 生命周期：`System.Threading.Timer`，每分钟 tick（对齐需求"全局单套 Cron 定时线程"）。
- 职责：遍历 `fileBackupJobs` 与 `dbBackupInstances`，对每个启用任务解析其 fullCron / incrementalCron，命中当前分钟且当日该任务未执行 → 提交后台执行。
- **防重入**：执行前 `BackupReentryLock.TryEnter(taskKey)`，失败（已在运行）→ 记录日志"任务运行中，定时触发跳过"。
- **授权联动**：每次 tick 检查 `LicenseGuard`，未授权直接 return。
- **SQLite 拦截**：dbType=SQLite 时增量 cron 永远不调度（代码层 `IsIncrementalSupported(dbType)` 拦截）。
- **增量前置校验**：数据库增量执行前校验该实例存在最近全量快照（`SnapshotChainManager.FindSnapshotByTime` 或实例全量清单非空），否则告警并跳过任务。

### 3.4 文件定时备份流程

```
BackupCronScheduler.tick
  └─ 命中 job.fullCron（且当日未跑） → 全量：BackupExecutor.BackupDirectory（新建快照链全量根节点）
  └─ 命中 job.incrementalCron        → 增量：BlockIncrementalService.CreateIncrementalFromDirectoryAsync
        （USN 变更检测 → 块级差分 → 增量包 + .lgblockmap → 入快照链增量节点）
  └─ 备份完成 → SnapshotChainManager.AddSnapshot + CleanupOldSnapshots（保留策略）
```

### 3.5 实时监控增量（RealtimeFileWatcher）

- 基于 `FileSystemWatcher`（Win32 ReadDirectoryChangesW 封装），监控源目录（单文件任务监控其父目录+文件名过滤）。
- **事件防抖**：改动事件进入队列，`watchDebounceMs`（默认 3s）窗口内合并 → 触发一次块级增量快照。
- 与定时增量共用同一链，避免链过长：实时增量达到 N 次（默认 12）自动合并为全量（`SnapshotChainManager.MergeSnapshots`），截断增量链。
- 受 `LicenseGuard` 门禁：未授权不启动监控。

### 3.6 数据库增量备份（DbIncrementalBackupEngine）

| 类型 | 全量 | 增量（事务日志） | 工具 |
|------|------|------------------|------|
| MySQL/MariaDB | mysqldump（现有，单事务热备份） | **binlog**：mysqlbinlog `--read-from-remote-server --start-position=<pos>` 流式输出 → 内存流 → 加密写备份集；位置记录 `SHOW MASTER STATUS`，存实例元数据 | mysqlbinlog |
| PostgreSQL | pg_dump（逻辑全量，新增） | **WAL**：pg_receivewal 采集自上次 LSN 起的 WAL 段至受保护临时目录 → 逐段流式读入加密管线 → 立即删除明文段（产物无明文） | pg_receivewal / pg_waldump |
| SQLite | 文件复制（现有） | ❌ **强制禁用**（代码层拦截，即使配置开启也不执行） | — |

- 增量包同样存入统一 AES-256-GCM 加密备份集，元数据记录 `DbType / BackupMode=Incremental / BinlogPos(LSN)`，供 PITR 应用。
- **流式要求**：明文仅存在于内存流或 ACL 隔离的受保护临时目录，加密完成后立即清理，不在备份目录落明文文件。

### 3.7 dbconfig 引导式配置（DbConfigWizard）

- 入口：`LightGuard.exe dbconfig`（Program.cs 新增参数分支，参考现有 `--register-elevation-task` 模式，不破坏主流程）。
- 流程：
  1. 新建 / 选择已有实例；
  2. 下拉选择数据库类型（MySQL / PostgreSQL / SQLite / MariaDB / SqlServer / Access）；
  3. 分字段录入：IP / 端口 / 用户名 / 密码 / 数据库名；SQLite 改为录入 db 文件路径；
  4. 内部拼接连接参数（不要求用户手写连接字符串）；
  5. 保存前执行连接/文件有效性测试（`DbConnectionTester`）；
  6. 快捷周期选项：不常备份 / 每天 / 每周 / 每 2 小时 / 每 6 小时（映射为预设 cron，无需手写）；
  7. 密码经 HKDF 派生后保存盐与凭据引用，**不保存明文密码**；
  8. 控制台输出进度条与结果。
- UI 兼容：配置保存到 config.json 的 `dbBackupInstances` 节后，现有 `DatabaseBackupPage` / 备份引擎自动可见（新增节独立，不破坏现有 UI 读取逻辑）。

---

## 4. 新增结构体/类定义

### 4.1 文件备份任务配置（FileBackupJob）

```csharp
public sealed class FileBackupJob
{
    public string Name { get; set; } = "";            // 任务名（唯一）
    public string SourcePath { get; set; } = "";      // 源路径（文件或目录）
    public bool IsSingleFile { get; set; }            // true=单文件；false=目录递归
    public bool Enabled { get; set; } = true;
    public string FullCron { get; set; } = "";        // 定时全量 cron；空=禁用
    public string IncrementalCron { get; set; } = ""; // 定时增量 cron；空=禁用
    public bool RealtimeWatch { get; set; }           // 实时监控增量开关
    public int WatchDebounceMs { get; set; } = 3000;  // 防抖窗口
    public string ChainDir { get; set; } = "";        // 快照链目录
    public SnapshotRetention Retention { get; set; } = new(); // 保留策略
    public int MaxRealtimeBeforeMerge { get; set; } = 12;     // 实时增量合并阈值
    public string PasswordRef { get; set; } = "";     // 口令凭据引用（不落盘明文）
    public DateTime? LastFullAt { get; set; }
    public DateTime? LastIncrementalAt { get; set; }
    public DateTime? LastRealtimeAt { get; set; }
}

public sealed class SnapshotRetention
{
    public int Hourly { get; set; } = 24;
    public int Daily { get; set; } = 7;
    public int Weekly { get; set; } = 4;
}
```

### 4.2 数据库备份实例配置（DbBackupInstance）

```csharp
public sealed class DbBackupInstance
{
    public string Name { get; set; } = "";            // 实例名（唯一）
    public DatabaseType DbType { get; set; }          // 含 PostgreSQL
    // —— 分字段连接参数（dbconfig 引导录入，内部拼接连接字符串）——
    public string Host { get; set; } = "";
    public int Port { get; set; }
    public string User { get; set; } = "";
    public string Database { get; set; } = "";
    public string DbFilePath { get; set; } = "";      // SQLite 专用
    public bool Enabled { get; set; } = true;
    public string FullCron { get; set; } = "";        // 定时全量 cron；空=禁用
    public string IncrementalCron { get; set; } = ""; // 定时增量 cron；SQLite 强制忽略
    public int MaxBackupCount { get; set; } = 20;
    public string CredentialRef { get; set; } = "";   // 密码凭据引用
    public DateTime? LastFullAt { get; set; }
    public DateTime? LastIncrementalAt { get; set; }
    public string LastBinlogPos { get; set; } = "";   // MySQL binlog 位置 / PG LSN
    public string? FullSnapshotNodeId { get; set; }   // 最近全量快照节点（增量前置校验）
}
```

### 4.3 其它关键类

```csharp
// 轻量 cron 解析器：支持 5 段（分 时 日 月 周），* / , - 语法 + 快捷预设
public sealed class CronExpression
{
    public static CronExpression Parse(string expr);
    public bool IsDue(DateTime now, DateTime? lastRun);  // 命中当前分钟且当日未跑
    public static string FromPreset(CronPreset preset);  // 快捷周期 → cron
}
public enum CronPreset { Disabled, Daily, Weekly, Every2Hours, Every6Hours, Every12Hours }

// 任务防重入锁：TaskKey → 锁，TryEnter/Exit
public sealed class BackupReentryLock
{
    public bool TryEnter(string taskKey);
    public void Exit(string taskKey);
    public bool IsRunning(string taskKey);
}

// 授权门禁
public static class LicenseGuard
{
    public static bool IsActivated { get; }
    public static bool IsBackupEnabled();  // 未授权：加密备份/定时/实时/数据库 全禁用
}

// HKDF 派生 + 零化
public static class KeyDerivation
{
    public static byte[] DeriveKey(string password, byte[] salt, int keySize = 32); // HKDF-SHA256
    public static byte[] NewSalt(int size = 16);
    public static void ZeroMemory(byte[] key);
}
```

---

## 5. 数据流与交互

### 5.1 定时调度数据流

```
[BackupCronScheduler: Timer 每分钟]
   │ LicenseGuard.IsBackupEnabled() == false ──→ 跳过（日志）
   ├─ FileBackupJobs：命中 fullCron / incrementalCron
   │     │ ReentryLock.TryEnter(job.Name) 失败 ──→ 跳过（防重入）
   │     ├─ 全量 → BackupExecutor → SnapshotChainManager.AddSnapshot(Full) → Cleanup
   │     └─ 增量 → BlockIncrementalService(USN→块差分→增量包) → AddSnapshot(Incremental) → Cleanup
   └─ DbBackupInstances：命中 fullCron / incrementalCron（SQLite 增量拦截）
         │ ReentryLock.TryEnter("db:" + inst.Name) 失败 ──→ 跳过
         ├─ 全量 → DatabaseBackupEngine.BackupDatabase → 更新 FullSnapshotNodeId
         └─ 增量 → 校验 FullSnapshotNodeId 非空，否则告警跳过
                 → DbIncrementalBackupEngine(binlog/WAL 流式) → 更新 LastBinlogPos
```

### 5.2 实时监控数据流

```
[FileSystemWatcher 事件]
   → 防抖窗口合并 → ReentryLock.TryEnter(job.Name)
   → BlockIncrementalService（USN 或变更清单）→ AddSnapshot(Realtime)
   → 实时增量计数 ≥ MaxRealtimeBeforeMerge → MergeSnapshots（截断链）
```

### 5.3 密码生命周期

```
dbconfig / UI 输入密码（控制台不回显）
   → 生成实例盐 → HKDF(password, salt) → AES-256 密钥（内存，不落盘）
   → 用该密钥加密备份集 → 配置仅存 salt + credentialRef
   → 任务结束 → KeyDerivation.ZeroMemory(key) → 清空内存
```

---

## 6. 边界与禁止事项（约束）

1. **SQLite 强制禁用增量**：`DbIncrementalBackupEngine.IsIncrementalSupported(SQLite) == false`，调度与手动入口双重拦截。
2. **数据库不做文件系统实时监控备份**：实时监控仅适用于文件任务（`FileBackupJob`），数据库仅定时抓取事务日志。
3. **数据库增量前置校验**：无最近全量快照 → 告警并跳过（不自动补全量，避免隐藏执行成本）。
4. **禁止直接拷贝运行中数据库物理文件**：MySQL 全量走 mysqldump、PG 全量走 pg_dump、增量走 binlog/WAL 日志。
5. **不落地明文临时备份文件**：binlog 流式走内存；PG WAL 段仅驻留 ACL 隔离临时目录，加密后立即删除。
6. **不改动原有可用业务代码**：全部新增文件/类；仅 `Program.cs` 加参数分支、`DatabaseType` 加枚举、`DatabaseBackupEngine` 加 PG 分支（均为纯增量）。
7. **防重入**：运行中定时触发跳过，绝不并发执行同一任务。
8. **授权联动**：未授权状态即使配置开启也不执行（调度/实时/手动入口统一走 `LicenseGuard`）。

---

## 7. 非目标（本迭代不做）

- 数据库离线物理备份（VSS 级）— 已有 VSS 引擎覆盖文件系统，数据库仍走逻辑备份。
- 数据库实时监控（禁止项，见 §6.2）。
- SqlServer 增量（LOG 备份）— 需求未列，保留现有 TransactionLog 全量内能力。
- 完整 Cron 6/7 段语法（含秒、年）— 本迭代 5 段足够。
- 分布式集群数据库（主从自动切换）— 单实例即可。

---

## 8. 交付物

1. 全部新增/修改源码（git commit，diff 见提交记录）。
2. 新增结构体定义（§4，见代码注释与本文档）。
3. JSON 配置样例（§3.2）。
4. 自检清单：`checklist.md` 逐条核对功能总表。
5. 任务分解：`tasks.md`（P0 文件块级增量+定时 → P1 数据库定时调度接入全局 cron → P2 dbconfig 引导配置）。
