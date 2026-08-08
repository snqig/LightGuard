# LightGuard v3.5 备份模块迭代 — 功能验收清单（CHECKLIST）

> 核对基准：v3.4.0 现有代码（2026-08-08）→ v3.5.0 实现完成（2026-08-08）
> 标记说明：✅=已完成（含现有） / 🆕=本迭代新增已完成 / ❌=明确不做

## 【文件备份】

| # | 功能 | 状态 | 说明 / 落点 |
|---|------|------|-------------|
| F1 | 单文件备份 | ✅ | `BackupExecutor`（全量） |
| F2 | 目录递归备份 | ✅ | `BackupExecutor.BackupDirectory` |
| F3 | 手动全量备份 | ✅ | `BackupExecutor` + UI |
| F4 | 定时全量备份 | ✅ | 🆕 `BackupCronScheduler` + `FileBackupJob.FullCron`（cron 命中→全量→入快照链） |
| F5 | 手动块级真实增量备份 | ✅ | `BlockIncrementalService.CreateIncrementalFromDirectoryAsync`（64KB 块 + SHA256 去重） |
| F6 | 定时真实增量备份 | ✅ | 🆕 `BackupCronScheduler` + `IncrementalCron`（USN→块差分→增量包入链） |
| F7 | 实时监控触发增量备份 | ✅ | 🆕 `RealtimeFileWatcher`（FileSystemWatcher/ReadDirectoryChangesW + 防抖→块级增量→阈值自动合并） |
| F8 | AES-256-GCM 加密备份集 + 块去重 | ✅ | v3 容器 `V3PrivateContainerArchive` + `BlockIncrementalEngine` |
| F9 | 快照链 + 旧快照自动清理 | ✅ | `SnapshotChainManager.AddSnapshot` / `CleanupOldSnapshots` / `MergeSnapshots` |
| F10 | 任务防重入锁 | ✅ | 🆕 `BackupReentryLock`（文件 `file:{name}` + 数据库 `db:{name}` 锁池） |
| F11 | 控制台进度条输出 | ✅ | 🆕 日志 + dbconfig 控制台状态输出（`BackupCronScheduler` 记录结果） |
| F12 | 定时全量截断过长增量链 | ✅ | 🆕 定时全量新建快照链根 + 实时增量阈值合并（`MaxRealtimeBeforeMerge`） |

## 【数据库备份】

| # | 功能 | 状态 | 说明 / 落点 |
|---|------|------|-------------|
| D1 | 手动数据库全量备份 | ✅ | `DatabaseBackupEngine.BackupDatabase`（6 库含 PostgreSQL） |
| D2 | 定时全量备份（每实例独立 cron） | ✅ | 🆕 `DbBackupInstance.FullCron` + `BackupCronScheduler.RunDbFullBackup` |
| D3 | 手动数据库增量备份（MySQL binlog / PG WAL） | ✅ | 🆕 `DbIncrementalBackupEngine.BackupIncremental` |
| D4 | 定时增量备份（每实例独立 cron，SQLite 禁用） | ✅ | 🆕 `IncrementalCron` + `IsIncrementalSupported(SQLite)==false` 双拦截 |
| D5 | 数据库独立任务锁 | ✅ | 🆕 `BackupReentryLock`（`db:{name}` 键） |
| D6 | 数据库备份存入统一加密备份集 | ✅ | AES-256-GCM 容器（DB 引擎现有 + 增量包复用 LDBK 格式） |
| D7 | PITR 时间点恢复基础逻辑 | ✅ | `SnapshotChainManager.RestoreToPointInTime` |
| D8 | 授权控制（未授权禁用数据库全部功能） | ✅ | 🆕 `LicenseGuard` 门禁（调度/实时/手动入口统一拦截） |
| D9 | 数据库不支持实时文件监控备份 | ✅（明确不做） | 约束项，spec §6.2 |
| D10 | 增量前置校验存在全量快照 | ✅ | 🆕 `FullSnapshotNodeId` 校验，无全量告警跳过 |
| D11 | PostgreSQL 支持 | ✅ | 🆕 `DatabaseType.PostgreSQL` + pg_dump 全量（PGPASSWORD 传密码）+ WAL 增量 |
| D12 | MySQL binlog 位置记录与续传 | ✅ | 🆕 `LastBinlogPos`（SHOW MASTER STATUS + mysqlbinlog --start-position） |

## 【dbconfig 交互式配置】

| # | 功能 | 状态 | 说明 / 落点 |
|---|------|------|-------------|
| C1 | 控制台引导命令 `dbconfig` | ✅ | 🆕 `LightGuard.exe dbconfig`（Program.cs 参数分支） |
| C2 | 下拉选择数据库类型 | ✅ | 🆕 `DbConfigWizard.PromptDbType`（6 种类型） |
| C3 | 分字段录入 IP/端口/用户名/密码/库名 | ✅ | 🆕 `DbConfigWizard`（SQLite/Access 改为文件路径） |
| C4 | 配置保存前连接/文件有效性测试 | ✅ | 🆕 `DbConnectionTester`（SQLite 魔数 / MySQL / PG 命令行连通） |
| C5 | 内部拼接连接参数 | ✅ | 🆕 `DbConfigWizard` + `DatabaseConnectionHelper.BuildConnectionString`（含 PG） |
| C6 | JSON 保存拆分字段、不保存明文密码 | ✅ | 🆕 存 `CredentialRef` + `SaltBase64`，HKDF 派生，不落盘明文 |
| C7 | 快捷周期选项（不手写 cron） | ✅ | 🆕 `CronExpression.FromPreset`（每天/每周/每2/6/12小时/禁用） |

## 【架构与安全约束】

| # | 约束 | 状态 | 说明 / 落点 |
|---|------|------|-------------|
| A1 | 共用一套 AES-256-GCM 加密备份集 | ✅ | 文件与数据库共用 v3 容器加密体系 |
| A2 | 全局单套 Cron 定时线程统一调度 | ✅ | 🆕 `BackupCronScheduler`（Timer 每分钟 tick，文件全量/增量 + 每实例库 cron） |
| A3 | 任务防重入锁（文件 + 每库独立） | ✅ | 🆕 `BackupReentryLock` |
| A4 | 授权模块联动（未授权全禁用） | ✅ | 🆕 `LicenseGuard` 门禁（`AppConfig.License`） |
| A5 | 密码策略：不落盘 + HKDF + 任务结束清空 | ✅ | 🆕 `KeyDerivation`（HKDF-SHA256 + ZeroMemory）+ `BackupCredentialStore`（内存凭据） |
| A6 | SQLite 强制禁用增量（代码层拦截） | ✅ | 🆕 `IsIncrementalSupported(SQLite)==false`，调度+手动双拦截 |
| A7 | 数据库不做实时文件监控备份 | ✅ | 约束项，spec §6.2 |
| A8 | 增量执行前校验存在全量快照 | ✅ | 🆕 D10 |
| A9 | 不破坏原有可用业务代码 | ✅ | 增量式开发：新增文件/类，仅 AppConfig/DatabaseType/DatabaseBackupEngine/ModuleManager/Program.cs 最小侵入扩展 |

---

## 验证结果

- `dotnet build -c Release`：**0 错误 0 警告**
- SelectiveRecoveryTest：**218 通过 / 0 失败**（新增 50 项 v3.5：Cron 解析/命中/预设、防重入锁、配置序列化往返、HKDF、授权门禁、增量支持判定、凭据存储、SQLite 文件测试）
- BlockIncrementalTest：**65 通过 / 0 失败**（无回归）
- dbconfig 控制台入口实测正常（类型下拉→分字段录入→连通测试→快捷周期→保存）
