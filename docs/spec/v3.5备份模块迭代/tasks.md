# LightGuard v3.5 备份模块迭代 — 任务分解（TASKS）

> 开发顺序按用户指定：P0 文件块级增量+定时 → P1 数据库定时调度接入全局 cron → P2 dbconfig 引导配置
> 约束：全部新增文件/类，最小侵入式扩展；每个 P 完成后跑 `dotnet build` + 测试套件验证无回归
> 状态：**全部完成**（2026-08-08；build 0 错误 0 警告；测试 218 + 65 = 283 通过；dbconfig 实测正常）

---

## P0 — 文件块级增量 + 定时（优先级最高）

### P0-1 全局 Cron 调度基础设施
- **新增** `src/LightGuard/Backup/CronExpression.cs`
  - 5 段 cron（分 时 日 月 周）解析：`*`、`*/n`、`a,b`、`a-b`、`a-b/n`
  - `IsDue(DateTime now, DateTime? lastRun)`：命中当前分钟且当日该任务未跑过
  - `FromPreset(CronPreset)`：快捷周期（每天/每周/每2/6/12小时）→ cron 字符串
- **新增** `src/LightGuard/Backup/BackupReentryLock.cs`
  - `TryEnter(taskKey)` / `Exit(taskKey)` / `IsRunning(taskKey)`，线程安全（ConcurrentDictionary + Interlocked）

### P0-2 文件备份任务模型与配置
- **新增** `src/LightGuard/Backup/FileBackupJob.cs`
  - `FileBackupJob`（源路径/单文件/目录/定时 cron/实时监控开关/防抖窗口/快照链目录/保留策略/口令引用）
  - `SnapshotRetention`
- **修改** `src/LightGuard/Core/AppConfig.cs`
  - 新增 `List<FileBackupJob> FileBackupJobs { get; set; }`（JSON 反序列化，默认空）
  - 新增 `LicenseGuard` 相关配置节（授权状态）

### P0-3 授权门禁
- **新增** `src/LightGuard/Core/LicenseGuard.cs`
  - 静态门禁 `IsBackupEnabled()`；从配置读取授权状态
  - 未授权：`BackupCronScheduler` 不调度、`RealtimeFileWatcher` 不启动、dbconfig 不允许保存启用型配置

### P0-4 文件定时调度器
- **新增** `src/LightGuard/Backup/BackupCronScheduler.cs`
  - `System.Threading.Timer` 每分钟 tick；遍历 `FileBackupJobs` + `DbBackupInstances`
  - 文件侧：命中 `FullCron` → 全量 `BackupExecutor`；命中 `IncrementalCron` → `BlockIncrementalService.CreateIncrementalFromDirectoryAsync`（USN→块差分→增量包）
  - 完成后 `SnapshotChainManager.AddSnapshot` + `CleanupOldSnapshots`
  - 防重入：`BackupReentryLock`；授权：`LicenseGuard`；启动/停止挂到模块生命周期

### P0-5 实时监控增量
- **新增** `src/LightGuard/Backup/RealtimeFileWatcher.cs`
  - `FileSystemWatcher`（ReadDirectoryChangesW 封装）监控源目录；单文件任务监控父目录 + 文件名过滤
  - 防抖窗口（`WatchDebounceMs` 默认 3000ms）合并事件 → 触发块级增量快照
  - 实时增量计数 ≥ `MaxRealtimeBeforeMerge`（默认 12）→ `MergeSnapshots` 截断增量链

### P0-6 控制台进度输出 + 验证
- **新增** 控制台进度条辅助（复用 `BackupProgress` 事件 → 控制台重绘）
- **测试**：CronExpression 解析/命中/快捷预设、BackupReentryLock 并发、FileBackupJob 序列化往返、定时调度命中判定（新增用例并入 SelectiveRecoveryTest）
- **验证**：`dotnet build -c Release` 0 错误；测试全套通过

---

## P1 — 数据库定时调度接入全局 cron（含 PostgreSQL + 事务日志增量）

### P1-1 数据库实例配置模型
- **新增** `src/LightGuard/Database/DbBackupInstance.cs`
  - 分字段（Host/Port/User/Database/DbFilePath）+ `FullCron`/`IncrementalCron` + `CredentialRef` + `LastBinlogPos` + `FullSnapshotNodeId`
- **修改** `src/LightGuard/Core/AppConfig.cs`
  - 新增 `List<DbBackupInstance> DbBackupInstances { get; set; }`（JSON 节，等价需求"DB_BACKUP 段"）

### P1-2 PostgreSQL 支持（全量）
- **修改** `src/LightGuard/Database/DatabaseBackupEngine.cs`（最小侵入）
  - `DatabaseType` 枚举新增 `PostgreSQL`
  - 备份分支：`pg_dump`（逻辑全量，流式读 stdout 加密）；还原分支：`psql` 导入
  - 文件后缀 `.postgres`、连接参数解析（PG 连接串格式）

### P1-3 数据库增量备份引擎
- **新增** `src/LightGuard/Database/DbIncrementalBackupEngine.cs`
  - MySQL：`SHOW MASTER STATUS` 取 binlog 位置 → `mysqlbinlog --read-from-remote-server --start-position=<pos>` 流式输出 → 内存流 → AES-256-GCM 加密写备份集；更新 `LastBinlogPos`
  - PostgreSQL：基于 `LastLsn` 用 pg_receivewal 采集 WAL 段（ACL 隔离临时目录）→ 逐段流式读入加密管线 → 立即删明文
  - `IsIncrementalSupported(dbType)`：SQLite → false（代码层拦截）
  - 增量前置校验：`FullSnapshotNodeId` 为空 → 告警跳过（不自动补全量）

### P1-4 数据库定时调度接入全局 cron
- **修改** `src/LightGuard/Backup/BackupCronScheduler.cs`
  - 数据库侧：命中 `FullCron` → `DatabaseBackupEngine.BackupDatabase`；命中 `IncrementalCron` → `DbIncrementalBackupEngine`（SQLite 跳过）
  - 每实例独立防重入锁（`db:{name}`）
  - 完成后更新 `LastFullAt` / `LastBinlogPos` / `FullSnapshotNodeId`，触发 `CleanupOldBackups`
- **验证**：`dotnet build` 0 错误；新增用例（增量支持判定、前置校验、位置续传、PG 枚举序列化）

---

## P2 — dbconfig 交互式引导配置（含密码策略）

### P2-1 连接连通性测试
- **新增** `src/LightGuard/Database/DbConnectionTester.cs`
  - MySQL/PG：TCP 连接 + 认证测试（不暴露密码明文）
  - SQLite：文件存在性 + 文件头魔数校验（"SQLite format 3"）

### P2-2 dbconfig 引导向导
- **新增** `src/LightGuard/Database/DbConfigWizard.cs`
  - 控制台交互：类型下拉 → 分字段录入（IP/端口/用户/密码/库名；SQLite 为文件路径）→ 内部拼接连接参数 → 连通性测试 → 快捷周期选择（不手写 cron）→ 保存
  - 密码经 HKDF 派生（`KeyDerivation`），仅存盐 + `CredentialRef`，不落盘明文；任务结束 ZeroMemory
- **修改** `src/LightGuard/Program.cs`（最小侵入）
  - 新增参数分支：`args.Contains("dbconfig")` → 运行 `DbConfigWizard` 后 return（参考现有 `--register-elevation-task` 模式）

### P2-3 密码派生工具
- **新增** `src/LightGuard/Backup/KeyDerivation.cs`
  - `DeriveKey(password, salt)`：HKDF-SHA256 → AES-256 密钥
  - `NewSalt()` / `ZeroMemory()`

### P2-4 集成验证
- 验证链路：dbconfig 录入 → 配置落盘（分字段 + 盐 + 引用，无明文）→ 定时调度读取 → 全量/增量执行
- 全套测试通过；git commit（diff 见提交记录）
