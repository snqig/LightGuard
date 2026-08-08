# LightGuard 终版架构差异核对报告

> 核对日期：2026-08-07
> 依据：《LightGuard 完整项目终版文档》（含架构、权限原理、开发任务、迭代路线、安全红线）
> 版本策略：保持 v3.x 递增；文档中 v0.1-v0.7 仅作内部阶段代号

---

## 一、格式层（最大差异，P0 核心）

| 文档要求 | 当前代码库现状 | 结论 |
|---|---|---|
| 双层封装：自研混淆外壳 + 7z LZMA2 内核 | `Backup/LgBackupFormat.cs` 仅 AES-256-GCM/ChaCha20 分片加密，**无任何压缩、无混淆层** | ❌ 全新 v3 格式 |
| 7z 高压缩内核 | 全库无 LZMA/7z/压缩引用 | ❌ 需引入 7z 内核 |
| 文件名加密 | 清单 JSON 明文存相对路径，选择性还原/浏览全依赖明文路径 | ❌ 影响恢复端全链路 |
| 旧版 v1/v2 只读兼容 | 仅存在 v1（`CurrentVersion=1`），**代码库中不存在 v2 格式** | ⚠️ 文档假设与现状不符 |

> **关键冲突**：当前 v1（AES 分片）即"旧格式"。新 7z 格式落地后，现有 AES 分片格式需保留读路径（只读兼容），并需定迁移/导出策略。当前 v3.3.0 用户的所有备份包将自动降级为"旧格式"。

## 二、权限层（文档今日核心重点）

| 文档要求 | 当前代码库现状 | 结论 |
|---|---|---|
| 普通权限 UI 双击启动 | `app.manifest` 声明 `requireAdministrator`，**每次启动必弹 UAC** | ❌ 核心痛点未解决 |
| 高危操作隔离 Worker 子进程 | 单进程架构，UI 与底层操作同进程 | ❌ 全新架构 |
| 计划任务免 UAC 提权 | 无（`Native/ServiceHelper.cs` 的 schtasks 仅用于系统清理，非自我提权） | ❌ 未实现 |
| System 服务终版（P2） | 无 `ServiceBase` 服务 | ❌ 未实现 |
| 安全红线合规 | 现用 `runas` 合法提权，无绕过/杀软干扰 | ✅ 符合红线 |

## 三、备份引擎能力盘点

| 文档能力 | 现状 | 结论 |
|---|---|---|
| USN 变更追踪 | `Backup/IncrementalDifferentialEngine.cs` USN 优先 + 哈希回退 | ✅ 已实现 |
| 增量/差异备份 | 文件级（整文件哈希/USN） | 🟡 部分（非块级） |
| **块级增量** | 仅固定分片切分，无块级去重 | ❌ 未实现 |
| VSS 卷影副本 | `Backup/VssShadowCopyEngine.cs` | ✅ 已实现 |
| WORM 不可变 | `Backup/BackupPermissionLock.cs` 三层 ACL 防删 + `RansomwareProofBackupPool` | 🟡 文件级 ACL 锁（非真 WORM），基本可用 |
| VHD 虚拟挂载 | 无 | ❌ 未实现 |
| 断点续备 / 健康校验 / 快照链 / 智能过滤 / 节流 / 数据库备份 / 选择性还原 | 全部已实现（v3.0~v3.3 交付） | ✅ |

## 四、恢复与容灾

| 文档能力 | 现状 | 结论 |
|---|---|---|
| 三种模式/远程/预览/版本回溯 | 已实现 | ✅ |
| 分区克隆 / 系统迁移 / 引导修复 / PE 救援 / 裸机恢复 | 无 | ❌ P2 |
| 备份链合并 / 全量合成 / 3-2-1 多副本复制 | 无 | ❌ P2 |

## 五、运维与告警

| 文档能力 | 现状 | 结论 |
|---|---|---|
| 钉钉/企微/邮件告警 | 全库无任何告警通道引用 | ❌ P1 |
| SMB/NAS 断线重连、任务自愈重试、防假成功 | 支持 UNC + 节流，无重试队列/自愈 | ❌ P1 |
| 前置/后置脚本、空间预警、介质绑定 | 无 | ❌ P1 |
| 定时备份调度 | 仅生命周期清理 Timer（24h），**无备份调度** | ❌ P1 |
| 托盘后台 / 任务队列 | 无托盘模式 | ❌ P1 |
| 日志审计报告 | `BackupAuditReporter` + 审计系统 + CSV | ✅ 部分 |

## 六、UI/UX

- ✅ 仪表盘（DashboardPage）、新手向导（OnboardingForm）、多语言（LangHelper 三语）、自动更新（增量差分）
- 🟡 备份浏览器已有（v3.3.0 交付），但**无版本时间轴、无文件内容预览**
- ❌ 配置导入导出、可视化排除规则（现为文本规则）

## 七、全局规范符合性（文档第 7 节）

| 规范 | 现状 | 结论 |
|---|---|---|
| 1. 所有读写经 IBackupArchive | 接口不存在 | ❌ P0 首项 |
| 2. 敏感密码 AES 加密存储 | `Core/ConfigManager.cs` 无任何加密存储逻辑 | ❌ 待建（当前是否存凭证需核查） |
| 3-6. 提权红线/纯用户态/旧格式只读 | 符合 | ✅ |
| 7. 取消/不卡死/可追溯 | 恢复支持取消，备份部分异步 | 🟡 需补全局 |

## 八、P0 实施定序建议（依赖关系驱动）

1. **IBackupArchive 统一抽象层** — 先立接口，全部读写收口（无依赖，先行）
2. **v3 双层格式**（7z 内核 + 私有外壳 + 文件名加密）— 核心，依赖 1
3. **旧格式 v1 只读兼容** — 与 2 并行（保留现有 AES 分片读路径）
4. **权限重构**（去 `requireAdministrator` → Worker 子进程 + 计划任务）— 独立可并行，是体验最大收益点
5. **块级增量** — 依赖 2 的新格式
6. **VHD 挂载** — 依赖 4（挂载需管理员，走 Worker）

## 九、两点专业建议（涉及安全红线与合规）

1. **混淆 ≠ 强加密**：建议私有混淆仅作"抗识别/抗扫描层"，数据安全仍由标准 AEAD（XChaCha20-Poly1305 等）保证，否则违反"纯用户态合法合规"初衷且抗勒索强度不足。
2. **格式不兼容升级建议**：v3 双层格式属破坏性变更。保持 v3.x 前提下，建议至少落在明确大版本（如 v3.4 作为新格式首版，旧包自动只读），并在发布说明中声明"旧包只读、不自动迁移"。

---

## 附：P0 进展记录

### P0-1（2026-08-07）
- 差异核对报告保存；`IBackupArchive` 接口设计完成（`src/LightGuard/Backup/IBackupArchive.cs`）；7z 内核选型调研完成。
- **7z 内核选型结论**：采用纯托管 LZMA 编码器作为压缩内核（无需原生 dll，单文件发布兼容、无杀软误报风险）：
  - 实测 `Faithlife.Lzma` 19.0.0 与 `LZMA-SDK` 22.1.1 编译产物均**仅含 LZMA1**（`SevenZip.Compression.LZMA.Encoder`），无 LZMA2 类；NuGet 上亦无纯托管 LZMA2 包（Aspose.Zip 商业、FastLZMA2Net/ManagedXZ 原生依赖）。
  - 落地：采用 **LZMA-SDK 22.1.1**（官方 7-Zip SDK 纯托管移植，公有领域）实现 LZMA 内核；容器头记录 `Codec` 字段，后续 Chunked 块级增量阶段可升级 LZMA2 而不破坏格式。
  - 不推荐：SevenZipSharp / 7z.Libs（原生 7z.dll 依赖）、外部 7za.exe（破坏单文件便携性）。
  - 自研容器内嵌原始 LZMA 流而非 .7z 归档，第三方压缩软件（7z/WinRAR/好压）无法识别，满足"私有格式不可开"目标。

### P0-2（2026-08-07）
- **`V3PrivateContainerArchive` 落地**（`src/LightGuard/Backup/V3PrivateContainerArchive.cs` + `BackupArchiveFactory.cs`）：
  - 双层架构：外层私有容器（魔数 `LGBK3\x01` + AES-256-GCM AEAD 外壳），内层 7-Zip LZMA 压缩内核。
  - 布局：`[魔数][版本][盐][算法][头负载长][nonce][tag][加密头][条目数据区]`；条目记录含相对偏移（顺序读取）与解压后 SHA256。
  - 头部整体 AEAD 加密（含路径），满足文件名加密要求；密钥 PBKDF2 派生、随机盐、永不落盘。
  - 操作：WriteAsync（全量）/ AppendAsync（增量合并重建，同名覆盖）/ ListEntriesAsync / OpenEntryAsync / VerifyAsync，全异步 + 可取消 + 进度。
  - `BackupArchiveFactory` 统一入口：DetectFormat（魔数嗅探）/ Create / Open；v1 旧格式只读适配器留待 P0-3。
  - 新增往返测试 15 项（写/读/校验/追加/错误口令/密文篡改检出/魔数识别），全套 57 项用例通过；Debug/Release 编译 0 错误。

### P0-3（2026-08-07）— 旧格式 v1 只读兼容
- **`V1LegacyArchiveAdapter`**（`src/LightGuard/Backup/V1LegacyArchiveAdapter.cs`）：以 `IBackupArchive` 暴露旧 AES 分片包——仅 List / Open / Verify，Write/Append 抛 NotSupportedException（规范 5：旧格式仅只读）。
- 复用 v1 读取管线（PBKDF2 派生 → 逐分片解密 + 分片级 SHA256 → 整包 SHA256 → 解析归档条目）；逐文件哈希来自清单 FileHashes（JSON）。
- `BackupArchiveFactory.Open` 已按魔数路由 v1 → 适配器；`DetectFormat` 修复 9 字节魔数读取（v1 魔数 9B）。
- 新增 9 项测试（识别/清单/读取哈希/整包校验/只读拒绝/错误口令），全套 66 项通过。

### P0-4（2026-08-07）— 权限重构方案A（Worker 子进程 + 免 UAC 提权）
- **`Core/PrivilegedWorker.cs`**：
  - `RunAsync(spec)`：管理员 → 内联执行；非管理员 → 首选计划任务通道（`schtasks /run`，免 UAC），回退标准 runas（合法 UAC，无绕过）。
  - `TryHandleWorkerMode(args)`：无界面工作进程调度（`--worker <spec.json>` / `--worker-pending`），请求/结果经 `%TEMP%\LightGuard\` JSON 传递，执行后即删。
  - `EnsureElevationTaskRegistration()`：以管理员身份运行（安装/首次）时注册 `LightGuardElevation` 最高权限计划任务（`/rl highest`）。
  - 首个工作操作：`VssBackup`（VssShadowCopyEngine 无界面备份）。
- **Program.cs**：工作进程模式在管理员检查与 UI 初始化之前拦截；管理员启动时自动注册提权任务。
- **BackupPage**：VSS 备份按钮非管理员时自动经 Worker 提权执行（免 UAC / UAC 弹窗一次），管理员内联不变。
- **Chunked 块级模式**（块级增量基础）：容器新增 `Chunked` 压缩模式——按 ChunkSize 分块、每块独立 LZMA 流 + 独立 AEAD，条目记录块引用表（Off/CLen/Len/Hash），支持跨包块去重索引基础；`Solid` 模式明确拒绝（NotSupportedException）。PerFile 保持默认。
- 新增测试 9 项（Worker 协议/结果回传/任务查询不抛异常 + Chunked 往返/校验 + Solid 拒绝），**全套 74 项通过**；Debug/Release 编译 0 错误。

### P0-5（2026-08-08）— 块级增量引擎（USN 变更 → 块级差分）
- **`Backup/BlockIncrementalEngine.cs`**（纯数据层，无 IO 依赖）：
  - `BlockChunkIndex`：块 SHA256 → 长度 索引，支持 `MergeFrom`（Chunked 元数据回退构建）。
  - `BuildIndex` / `BuildIndexFromChunks`：从文件数据或压缩块元数据构建索引。
  - `ComputeDelta(newData, baseData, baseIndex, chunkSize)`：固定块切分（默认 256KB）→ 逐块差分。
    - **差分语义修正（重要）**：复用判定基于「同偏移块」逐字节一致（文件级差分），而非全局哈希命中——修复插入/追加相同内容块时按偏移重建越界或取错内容的缺陷；`baseIndex` 仅作存在性加速（哈希不在索引中直接判新增）。
  - `Apply(baseData, delta)`：复用块按偏移取基准数据、新块拼接，重建最新内容；复用块缺基准抛 `InvalidDataException`。
- **`Backup/BlockIncrementalService.cs`**（服务层编排 + USN 门面）：
  - `CreateIncrementalAsync`：打开基础包（Chunked 元数据构建索引）→ 逐文件读基准数据做同偏移差分 → 新块拼接 + 块映射（`.lgblockmap` JSON）写入增量包（PerFile 模式）。
  - `CreateIncrementalFromDirectoryAsync`（USN 驱动高层入口）：USN 日志检测变更（`UsnChangeDetector`）→ 无基准/非盘符/USN 不可用回退全量枚举 → 读取变更文件 → 块级差分 → 增量包；头部写 `Strategy=BlockIncremental` / `UsnStart` / `UsnEnd` / `SourcePath` 元数据。
  - `RebuildFileAsync`：读块映射 → 复用块取自基础包同偏移、新块取自增量包 → 逐块重建；未变更文件直接来自基础包。
  - `TryReadUsnEnd`：从 v3 包头读 USN 游标，供下次增量续跑（口令错误/无元数据 → -1）。
  - `UsnChangeDetector`：直接使用 `UsnJournalScanner`（无 AppState 副作用）；USN 记录仅含文件名 → 按名匹配源目录文件；删除记录跳过；无匹配回退全量枚举保安全。
- **v3 容器头部新增 `Metadata`**（`V3Header.Metadata` + `Create(..., metadata)` + `Open` 读取 + `BuildHeaderJson` 写入），向后兼容（旧包缺失为 null）；`BackupArchiveFactory.Create` 透传。
- **新增独立测试项目 `tests/BlockIncrementalTest`（35 项）**：数据层（索引/全复用/部分变更/Apply 往返/空基准/缺基准抛错）+ 服务层（基础包 Chunked + 增量包 PerFile 往返重建一致性、无基准全新增、未变更文件来自基础包、基础/增量包健康校验）+ USN 游标元数据读写。**全套 74 + 35 = 109 项通过**；Debug/Release 编译 0 错误。

### P0-6（2026-08-08）— 增量链合并与版本点恢复（时间快照链）
- **`Backup/IncrementalChainService.cs`**（新建）：
  - 链模型：基础包（全量，Chunked）= 版本 0，其后每个增量包 = 版本点 1..N；每增量包相对基础包同偏移差分，复用块始终引用基础包，链上任意版本点语义一致。
  - `LoadChainAsync`：读取增量包头 Metadata（BackupTime/UsnEnd）→ 按备份时间升序排序 + 版本编号（1..N）；口令错误抛明确异常。
  - `RestoreToVersionAsync(base, deltas, dir, versionIndex)`：版本 0..N 任意点恢复——基础包全量 + 顺序应用链上前 N 个增量包的块级重建（后包覆盖同名），输出目录重建结构。
  - `RestoreToTimeAsync(..., targetTime)`：命中最后一个 备份时间 ≤ target 的版本点（链首前 → 版本 0）。
  - `MergeToFullAsync(base, deltas, mergedPath)`：恢复链尾最新版本 → 写 Chunked 新全量包（Metadata: Strategy=Full / MergedFrom / MergedDeltaCount / UsnEnd），可继续作为下一轮增量基准。
- **`BlockIncrementalService` 重构**：`RebuildFileAsync` 拆出 `ReadBlockMapAsync` + `RebuildFileCore`（基础包+增量包已打开场景批量复用）；`CreateIncrementalFromDirectoryAsync` 增量包头补写 `BackupTime`。
- **新增链测试 30 项**（`tests/BlockIncrementalTest/ChainTests.cs`）：乱序链加载排序/版本编号、版本 0/1/2 三点恢复内容逐文件校验、时间点命中（区间内/链尾后/链首前）、链合并为新全量（内容=最新版本、健康校验通过、可续增量重建一致）、越界版本抛异常。**全套 74 + 35 + 30 = 139 项通过**；Debug/Release 编译 0 错误。

### P0-7（2026-08-08）— VHD 虚拟磁盘挂载（裸机恢复 / 卷访问）
- **`Backup/VhdMountManager.cs`**（新建，virtdisk.dll P/Invoke）：
  - `CreateVirtualDisk(path, sizeMb, fixedSize, overwrite)`：创建 VHD（V1 参数：UniqueId/MaximumSize/扇区 512，固定=FullPhysicalAllocation / 动态增长）。
  - `Attach(vhdPath, readOnly, assignDriveLetter)`：Open → AttachVirtualDisk（只读默认 `ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY`，防写宿主盘）→ `GetVirtualDiskPhysicalPath` 解析物理盘号 → 遍历 `FindFirstVolume/FindNextVolume` + `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS` 按磁盘号精确识别本 VHD 卷 → 为无盘符卷 `SetVolumeMountPoint` 分配空闲盘符（D-Z 扫描）。
  - `Detach(vhdPath)`：回收本 VHD 卷盘符（`DeleteVolumeMountPoint`）→ DetachVirtualDisk；未挂载/文件缺失幂等安全。
  - `ListAttachedPhysicalDisks()`：枚举 \\.\PhysicalDrive0..31 已挂载盘。
  - 错误处理：Win32 错误码 → 中文 IOException（文件不存在/权限不足/参数无效/通用 Win32Exception）。
- **`Core/PrivilegedWorker.cs` 集成**：`WorkerSpec` 新增 `ReadOnly`；调度器新增 `VhdAttach` / `VhdDetach` 操作——非管理员自动经计划任务/runas 提权执行，管理员内联；结果回传挂载盘符。
- **测试**：`SelectiveRecoveryTest` 新增 VHD 用例（Worker 缺参/挂载不存在文件 → 结构化失败）；管理员环境执行 创建→只读挂载→物理盘识别→卸载 往返 + 幂等 Detach。当前非管理员环境真实往返标记 WARN 跳过（生产经 Worker 提权）。**全套 74 + 4 = 78 项通过**；Debug/Release 编译 0 错误。

### P0-8（2026-08-08）— WORM 集成 v3 备份（抗勒索只读隔离池）
- **`Backup/WormManager.cs`**（新建，WORM = Write Once Read Many）：
  - 备份包写入完成后自动施加 `BackupPermissionLock` 三层防删除锁（NTFS ACL 拒绝 Everyone 写入/追加/删除/改属性 + 只读/隐藏属性 + .lockfile 标记），形成抗勒索只读隔离备份池。
  - `AutoLock` 容错：文件不存在 / 锁定失败不抛出（仅日志），不阻断备份主流程；`IsLocked` / `GetStatus` / `VerifyIntegrity` 状态门面。
  - 开关：`AppConfig.Backup.WormAutoLock`（默认开启）；`AutoLockDisabled` 进程级临时关闭（测试/调试，不改配置）。
- **三层自动锁定集成点**：
  - `BackupExecutor`：数据/流式两条写包路径（WriteBackup + VerifyBackup 通过后 `WormManager.AutoLock(outputPath)`）——覆盖全量/分区/整盘/数据库备份。
  - `BlockIncrementalService.CreateIncrementalAsync`：增量包写入完成后自动锁定。
  - `IncrementalChainService.MergeToFullAsync`：链合并包写入完成后自动锁定。
- **生命周期联动**：`BackupLifecycle.DeleteIfNotLocked` 删除前自动 `WormManager.Unlock`（否则 ACL 拒绝删除）；`SetLock` 改写清单前同样解锁。
- **关键缺陷修复**：`BackupPermissionLock.DeniedRights` 原含 `Modify`（隐含 ReadData），Deny 优先级导致连 SYSTEM/管理员都无法读取锁定备份（浏览/校验/恢复/清单读取全被拒）→ 改为仅拒绝 Write/AppendData/Delete/WriteAttributes/WriteExtendedAttributes；锁定 ACL 额外 Allow 当前用户 Read，保证 LightGuard 普通权限进程可读回自己的备份。
- **测试**：`SelectiveRecoveryTest` 新增 WORM 用例 11 项（禁用容错 / 启用锁定 / 三层齐全 / 完整性 / 锁定后仍可读 / 解锁可删 / 生命周期清理自动解锁后删除）。**全套 65 + 89 = 154 项通过**；Debug/Release 编译 0 错误。

### P0-9（2026-08-08）— 权限方案 A 收尾（asInvoker + 非管理员灰化）
- **`app.manifest`**：`requestedExecutionLevel` 由 `requireAdministrator` 切换为 **`asInvoker`**——UI 以普通权限启动，不再强制 UAC 弹窗重启。
- **`Program.cs`**：移除"非管理员强制重启为管理员"逻辑；管理员启动时调用 `PrivilegedWorker.EnsureElevationTaskRegistered()` 注册免 UAC 提权计划任务（尽力而为，供后续 Worker 使用）。
- **`Core/PermissionPolicy.cs`**（新建）：静态权限映射表（功能 Key → 是否需要管理员），`RequiresAdmin` 未知功能保守返回 true；`CanAccess = IsAdmin || !RequiresAdmin`。仪表盘/加密备份/自动更新/云端更新/设置 普通权限可访问；隐私加固/流氓净化/防火墙/网络隔离/勒索防护/勒索解密/Defender查杀/文件审计/分区备份/整盘备份/数据库备份 需管理员。
- **`UI/Controls/CustomControls.cs`**：`SidebarButton` 新增 `Disabled` 属性——禁用时不响应悬停/点击；`OnPaint` 禁用态渲染灰底（`Theme.DisabledBg`）+ 全灰文字 + 文字后缀 `🔒`。
- **`UI/Theme.cs`**：补 `DisabledBg`（Dark `#282828` / Light `#E6E6E6`）+ 便捷访问属性。
- **`UI/MainForm.cs`**：导航按钮循环内按 `PermissionPolicy.CanAccess(key)` 设置 `btn.Disabled`——非管理员下高危功能导航灰化且不可进入。
- **测试**：**全套 65 + 89 = 154 项通过**；Release 编译 0 错误（仅既有 8 警告）。

### P0-10（2026-08-08）— 安装器权限优化 + 目录 ACL 配置（P0 收尾）
- **运行时（C#）**：
  - `Core/PrivilegedWorker.cs`：新增 `UnregisterElevationTask()`——注销免 UAC 提权计划任务（`schtasks /delete`，任务不存在时幂等返回 true，保证卸载无残留）。
  - `Core/DirectoryAclConfigurator.cs`（新建）：服务器版数据目录 `%ProgramData%\LightGuard` ACL 兜底配置——为 Users 组授予 Modify（继承子目录与文件，幂等：已配置则跳过），解决 asInvoker 普通权限 UI 无法读取安装器创建的共享数据目录问题（审计日志/病毒库/配置）。仅管理员生效，非服务器环境静默跳过。
  - `Program.cs`：新增安装器生命周期命令 `--register-elevation-task` / `--unregister-elevation-task`（MSI CustomAction 调用，无界面执行后退出）；`DistributionProfile.DetectFromEnvironment()` 后调用 `DirectoryAclConfigurator.ApplyAll()` 兜底。
- **安装器（packaging/build-msi.ps1 生成 .wxs）**：
  - **计划任务生命周期**：`RegisterElevTask` / `UnregisterElevTask` 两个 CustomAction 直接调用 `LightGuard.exe` 专用命令行（避免 schtasks 引号拼接），以 msiexec 提升身份执行（`Impersonate=no`，`Return=ignore` 不阻塞安装）；`InstallExecuteSequence` 绑定——安装/升级注册（`Condition="NOT REMOVE~="ALL""`），卸载注销（`Condition="REMOVE~="ALL""`，Before=RemoveFiles）。
  - **服务器版数据目录**：`CommonAppDataFolder\LightGuard` 目录组件（CreateFolder + `<Permission>`：SYSTEM/Admins GenericAll、Users 读写执行删除；卸载 RemoveFolder 清理空目录）。
  - **WiX v4 语法适配**：`<Custom>` 条件用 `Condition` 属性（inner text / `When` 属性均报错）；`<Permission>` 必须嵌套于 `<CreateFolder>` 内（不可作为 Component 直接子元素）。
  - **编码修复**：build-msi.ps1 重写后丢失 UTF-8 BOM，PowerShell 5.1 按 ANSI 解析中文出错 → 恢复 UTF-8 BOM（与 packaging 其余脚本一致）。
- **验证**：客户端版 + 服务器版 `build-msi.ps1` 完整打包成功（WiX 7.0.0 编译 0 错误）；**全套 65 + 92 = 157 项测试通过**（新增 ACL 用例 3 项）；Release 编译 0 错误。

### P0 全部完成（后续 P1 批次规划见前文）

### P1-1（2026-08-08）— 双版本分发完善（差分更新形态区分）
- **`Core/DistributionProfile.cs`**：新增 `DeploymentMode`（Installed / Portable）与 `Mode` / `IsPortable`——检测顺序：环境变量 `LIGHTGUARD_PORTABLE=1` → 应用目录 `portable.mode` 标记 → 应用目录不在 Program Files 下视为便携。`DetectFromEnvironment()` 开头先检测部署形态（与 server 检测互不冲突）。
- **`Update/IncrementalUpdateModels.cs`**：`IncrementalUpdateManifest` 新增 `Edition` 字段（client / server / universal）——Server 版（仅英文语言包）与 Client 版（三语）文件集不同，差分包必须区分，防装错。
- **`Update/IncrementalUpdateService.cs`**：`CheckAsync` 新增 `currentEdition` 参数并做适用形态校验（新增公共静态 `IsEditionCompatible`：空/universal 兼容，否则须一致、大小写不敏感）；不匹配返回明确错误。
- **`Modules/UpdateModule.cs`**：
  - `CheckIncrementalUpdateAsync`：便携版（单文件）不支持文件级差分 → 返回明确提示走全量更新链路；安装版按当前形态（client/server）传递 edition 校验。
  - `ApplyIncrementalUpdate`：权限方案A 联动——MSI 版安装在 Program Files、非管理员且安装目录不可写时，自动经 `PrivilegedWorker` 提权应用（免 UAC 计划任务 / runas 回退）。
- **`Core/PrivilegedWorker.cs`**：`WorkerSpec` 新增 `JsonData` 通用负载；调度器新增 `ApplyIncrementalUpdate` op（Source=差分包，Dest=应用目录，JsonData=清单 JSON），结果回传替换/删除数与备份路径。
- **packaging**：
  - `build-update-manifest.ps1`：新增 `-Edition`（client/server/universal）参数，清单写入 `edition` 字段。
  - `build-portable.ps1`：打包时写入 `portable.mode` 标记（运行时据此识别便携部署）。
- **验证**：便携版打包成功且产物含 `portable.mode`；`build-update-manifest.ps1 -Edition server` 生成的清单含 `"edition":"server"`；**全套 65 + 104 = 169 项测试通过**（新增双版本分发用例 12 项）；Release 编译 0 错误。

### P1-2（2026-08-08）— SMB 审计改进（持久化 + 风险告警）
- **`Core/AlertNotifier.cs`**（新建）+ **`AppConfig.Alert`**（`AlertConfig`）：风险事件告警通知——本地日志始终记录；钉钉/企微群机器人 Webhook 按配置外发（`Enabled` / `DingTalkWebhook` / `WeComWebhook` / `AlertOnCriticalOnly` / `TitlePrefix`），失败静默不影响主流程。补齐差异报告 P1「钉钉/企微告警通道」。
- **`Audit/SmbRiskStore.cs`**（新建）：风险事件持久化——JSON Lines 按天分片 `risk_{yyyyMMdd}.jsonl`，`StoreAsync` / `QueryRecentAsync`（跨分片取最新 N 条）/ `Purge`（保留天数清理）。
- **`Modules/SmbAuditModule.cs`** 接入持久化与告警：
  - 审计记录持久化：`AuditLogStorage`（DataDir/smb_audit/records）——采集记录映射为 `SmbAuditEvent` 异步落盘（fire-and-forget，失败不阻断采集）；新增 `QueryHistoricalRecords(filter)` 跨重启历史查询。
  - 风险事件持久化 + 告警：`SmbRiskDetector.RiskDetected` → `SmbRiskStore.StoreAsync` + `AlertNotifier.NotifyAsync`（批量外泄/权限篡改/高频删除/凌晨访问/备份目录异常即时告警）；新增 `GetPersistentRiskHistory(count)`。
  - 保留策略：启动时 + 每日定时 `Purge`（默认 90 天，与 `SmbDeployConfig.LogRetentionDays` 一致）；新增 `PurgeRetentionNow()`。
- **验证**：**全套 65 + 112 = 177 项测试通过**（新增 SMB 审计改进用例 8 项：审计记录持久化往返/按用户筛选、风险事件持久化往返含关联记录、过期分片清理、AlertNotifier 静默容错）；Release 编译 0 错误。

### P1-3（2026-08-08）— 云端规则更新（事件联动 + 双重校验 + 热重载）
- **`Ransomware/YaraEngine.cs`**：新增 `public int ReloadOnlineRules()` 热重载方法——先移除 `Source == "在线更新"` 的旧规则，再重新加载 `DataDir/yararules/online_rules.json`（含签名校验），返回本次加载的在线条数，供云端更新应用后立即生效。
- **`Core/CloudUpdate/CloudUpdateClient.cs`** 增强：
  - 新增 `public event Action<RuleType, string, string>? RuleApplied`（参数：规则类型 / 应用后文件路径 / RSA 签名），应用成功后在原子替换后触发，供模块联动（P1-3 核心联动缺口：`cloudupdate/` 下载目录与 `yararules/` 加载目录不同步）。
  - `CheckUpdateAsync` 新增 **minClientVersion 校验**（新增公共静态 `IsClientVersionSupported`：清单未声明或当前 >= 最低要求则支持，v 前缀兼容），不满足返回"客户端版本过旧…请先升级"明确错误。
  - `DownloadAndApplyAsync` 新增 **SizeBytes 文件大小校验**（SHA256 通过后、RSA 签名前），防截断/防半包，不匹配即删除临时文件并返回明确错误。
- **`Modules/CloudUpdateModule.cs`**：订阅 `Client.RuleApplied` → `OnRuleApplied` 联动——仅 YARA 勒索规则需要即时生效：同步 `online_rules.json` + `online_rules.sig` 到 `yararules/` 目录，再经 `EtwYaraModule.GetDefenseEngine()?.GetYaraEngine()` 调用 `ReloadOnlineRules()` 热重载；防御引擎未运行时记录"下次启动生效"。`OnReleaseResources` 反订阅。
- **`packaging/publish-rules.ps1`**（新建，发布端）：复制规则文件到 `dist/rules/files/{RuleType}/{fileName}` → 计算 SHA256 + SizeBytes → RSA-2048 签名（可选私钥）→ 合并生成 `manifest/{Channel}.json`（对齐 `UpdateManifest`：serverTime / latestVersions[ruleType,version,publishedAt,downloadUrl,sha256,rsaSignature,sizeBytes,changelog] / minClientVersion）。已补 UTF-8 BOM；修复 PowerShell 5.1 不支持的 `Join-Path` 三参数写法（嵌套调用）。实测：生成清单经 SHA256/SizeBytes 与文件一致性校验通过，格式可被客户端 case-insensitive 解析。
- **验证**：**全套 65 + 134 = 199 项测试通过**（新增云端规则更新用例 22 项：minClientVersion 拦截/支持判定、语义化版本比较、SHA256 匹配/不匹配、RSA 有效签名/篡改拒绝、本地 HTTP 服务器端到端清单拉取与 SHA256/SizeBytes 双校验拒绝、YaraEngine 热重载加载/幂等不累积/移除回落）；Release 编译 0 警告 0 错误。

### 缺陷修复（2026-08-08）— Adobe 全家桶封锁后 EXE 打不开（ACL 拒绝执行）
- **根因**：`Firewall/AclPermissionHelper.SetExeReadonlyAcl`（Adobe 封锁模板 `ApplyAdobeBlock` 调用）对 Adobe 目录全部 EXE 拒绝 `Everyone: Write | Modify | Delete`；而 .NET `FileSystemRights.Modify = Read | Write | ExecuteFile | Delete`，**拒绝 Modify 即拒绝 ExecuteFile/Traverse** → Adobe 相关 EXE 无法启动。
- **修复**：拒绝权限改为 `Write | Delete`（保留 Read/ExecuteFile）——EXE 仍被只读锁定（防更新替换/防卸载），但可正常启动；`LockConfigFile` 同步修复。已锁定用户执行防火墙「一键还原模板」（`RevertPreset` → `BatchRestoreFolderExeAcl`）即恢复默认权限。
- **验证**：新增 EXE ACL 回归用例 6 项（锁定成功 / 不拒绝 ExecuteFile / 不拒绝 ReadData / 锁定后可读 / 恢复成功 / 恢复后 Deny 移除），非管理员环境容错跳过。

### P1-4（2026-08-08）— UI DPI 适配（PerMonitorV2 + 整体缩放）
- **`app.manifest`**：声明 `<dpiAware>true/pm</dpiAware>` + `<dpiAwareness>PerMonitorV2</dpiAwareness>`（配合 Program.cs `SetHighDpiMode`；指定 ApplicationManifest 时 SDK 不自动注入，需手动声明并 `NoWarn WFAC010`）。此前仅调 `SetHighDpiMode` 而无 manifest 声明 → 实际不生效，高分屏 UI 模糊。
- **`UI/MainForm.cs`**：新增 `AdaptToDpi()`（构造中、布局记忆恢复前调用）——`DeviceDpi > 96` 时窗口物理尺寸（Size/MinimumSize）× 缩放系数，并对子控件整体 `Scale(SizeF)`（标题栏/侧边栏导航/各页面内部成比例放大，无重叠/截断）；`PositionTitleBarButtons` 改用实际按钮宽度排布（避免缩放后固定 46px 导致重叠）。
- **`UI/Theme.cs`**：新增 `DpiFont(Font, Control)`——按控件 `DeviceDpi` 放大手绘字体（96 DPI 时原样返回不创建新实例）。
- **`UI/Controls/CustomControls.cs`**：`SidebarButton` / `AccentButton` 的 `OnPaint` 手绘文字改用 `Theme.DpiFont`（高分屏文字不偏小）。
- **验证**：构建产物 exe 内嵌 manifest 确认含 `dpiAwareness=PerMonitorV2` + `asInvoker`；新增 manifest 回归用例 4 项（PerMonitorV2 / dpiAware / asInvoker 不回归 / longPathAware）；**全套 65 + 145 = 210 项测试通过**；Release 编译 0 错误（WFAC010 已抑制，仅剩既有 CS0169 字段未使用警告）。

### P1-5（2026-08-08）— Defender 全业务集成（持久化 + 调度 + 告警 + 处置）
- **`Core/AppConfig.DefenderConfig`**（新建）：全业务策略持久化——每日定时扫描开关/时间（HH:mm）/类型（QuickScan/FullScan）、扫描优先级、威胁处置动作（Quarantine/Remove/Allow/None）、病毒库自动更新 + 过期天数阈值、威胁 Webhook 告警开关、实时保护异常告警开关。
- **`Defender/DefenderScanStore.cs`**（新建）：扫描历史与威胁清单持久化——`DataDir/defender/defender_data.json`，原子写（tmp+Move），RawOutput 截断 2000 字符，上限与内存一致（历史 200 / 威胁 1000），`Save` / `Load` / `Clear` 幂等容错。
- **`Modules/DefenderScanModule.cs`** 增强：
  - 历史持久化：`OnInitializeAsync` 加载磁盘数据（重启不丢），`RecordScan` / `UpdateThreatAction`（新增，事后处置回写）同步落盘，`ClearHistory` 同步清理，`Dispose`/`OnReleaseResources` 保存。
  - 每日调度（新增 `System.Threading.Timer`，每分钟 tick）：① 到达 `ScanTime` 且当日未执行 → 自动快速/全盘扫描（防重入），结果入库；② 病毒库过期（`IsSignatureOutdated`）→ 自动 `UpdateSignaturesAsync`（每日检查一次）；③ 实时保护被关闭 / 引擎健康异常 → Webhook 告警（每日限流）。
  - 威胁告警（P1-5 联动 AlertNotifier）：扫描发现威胁 → 钉钉/企微 Webhook 外发（高/严重级 → Critical，其余 High），受 `AlertOnThreat` 控制。
  - `GetStatusSummary` 增强：病毒库版本 + 更新时间（天前）+ 定时扫描状态。
  - 新增静态判定（可测试）：`IsScheduledTimeDue(scanTime, now, lastRunDate)`、`IsSignatureOutdated(status, maxAgeDays)`。
- **`UI/Pages/DefenderScanPage.cs`** 增强：
  - 策略页：优先级/处置动作改动即持久化到 `AppConfig.Defender`；新增「每日调度与保护监控」配置卡（定时扫描开关/时间/类型、病毒库自动更新/过期天数、威胁告警/保护异常告警开关，全部落盘）。
  - 历史页：新增「威胁清单（跨重启保留）」区——展示累计威胁（名称/路径/等级/处置/时间），支持事后处置：隔离所选（AES 加密移入隔离区）/ 删除所选 / 允许所选（回写 `UpdateThreatAction`）+ 「恢复隔离区」入口。
- **`UI/QuarantineManageDialog.cs`**（新建）：隔离区管理弹窗——`ListQuarantinedFiles` 展示（文件名/原始路径/隔离时间/原因），恢复所选（`RestoreFile`）/ 删除所选（`DeleteQuarantined`）。补齐差异报告「隔离区无管理页面」缺口。
- **验证**：新增 Defender 集成用例 23 项（持久化往返含 RawOutput 截断、清空重载为空、定时时刻判定 5 例、病毒库过期判定 5 例、DefenderConfig 序列化往返、AppConfig 默认值）；**全套 65 + 168 = 233 项测试通过**；Release 编译 0 错误。

### P1-5 补充（2026-08-08）— DefenderScanPage 策略配置 UI 显示一致性修复
- **问题**（核对 AppConfig.Defender 与 UI 绑定发现的 3 处显示不一致）：
  1. 扫描时间下拉框：配置值不在预设列表（如自定义 05:00）时被错误回退显示 02:30，与实际配置不符。
  2. 处置动作下拉框：缺少 `ThreatAction.None` 选项，配置为"不处置（仅告警）"时界面仍显示"隔离"，误导用户。
  3. 过期天数下拉框：用 switch 固定索引映射，非预设值（如 5）错误显示"3 天"。
- **修复**（`UI/Pages/DefenderScanPage.cs`）：
  1. `_scanTimeCombo` 初始化后若 `Items` 不含配置值则动态 `Add` 并选中（不再错误回退）。
  2. `_remediationCombo` 增加"不处置（仅告警）"选项映射 `ThreatAction.None`，选中事件按索引回写 `ThreatAction.None`。
  3. `_sigMaxAgeCombo` 动态加入 `"{值} 天"` 并选中，回写逻辑同步。
- **验证**：DefenderUiProbe 宿主注入边界值（ScanTime=05:00、ThreatAction=None、SignatureMaxAgeDays=5）实测下拉框：扫描时间 `Selected="05:00"`、处置动作 `Selected="不处置（仅告警）"`、过期天数 `Selected="5 天"`，且各 Items 均含动态加入项，三项全部通过。
