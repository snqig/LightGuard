# LightGuard v1.0.0

> 超低资源 + 现代 Win11 UI + 全自动勒索防护 + 加密伪装防勒索备份 + 多开源病毒库自动更新 + 系统隐私加固 + 流氓软件一键净化

## 功能特性

### 六大核心模块

| 模块 | 功能 |
|------|------|
| 系统隐私加固 | 一键关闭遥测、广告、后台应用、搜索联网，家用/办公双模板 |
| 流氓软件净化 | WPS/360/Edge/2345 全套净化，全局防捆绑+Hosts广告屏蔽 |
| 防火墙管理 | 入站/出站规则管理，智能拦截偷流量，Defender智能兼容 |
| 勒索病毒防护 | 多源病毒库聚合，双引擎扫描，VSS卷影副本秒还原 |
| 加密智能备份 | AES256加密，.sys伪装备份防勒索，NTFS增量，NAS/WebDAV |
| 自动更新 | 三层更新：软件本体+杀毒引擎+病毒库规则库 |

### 产品特点

- 单 EXE 绿色免安装，自包含 .NET 8 运行时
- 双模式自适应 UI（高配 Mica 云母 / 低配极简）
- 智能后台调度：游戏全屏/低电量/前台操作自动暂停
- 首次运行引导，小白零门槛
- 所有优化支持一键还原

## 系统要求

- Windows 10 1903+ / Windows 11
- 管理员权限

## 技术栈

- C# .NET 8 WinForms
- P/Invoke (DWM/Mica, VSS, 防火墙, 注册表)
- 自定义 Fluent UI 渲染引擎

## 项目结构

```
src/LightGuard/
├── Core/           # 核心框架（模块系统、硬件检测、配置、调度）
├── Native/         # Win32 API 封装（注册表、防火墙、Hosts、服务）
├── Modules/        # 六大功能模块
├── UI/             # 界面（主窗口、8页面、控件、主题、引导）
├── Program.cs      # 入口
└── LightGuard.csproj
```

## 构建

```powershell
dotnet publish src/LightGuard/LightGuard.csproj -c Release -r win-x64 --self-contained true -o ./publish
```

## License

MIT
