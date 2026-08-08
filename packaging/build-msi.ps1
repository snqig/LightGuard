# ============================================================
# LightGuard MSI 安装版打包脚本（P1-1 双版本分发架构 - A版）
#
# 特性：
#   - 企业/服务器主力版本，长期部署首选
#   - 目录部署（非 single-file），无临时文件释放，降低杀毒误报概率
#   - 默认 framework-dependent（Core≈15MB）；-SelfContained 免运行时
#   - 支持修复 / 卸载 / 无残留（WiX 标准卸载 + 清理空目录）
#   - 组件 GUID 由文件相对路径确定性派生，支持增量差分更新
#   - 可选组件：服务器版自动剔除 zh-CN/zh-TW 语言包
#
# 依赖：WiX Toolset 7（dotnet tool install --global wix）
#
# 用法：
#   .\build-msi.ps1                     # 客户端 MSI（framework-dependent）
#   .\build-msi.ps1 -Edition Server     # 服务器精简版
#   .\build-msi.ps1 -SelfContained      # 自包含版（免运行时，体积较大）
# ============================================================
param(
    [ValidateSet('Client', 'Server')][string]$Edition = 'Client',
    [ValidateSet('win-x64', 'win-x86', 'win-arm64')][string]$Rid = 'win-x64',
    [switch]$SelfContained,
    [string]$OutputDir = ''
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$csproj = Join-Path $root 'src\LightGuard\LightGuard.csproj'
$common = Join-Path $PSScriptRoot 'packaging-common.ps1'
. $common

$version = Get-VersionFromCsproj $csproj
$numVersion = Get-NormalizedVersion $version

if ([string]::IsNullOrEmpty($OutputDir)) {
    $OutputDir = Join-Path $root 'dist'
}
$staging = Join-Path $root 'build\msi-staging'
$wixSrc = Join-Path $PSScriptRoot 'wix\LightGuard.wxs'
$msiName = "LightGuard-msi-${numVersion}-${Rid}.msi"
$msiPath = Join-Path $OutputDir $msiName

# 确定性 GUID：由字符串生成标准 v5 GUID
function New-DeterministicGuid([string]$seed) {
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $bytes = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($seed))
    $bytes[6] = (($bytes[6] -band 0x0F) -bor 0x30)  # version 3-like
    $bytes[8] = (($bytes[8] -band 0x3F) -bor 0x80)  # RFC 4122 variant
    return [guid]::new($bytes).ToString('B').ToUpperInvariant()
}

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " LightGuard MSI 安装版打包 v${numVersion} [$Edition / ${Rid}]" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan

# ---- 0. 检查 wix ----
$wixCmd = Get-Command wix -ErrorAction SilentlyContinue
if ($wixCmd -eq $null) {
    throw "未找到 wix 命令，请先执行: dotnet tool install --global wix"
}
Write-Host "WiX Toolset: $(& wix --version)"

# 接受 WiX v7 OSMF EULA（首次使用需要）
& wix eula accept wix7 2>$null | Out-Null

# ---- 1. 发布（目录部署，非 single-file） ----
Clear-Directory $staging
New-Item -ItemType Directory -Path $staging -Force | Out-Null

$publishArgs = @(
    'publish', $csproj,
    '-c', 'Release',
    '-r', $Rid,
    '-o', $staging,
    '-p:PublishSingleFile=false'
)
if ($SelfContained) {
    $publishArgs += @('-p:SelfContained=true', '-p:EnableCompressionInSingleFile=false')
}
else {
    $publishArgs += @('-p:SelfContained=false')
}

Write-Host "`n[1/5] dotnet publish (directory deploy) ..."
& dotnet $publishArgs --nologo -v q
if ($LASTEXITCODE -ne 0) { throw "dotnet publish 失败，退出码 $LASTEXITCODE" }

# ---- 2. 精简资源 ----
Write-Host "`n[2/5] 精简外部资源 (Edition=$Edition) ..."
Apply-EditionTrim -StagingDir $staging -Edition $Edition

# ---- 3. 生成 WiX 源文件 ----
Write-Host "`n[3/5] 生成 WiX 源 ($wixSrc) ..."

# 收集文件（相对 INSTALLFOLDER 的路径）
$files = Get-ChildItem $staging -Recurse -File | Sort-Object FullName

# 固定 UpgradeCode（跨版本不变，基于产品名）
$upgradeCode = New-DeterministicGuid 'LightGuard-Enterprise-UpgradeCode'
$productGuid = New-DeterministicGuid "LightGuard-MSI-$version-$Edition-$Rid"

$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine('<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">')
[void]$sb.AppendLine('  <Package')
[void]$sb.AppendLine("    Name=""LightGuard ${numVersion}""")
[void]$sb.AppendLine("    Manufacturer=""落尘(Luochen)""")
[void]$sb.AppendLine("    Version=""${numVersion}""")
[void]$sb.AppendLine("    UpgradeCode=""${upgradeCode}""")
[void]$sb.AppendLine('    Language="1028"')
[void]$sb.AppendLine('    Scope="perMachine"')
[void]$sb.AppendLine('    Compressed="yes">')
[void]$sb.AppendLine('    <SummaryInformation')
[void]$sb.AppendLine('      Description="LightGuard 全栈安全容灾审计系统 - 企业/服务器主力版本"')
[void]$sb.AppendLine('      Manufacturer="落尘(Luochen)" />')
[void]$sb.AppendLine('    <MajorUpgrade DowngradeErrorMessage="检测到更高版本，请先卸载当前版本。" />')
[void]$sb.AppendLine('    <MediaTemplate EmbedCab="yes" CompressionLevel="high" />')
[void]$sb.AppendLine('    <StandardDirectory Id="ProgramFiles64Folder">')
[void]$sb.AppendLine('      <Directory Id="INSTALLFOLDER" Name="LightGuard" />')
[void]$sb.AppendLine('    </StandardDirectory>')
[void]$sb.AppendLine('    <StandardDirectory Id="ProgramMenuFolder">')
[void]$sb.AppendLine('      <Directory Id="ProgramMenuDir" Name="LightGuard" />')
[void]$sb.AppendLine('    </StandardDirectory>')
# P0-10 服务器版：系统级共享数据目录 %ProgramData%\LightGuard（安装时创建 + ACL 配置）
if ($Edition -eq 'Server') {
    [void]$sb.AppendLine('    <StandardDirectory Id="CommonAppDataFolder">')
    [void]$sb.AppendLine('      <Directory Id="DATA_FOLDER" Name="LightGuard" />')
    [void]$sb.AppendLine('    </StandardDirectory>')
}

# 生成组件组
[void]$sb.AppendLine('    <ComponentGroup Id="ProductComponents" Directory="INSTALLFOLDER">')

# 主 EXE 组件（关键路径）
$exeRel = 'LightGuard.exe'
$exeComponentId = 'CMP_EXE'
$exeGuid = New-DeterministicGuid ('file-' + $exeRel)
[void]$sb.AppendLine("      <Component Id=""${exeComponentId}"" Guid=""${exeGuid}"" KeyPath=""yes"">")
[void]$sb.AppendLine('        <File Source="' + (Join-Path $staging $exeRel).Replace('\\','\') + '" />')
[void]$sb.AppendLine('      </Component>')

# 其余文件
foreach ($f in $files) {
    $rel = $f.FullName.Substring($staging.Length).TrimStart('\', '/')
    if ($rel -ieq $exeRel) { continue }
    $componentId = 'CMP_' + ($rel -replace '[^a-zA-Z0-9]', '_')
    # 组件 GUID 由相对路径派生（升级/修复稳定）
    $fileGuid = New-DeterministicGuid ('file-' + $rel)
    [void]$sb.AppendLine("      <Component Id=""${componentId}"" Guid=""${fileGuid}"" Directory=""INSTALLFOLDER"">")
    [void]$sb.AppendLine("        <File Source=""$(Join-Path $staging $rel)"" KeyPath=""yes"" />")
    [void]$sb.AppendLine('      </Component>')
}
[void]$sb.AppendLine('    </ComponentGroup>')

# 快捷方式组件（开始菜单）
[void]$sb.AppendLine('    <Component Id="CMP_StartMenuShortcut" Directory="ProgramMenuDir" Guid="' + (New-DeterministicGuid 'shortcut-startmenu') + '">')
[void]$sb.AppendLine('      <Shortcut Id="SHORTCUT_LG" Name="LightGuard" Description="LightGuard 全栈安全容灾审计系统" Target="[INSTALLFOLDER]LightGuard.exe" WorkingDirectory="INSTALLFOLDER" />')
[void]$sb.AppendLine('      <RemoveFolder Id="RemoveProgramMenuDir" On="uninstall" />')
[void]$sb.AppendLine('      <RegistryValue Root="HKCU" Key="Software\LightGuard" Name="installed" Type="integer" Value="1" KeyPath="yes" />')
[void]$sb.AppendLine('    </Component>')

# 卸载后清理空目录（无残留）
[void]$sb.AppendLine('    <Component Id="CMP_RemoveInstallFolder" Directory="INSTALLFOLDER" Guid="' + (New-DeterministicGuid 'remove-installfolder') + '">')
[void]$sb.AppendLine('      <RemoveFolder Id="RemoveInstallFolder" On="uninstall" />')
[void]$sb.AppendLine('      <RegistryValue Root="HKLM" Key="Software\LightGuard" Name="installed" Type="integer" Value="1" KeyPath="yes" />')
[void]$sb.AppendLine('    </Component>')

# P0-10 服务器版：数据目录组件（创建目录 + ACL：SYSTEM/Admins 完全控制、Users 读写执行）
if ($Edition -eq 'Server') {
    $dataFolderGuid = New-DeterministicGuid 'data-folder-ProgramData-LightGuard'
    [void]$sb.AppendLine("    <Component Id=""CMP_DataFolder"" Directory=""DATA_FOLDER"" Guid=""${dataFolderGuid}"">")
    [void]$sb.AppendLine('      <CreateFolder>')
    [void]$sb.AppendLine('        <Permission User="SYSTEM" GenericAll="yes" />')
    [void]$sb.AppendLine('        <Permission User="Administrators" GenericAll="yes" />')
    [void]$sb.AppendLine('        <Permission User="Users" GenericRead="yes" GenericWrite="yes" GenericExecute="yes" Delete="yes" />')
    [void]$sb.AppendLine('      </CreateFolder>')
    [void]$sb.AppendLine('      <RemoveFolder Id="RemoveDataFolder" On="uninstall" />')
    [void]$sb.AppendLine('    </Component>')
}

[void]$sb.AppendLine('    <Feature Id="MainFeature" Title="LightGuard" Description="LightGuard 核心程序与资源" Level="1">')
[void]$sb.AppendLine('      <ComponentGroupRef Id="ProductComponents" />')
[void]$sb.AppendLine('      <ComponentRef Id="CMP_StartMenuShortcut" />')
[void]$sb.AppendLine('      <ComponentRef Id="CMP_RemoveInstallFolder" />')
if ($Edition -eq 'Server') {
    [void]$sb.AppendLine('      <ComponentRef Id="CMP_DataFolder" />')
}
[void]$sb.AppendLine('    </Feature>')

# P0-10 安装器权限优化：计划任务生命周期（安装/升级注册免 UAC 提权任务；卸载注销，无残留）
# CustomAction 直接调用 LightGuard.exe 的专用命令行模式（避免 schtasks 引号拼接），
# 以 msiexec 提升身份（Impersonate=no）执行；Return=ignore 保证失败不阻塞安装/卸载。
[void]$sb.AppendLine('    <CustomAction Id="RegisterElevTask" Directory="INSTALLFOLDER"')
[void]$sb.AppendLine('      ExeCommand="&quot;[INSTALLFOLDER]LightGuard.exe&quot; --register-elevation-task"')
[void]$sb.AppendLine('      Execute="immediate" Impersonate="no" Return="ignore" />')
[void]$sb.AppendLine('    <CustomAction Id="UnregisterElevTask" Directory="INSTALLFOLDER"')
[void]$sb.AppendLine('      ExeCommand="&quot;[INSTALLFOLDER]LightGuard.exe&quot; --unregister-elevation-task"')
[void]$sb.AppendLine('      Execute="immediate" Impersonate="no" Return="ignore" />')
[void]$sb.AppendLine('    <InstallExecuteSequence>')
[void]$sb.AppendLine('      <Custom Action="RegisterElevTask" After="InstallFiles" Condition="NOT REMOVE~=&quot;ALL&quot;" />')
[void]$sb.AppendLine('      <Custom Action="UnregisterElevTask" Before="RemoveFiles" Condition="REMOVE~=&quot;ALL&quot;" />')
[void]$sb.AppendLine('    </InstallExecuteSequence>')
[void]$sb.AppendLine('  </Package>')
[void]$sb.AppendLine('</Wix>')

Set-Content -Path $wixSrc -Value $sb.ToString() -Encoding UTF8

# ---- 4. wix build（先输出到 staging 内，避免 dist 残留导致 8.3 短名问题） ----
Write-Host "`n[4/5] wix build -> $msiName ..."
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$buildOut = Join-Path $root 'build\msi-output'
Clear-Directory $buildOut
New-Item -ItemType Directory -Path $buildOut -Force | Out-Null

$archArg = switch ($Rid) {
    'win-x64'   { 'x64' }
    'win-x86'   { 'x86' }
    'win-arm64' { 'arm64' }
}
$tmpMsi = Join-Path $buildOut 'LightGuard.msi'
& wix build $wixSrc -o $tmpMsi -arch $archArg -pdbtype none
if ($LASTEXITCODE -ne 0) { throw "wix build 失败，退出码 $LASTEXITCODE" }

# wix 可能因 NTFS 8.3 短名缓存生成 LIGHTG~N.MSI，用通配符定位实际产物
$actualMsi = Get-ChildItem $buildOut -Filter '*.msi' -ErrorAction SilentlyContinue |
    Where-Object { $_.Length -gt 0 } | Select-Object -First 1
if ($actualMsi -eq $null) { throw "wix build 后未找到 MSI 产物" }

# 移动到最终位置（PowerShell 5.1 / .NET Framework 无 overwrite 重载）
$msiPath = Join-Path $OutputDir $msiName
if (Test-Path $msiPath) { Remove-Item $msiPath -Force }
[System.IO.File]::Move($actualMsi.FullName, $msiPath)

# ---- 5. 输出结果 ----
Write-Host "`n[5/5] 打包完成" -ForegroundColor Green
Write-Host "  MSI: $msiPath ($(Get-FileSizeMB $msiPath) MB)"
Write-Host "  安装目录文件数: $($files.Count)"
Write-Host "  暂存目录大小: $(Get-DirectorySizeMB $staging) MB"
