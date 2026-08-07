# ============================================================
# LightGuard 打包公共函数（P1-1 双版本分发架构）
# 被 build-portable.ps1 / build-msi.ps1 共用
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-LightGuardVersion {
    param([string]$CsprojPath)
    [xml]$xml = Get-Content $CsprojPath
    $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
    $ns.AddNamespace('msb', 'http://schemas.microsoft.com/developer/msbuild/2003')
    $node = $xml.SelectSingleNode("//msb:Project/msb:PropertyGroup/msb:Version", $ns)
    if ($node -eq $null) { $node = $xml.SelectSingleNode("//Version", $ns) }
    if ($node -ne $null) { return $node.InnerText.Trim() }
    return '1.0.0'
}

# 读取 csproj 中 Version 属性（兼容无命名空间或带命名空间的 csproj）
function Get-VersionFromCsproj {
    param([string]$CsprojPath)
    $content = Get-Content $CsprojPath -Raw
    if ($content -match '<Version>([^<]+)</Version>') { return $Matches[1].Trim() }
    return '1.0.0'
}

# 规范化版本：移除 v 前缀
function Get-NormalizedVersion {
    param([string]$Version)
    return $Version -replace '^v', ''
}

# 获取项目根目录
function Get-ProjectRoot {
    return (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
}

# 计算目录大小（MB）
function Get-DirectorySizeMB {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return 0 }
    $bytes = (Get-ChildItem $Path -Recurse -File | Measure-Object -Property Length -Sum).Sum
    return [math]::Round($bytes / 1MB, 2)
}

# 计算单文件大小（MB）
function Get-FileSizeMB {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return 0 }
    return [math]::Round((Get-Item $Path).Length / 1MB, 2)
}

# 清理目录
function Clear-Directory {
    param([string]$Path)
    if (Test-Path $Path) { Remove-Item $Path -Recurse -Force -ErrorAction SilentlyContinue }
}

# 服务器版精简：仅保留英文语言包，写入 server.mode 标记
# 客户端版：保留三套语言包
function Apply-EditionTrim {
    param(
        [string]$StagingDir,
        [ValidateSet('Client', 'Server')][string]$Edition
    )
    $langDir = Join-Path $StagingDir 'Resources\lang'
    if ($Edition -eq 'Server') {
        # 服务器版：删减非必要语种（仅保留英文）
        if (Test-Path $langDir) {
            foreach ($f in Get-ChildItem $langDir -File) {
                if ($f.Name -notlike 'lang_en-US.json') { Remove-Item $f.FullName -Force }
            }
        }
        # 写入服务器模式标记文件
        $marker = Join-Path $StagingDir 'server.mode'
        Set-Content -Path $marker -Value '1' -Encoding ASCII
        Write-Host "  [服务器版] 已精简语言包（仅英文），已写入 server.mode 标记"
    }
    else {
        # 客户端版：保留全部语言包
        Write-Host "  [客户端版] 保留完整语言包（zh-CN / en-US / zh-TW）"
    }
}

# 从 staging 输出 zip 包
function New-ZipPackage {
    param(
        [string]$SourceDir,
        [string]$ZipPath,
        [string]$EntryRootName
    )
    $tempZip = $ZipPath + '.tmp'
    if (Test-Path $tempZip) { Remove-Item $tempZip -Force }
    if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }

    # 创建临时目录放置顶层文件夹，使 zip 内为 LightGuard-portable/xxx
    $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ('lgzip_' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    try {
        $entryRoot = Join-Path $tempDir $EntryRootName
        Copy-Item -Path $SourceDir -Destination $entryRoot -Recurse -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path $entryRoot)) {
            # Copy-Item 被环境包装拦截时回退到 .NET 复制
            $destDir = New-Item -ItemType Directory -Path $entryRoot -Force
            foreach ($item in Get-ChildItem $SourceDir -Recurse -File) {
                $rel = $item.FullName.Substring((Resolve-Path $SourceDir).Path.Length).TrimStart('\')
                $target = Join-Path $entryRoot $rel
                New-Item -ItemType Directory -Path (Split-Path $target) -Force | Out-Null
                [System.IO.File]::Copy($item.FullName, $target, $true)
            }
        }
        Compress-Archive -Path $entryRoot -DestinationPath $ZipPath -CompressionLevel Optimal
        Write-Host "  Zip 包: $ZipPath ($(Get-FileSizeMB $ZipPath) MB)"
    }
    finally {
        Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
