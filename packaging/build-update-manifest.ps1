# ============================================================
# LightGuard 增量更新清单生成脚本（发布端）
#
# 将 packaging/build-diff.ps1 生成的差分包转换为客户端可消费的
# update-manifest.json，并完成 RSA-2048 数字签名（防篡改）。
#
# 用法（先运行 build-diff.ps1 生成 dist/diff/）：
#   .\build-update-manifest.ps1 -DiffDir .\dist\diff -TargetVersion 3.2.0 -BaseVersion 3.1.0
#   .\build-update-manifest.ps1 -DiffDir .\dist\diff -PrivateKeyXml .\publish\private.xml
# ============================================================
param(
    [Parameter(Mandatory)][string]$DiffDir,          # build-diff.ps1 输出目录（含 update.zip / changelog.json / delete.list）
    [string]$TargetVersion = '',                     # 目标版本（默认从 changelog.json 推断则需手动指定）
    [string]$BaseVersion = '',                       # 基准版本
    [string]$DownloadBaseUrl = '',                   # 差分包下载基础 URL（默认与清单同目录）
    [string]$PrivateKeyXml = '',                     # RSA 私钥 XML（可选；提供则签名）
    [string]$ReleaseNotes = '',                      # 发布说明
    [string]$OutDir = ''                             # 输出目录（默认 DiffDir）
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if ([string]::IsNullOrEmpty($OutDir)) { $OutDir = $DiffDir }

$zipPath = Join-Path $DiffDir 'update.zip'
$changelogPath = Join-Path $DiffDir 'changelog.json'
if (-not (Test-Path $zipPath)) { throw "未找到差分包: $zipPath" }
if (-not (Test-Path $changelogPath)) { throw "未找到变更清单: $changelogPath" }

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " LightGuard 增量更新清单生成" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan

# ---- 1. 读取 changelog.json ----
$changelog = Get-Content $changelogPath -Raw -Encoding UTF8 | ConvertFrom-Json
$added = @($changelog.added)
$modified = @($changelog.modified)
$deleted = @($changelog.deleted)
Write-Host "变更文件: 新增 $($added.Count) | 修改 $($modified.Count) | 删除 $($deleted.Count)"

# ---- 2. 计算 update.zip SHA256 ----
$sha = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host "update.zip SHA256: $sha"

# ---- 3. 计算下载 URL ----
if ([string]::IsNullOrEmpty($DownloadBaseUrl)) {
    $DownloadBaseUrl = './'  # 默认与清单同目录
}
$downloadUrl = if ($DownloadBaseUrl.EndsWith('/')) { "$DownloadBaseUrl" + (Split-Path $zipPath -Leaf) }
              else { "$DownloadBaseUrl/" + (Split-Path $zipPath -Leaf) }

# ---- 4. 构建清单对象 ----
$manifest = [ordered]@{
    version       = $TargetVersion
    baseVersion   = $BaseVersion
    downloadUrl   = $downloadUrl
    sha256        = $sha
    releaseNotes  = $ReleaseNotes
    publishedAt   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    added         = $added
    modified      = $modified
    deleted       = $deleted
}

# ---- 5. RSA 签名（对 canonical JSON 字节签名） ----
if (-not [string]::IsNullOrEmpty($PrivateKeyXml) -and (Test-Path $PrivateKeyXml)) {
    Write-Host "`n正在对清单进行 RSA-2048 签名 ..."
    $keyXml = Get-Content $PrivateKeyXml -Raw
    $json = $manifest | ConvertTo-Json -Depth 4 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $rsa = [System.Security.Cryptography.RSA]::Create()
    $rsa.FromXmlString($keyXml)
    $hash = [System.Security.Cryptography.SHA256]::HashData($bytes)
    $sig = $rsa.SignHash($hash, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $manifest['signature'] = [Convert]::ToBase64String($sig)
    $rsa.Dispose()
    Write-Host "签名完成"
}
else {
    Write-Host "`n警告: 未提供私钥，清单不包含数字签名（客户端将跳过签名校验）" -ForegroundColor Yellow
}

# ---- 6. 输出 update-manifest.json ----
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$outPath = Join-Path $OutDir 'update-manifest.json'
$manifest | ConvertTo-Json -Depth 4 | Set-Content $outPath -Encoding UTF8

Write-Host "`n清单已生成: $outPath" -ForegroundColor Green
Write-Host "  版本: $TargetVersion (基准: $BaseVersion)"
Write-Host "  下载: $downloadUrl"
Write-Host "  变更: $($added.Count + $modified.Count + $deleted.Count) 个文件"
