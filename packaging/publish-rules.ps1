# ============================================================
# LightGuard 云端规则发布脚本（P1-3 云端规则更新 - 发布端）
#
# 将规则文件发布为客户端 CloudUpdateClient 可消费的清单格式：
#   - 复制规则文件到 files/{RuleType}/{fileName}
#   - 计算 SHA256 + 文件大小（客户端双重校验防篡改/防截断）
#   - RSA-2048 数字签名（私钥 XML，可选）
#   - 生成/合并 manifest/{Channel}.json（UpdateManifest 对齐）
#
# 用法：
#   .\publish-rules.ps1 -RuleFile .\rules\online_rules.json -RuleType YaraRansomware `
#                       -Version 2.1.0 -Channel stable `
#                       -PrivateKeyXml .\publish\private.xml `
#                       -DownloadBaseUrl https://update.lightguard.app/v1/files
#
# 依赖：RSA 私钥 XML（openssl genrsa + RSAPrivateKeyConverter 生成）
# ============================================================
param(
    [Parameter(Mandatory)][string]$RuleFile,             # 规则文件路径
    [ValidateSet('YaraRansomware', 'AdBlockRules', 'DecryptorIndex', 'VirusDatabase')][string]$RuleType = 'YaraRansomware',
    [Parameter(Mandatory)][string]$Version,              # 语义化版本号（如 2.1.0）
    [ValidateSet('stable', 'beta', 'nightly')][string]$Channel = 'stable',
    [string]$PrivateKeyXml = '',                         # RSA 私钥 XML（可选；提供则签名）
    [string]$DownloadBaseUrl = 'https://update.lightguard.app/v1/files',  # 规则文件下载基础 URL
    [string]$MinClientVersion = '3.0.0',                 # 最低客户端版本
    [string]$Changelog = '',                             # 变更日志
    [string]$OutDir = ''                                 # 输出目录（默认 ./dist/rules）
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if ([string]::IsNullOrEmpty($OutDir)) {
    $OutDir = Join-Path $root 'dist\rules'
}

if (-not (Test-Path $RuleFile)) { throw "规则文件不存在: $RuleFile" }

# 规则类型 → 文件名映射（与 CloudUpdateClient.GetRuleFileName 对齐）
$fileNameMap = @{
    'YaraRansomware' = 'online_rules.json'
    'AdBlockRules'   = 'adblock_rules.json'
    'DecryptorIndex' = 'DecryptionToolIndex.json'
    'VirusDatabase'  = 'main.cvd'
}
$fileName = $fileNameMap[$RuleType]

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " LightGuard 云端规则发布 [$RuleType v$Version / $Channel]" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan

# ---- 1. 复制规则文件到发布目录 ----
$fileDir = Join-Path (Join-Path $OutDir 'files') $RuleType
$publishedFile = Join-Path $fileDir $fileName
New-Item -ItemType Directory -Path $fileDir -Force | Out-Null
[System.IO.File]::Copy($RuleFile, $publishedFile, $true)
Write-Host "规则文件已发布: $publishedFile ($([math]::Round((Get-Item $publishedFile).Length/1KB,1)) KB)"

# ---- 2. 计算 SHA256 + 文件大小 ----
$sha = (Get-FileHash $publishedFile -Algorithm SHA256).Hash.ToLowerInvariant()
$sizeBytes = (Get-Item $publishedFile).Length
Write-Host "SHA256: $sha"
Write-Host "SizeBytes: $sizeBytes"

# ---- 3. RSA-2048 签名 ----
$signature = ''
if (-not [string]::IsNullOrEmpty($PrivateKeyXml) -and (Test-Path $PrivateKeyXml)) {
    Write-Host "`n正在对规则文件进行 RSA-2048 签名 ..."
    $keyXml = Get-Content $PrivateKeyXml -Raw
    $fileBytes = [System.IO.File]::ReadAllBytes($publishedFile)
    $rsa = [System.Security.Cryptography.RSA]::Create()
    $rsa.FromXmlString($keyXml)
    $hash = [System.Security.Cryptography.SHA256]::HashData($fileBytes)
    $signature = [Convert]::ToBase64String($rsa.SignHash($hash,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1))
    $rsa.Dispose()
    Write-Host "签名完成（$($signature.Length) 字符）"
}
else {
    Write-Host "`n警告: 未提供私钥，清单不包含 RSA 签名（客户端将跳过签名校验）" -ForegroundColor Yellow
}

# ---- 4. 下载 URL ----
$downloadUrl = if ($DownloadBaseUrl.EndsWith('/')) { "$DownloadBaseUrl$RuleType/$fileName" }
               else { "$DownloadBaseUrl/$RuleType/$fileName" }

# ---- 5. 生成/合并清单 manifest/{Channel}.json ----
$manifestDir = Join-Path $OutDir 'manifest'
New-Item -ItemType Directory -Path $manifestDir -Force | Out-Null
$manifestPath = Join-Path $manifestDir "$Channel.json"

$latestVersions = @()
if (Test-Path $manifestPath) {
    try {
        $existing = Get-Content $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $latestVersions = @($existing.latestVersions)
    }
    catch { $latestVersions = @() }
}

# 构造本条规则版本信息
$newEntry = [ordered]@{
    ruleType    = $RuleType
    version     = $Version
    publishedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    downloadUrl = $downloadUrl
    sha256      = $sha
    rsaSignature = $signature
    sizeBytes   = $sizeBytes
    changelog   = $Changelog
}

# 合并：替换同 ruleType 条目，其余保留
$merged = @()
$replaced = $false
foreach ($e in $latestVersions) {
    if ($e.ruleType -eq $RuleType) {
        $merged += $newEntry
        $replaced = $true
    }
    else {
        $merged += $e
    }
}
if (-not $replaced) { $merged += $newEntry }

# 构建完整清单
$manifest = [ordered]@{
    serverTime      = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    latestVersions  = $merged
    minClientVersion = $MinClientVersion
}

$manifest | ConvertTo-Json -Depth 5 | Set-Content $manifestPath -Encoding UTF8

Write-Host "`n============ 云端规则发布完成 ============" -ForegroundColor Green
Write-Host "  清单: $manifestPath"
Write-Host "  下载: $downloadUrl"
Write-Host "  版本: $Version (通道: $Channel, 最低客户端: $MinClientVersion)"
Write-Host "  校验: SHA256 + 大小$(if ($signature) { ' + RSA 签名' })"
