# ============================================================
# LightGuard 双版本一键打包（P1-1 双版本分发架构）
#   A版：MSI 安装包（企业/服务器主力）
#   B版：绿色便携版（运维临时场景）
#
# 用法：
#   .\build-all.ps1                     # 客户端双版本（framework-dependent）
#   .\build-all.ps1 -Edition Server     # 服务器双版本精简
#   .\build-all.ps1 -SelfContained      # 双版本自包含（免运行时）
#   .\build-all.ps1 -Rid win-arm64      # 指定架构
#   .\build-all.ps1 -SkipMsi            # 仅便携版（跳过 MSI）
# ============================================================
param(
    [ValidateSet('Client', 'Server')][string]$Edition = 'Client',
    [ValidateSet('win-x64', 'win-x86', 'win-arm64')][string]$Rid = 'win-x64',
    [switch]$SelfContained,
    [switch]$SkipMsi,
    [switch]$SkipPortable
)

$ErrorActionPreference = 'Stop'
$common = Join-Path $PSScriptRoot 'packaging-common.ps1'
. $common
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

Write-Host "=========== LightGuard 双版本打包 [$Edition / $Rid] ===========" -ForegroundColor Magenta
Write-Host "A版: MSI 安装包（企业/服务器主力）"
Write-Host "B版: 绿色便携版（U盘运维/现场应急）"
Write-Host "==============================================================" -ForegroundColor Magenta

if (-not $SkipPortable) {
    Write-Host "`n########## B版：绿色便携版 ##########" -ForegroundColor Cyan
    & (Join-Path $PSScriptRoot 'build-portable.ps1') -Edition $Edition -Rid $Rid -SelfContained:$SelfContained
}

if (-not $SkipMsi) {
    Write-Host "`n########## A版：MSI 安装版 ##########" -ForegroundColor Cyan
    & (Join-Path $PSScriptRoot 'build-msi.ps1') -Edition $Edition -Rid $Rid -SelfContained:$SelfContained
}

Write-Host "`n=========== 全部完成，产物目录: $(Join-Path $root 'dist') ===========" -ForegroundColor Green
Get-ChildItem (Join-Path $root 'dist') -File | ForEach-Object {
    Write-Host "  $($_.Name) ($([math]::Round($_.Length/1MB,2)) MB)"
}
