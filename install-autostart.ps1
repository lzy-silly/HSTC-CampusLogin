#requires -Version 5.1
<#
.SYNOPSIS
  安装 / 卸载校园网自动登录的开机自启计划任务

.PARAMETER Action
  install - 安装自启任务（默认）
  remove  - 卸载自启任务
  status  - 查看任务状态

.EXAMPLE
  .\install-autostart.ps1 -Action install
  .\install-autostart.ps1 -Action status
  .\install-autostart.ps1 -Action remove
#>
[CmdletBinding()]
param(
    [ValidateSet('install','remove','status')]
    [string]$Action = 'install',
    [string]$TaskName = 'CampusNetAutoLogin'
)

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$MainScript = Join-Path $ScriptDir 'CampusLogin.ps1'

function Test-Admin {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

switch ($Action) {
    'status' {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if (-not $task) { Write-Host "任务 '$TaskName' 未安装"; exit 0 }
        $info = Get-ScheduledTaskInfo -TaskName $TaskName
        Write-Host "任务: $TaskName  状态: $($task.State)"
        Write-Host "上次运行: $($info.LastRunTime)  结果: $($info.LastTaskResult)"
        $actionEx = (Get-ScheduledTask -TaskName $TaskName).Actions[1]
        Write-Host "执行: $($actionEx.Execute) $($actionEx.Arguments)"
    }
    'remove' {
        if (-not (Test-Admin)) { Write-Error '需要管理员权限，请以管理员身份运行'; exit 1 }
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($task) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            Write-Host "已卸载自启任务 '$TaskName'"
        } else { Write-Host "任务 '$TaskName' 不存在，无需卸载" }
    }
    'install' {
        if (-not (Test-Admin)) { Write-Error '需要管理员权限，请以管理员身份运行'; exit 1 }
        if (-not (Test-Path $MainScript)) { Write-Error "主脚本不存在: $MainScript"; exit 1 }

        # PowerShell 路径与参数（隐藏窗口后台运行守护模式）
        $psExe = Join-Path $PSHOME 'powershell.exe'
        $arguments = '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}" -Mode daemon' -f $MainScript

        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $action = New-ScheduledTaskAction -Execute $psExe -Argument $arguments -WorkingDirectory $ScriptDir
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -Hidden
        $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest

        $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($existing) { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false }
        Register-ScheduledTask -TaskName $TaskName -Trigger $trigger -Action $action -Settings $settings -Principal $principal -Description '校园网自动登录（掉线自动重连）' | Out-Null
        Write-Host "已安装自启任务 '$TaskName'，登录后自动后台运行守护模式"

        # 询问是否立即启动
        $reply = Read-Host '是否立即启动守护进程？[y/N]'
        if ($reply -match '^(y|yes)$') {
            Start-ScheduledTask -TaskName $TaskName
            Write-Host '已启动，可运行: Get-ScheduledTaskInfo -TaskName CampusNetAutoLogin 查看状态'
        }
    }
}
