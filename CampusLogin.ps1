#requires -Version 5.1
<#
.SYNOPSIS
  校园网一键登录 / 自动登录脚本（韩山师范学院 ePortal + CAS 认证）

.DESCRIPTION
  完整复现浏览器登录链路：
    1) GET  rz.hstc.edu.cn          建立会话，获取客户端 IP
    2) GET  eportal/portal/cas/create   取得 CAS 授权地址（含 state）
    3) GET  hscas.hstc.edu.cn/cas/login 取登录页，提取 execution 令牌
    4) GET  /cas/jwt/publicKey           取 RSA 公钥
    5) POST /cas/login                   提交加密后的账号密码
    6) 跟随回调，解析 RetCode / ErrorMsg 判定结果

.PARAMETER Mode
  check   - 仅检测当前是否在线
  once    - 执行一次登录（若在线则跳过）
  force   - 强制登录一次（不检测在线状态）
  daemon  - 守护模式：循环检测，掉线自动重连
  help    - 显示帮助

.PARAMETER Config
  配置文件路径，默认脚本同目录 config.json

.PARAMETER LogFile
  日志文件路径，默认脚本同目录 campus-login.log

.EXAMPLE
  .\CampusLogin.ps1 -Mode once
  .\CampusLogin.ps1 -Mode daemon
#>
[CmdletBinding()]
param(
    [string]$Mode = '',
    [string]$Config = '',
    [string]$LogFile = ''
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ---------------------------------------------------------------- 路径 / 配置
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Config)   { $Config   = Join-Path $ScriptDir 'config.json' }
if (-not $LogFile)  { $LogFile  = Join-Path $ScriptDir 'campus-login.log' }

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 } catch { }
}

function Load-Config {
    if (-not (Test-Path $Config)) { throw "配置文件不存在: $Config" }
    return Get-Content -Path $Config -Raw -Encoding UTF8 | ConvertFrom-Json
}

# ---------------------------------------------------------------- DER / RSA
# 读取 ASN.1 DER 的 TLV，返回 @{ Tag; Value }
function Read-DerTlv {
    param([byte[]]$Data, [int]$Offset)
    if ($Offset -ge $Data.Length) { throw 'DER 数据越界' }
    $tag = $Data[$Offset]; $Offset++
    $len = $Data[$Offset]; $Offset++
    if ($len -band 0x80) {
        $n = $len -band 0x7F
        if ($n -eq 0 -or $n -gt 4) { throw 'DER 长度字段异常' }
        $len = 0
        for ($i = 0; $i -lt $n; $i++) { $len = ($len -shl 8) -bor $Data[$Offset]; $Offset++ }
    }
    if ($Offset + $len -gt $Data.Length) { throw 'DER 内容越界' }
    $value = New-Object byte[] $len
    [Array]::Copy($Data, $Offset, $value, 0, $len)
    return @{ Tag = $tag; Value = $value; NextOffset = ($Offset + $len) }
}

# 从 PEM 公钥解析 RSA Modulus / Exponent
function Get-RsaParametersFromPem {
    param([string]$Pem)
    $b64 = $Pem -replace '-----BEGIN [^-]+-----', '' -replace '-----END [^-]+-----', '' -replace '\s', ''
    $der = [Convert]::FromBase64String($b64)
    # SubjectPublicKeyInfo = SEQ { SEQ{算法标识}, BITSTRING{ SEQ{ INT(n), INT(e) } } }
    $inner = Read-DerTlv -Data $der -Offset 0
    $bytes = $inner.Value
    $off = 0
    $rsaSeq = $null
    while ($off -lt $bytes.Length) {
        $tlv = Read-DerTlv -Data $bytes -Offset $off
        if ($tlv.Tag -eq 0x03 -and $tlv.Value.Length -gt 0 -and $tlv.Value[0] -eq 0x00) {
            $kb = New-Object byte[] ($tlv.Value.Length - 1)
            [Array]::Copy($tlv.Value, 1, $kb, 0, $kb.Length)
            $rsaSeq = Read-DerTlv -Data $kb -Offset 0
            break
        }
        $off = $tlv.NextOffset
    }
    if (-not $rsaSeq -or $rsaSeq.Tag -ne 0x30) { throw '无法从公钥解析 RSA 参数' }
    # RSAPublicKey = SEQ { INT(n), INT(e) }
    $kb = $rsaSeq.Value
    $off = 0
    $ints = @()
    while ($off -lt $kb.Length) {
        $tlv = Read-DerTlv -Data $kb -Offset $off
        if ($tlv.Tag -eq 0x02) { $ints += ,$tlv.Value }
        $off = $tlv.NextOffset
    }
    if ($ints.Count -lt 2) { throw 'RSA 公钥缺少 modulus/exponent' }
    $mod = $ints[0]
    $exp = $ints[1]
    if ($mod.Length -gt 0 -and $mod[0] -eq 0) { $mod = $mod[1..($mod.Length - 1)] }
    if ($exp.Length -gt 0 -and $exp[0] -eq 0) { $exp = $exp[1..($exp.Length -1)] }
    return @{ Modulus = $mod; Exponent = $exp }
}

# 使用 JSEncrypt 兼容的 PKCS#1 v1.5 加密密码
function Get-EncryptedPassword {
    param([string]$Plain, [string]$Pem)
    $key = Get-RsaParametersFromPem -Pem $Pem
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $p = New-Object System.Security.Cryptography.RSAParameters
    $p.Modulus = $key.Modulus
    $p.Exponent = $key.Exponent
    $rsa.ImportParameters($p)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Plain)
    $cipher = $rsa.Encrypt($bytes, $false)   # false = PKCS#1 v1.5
    return '__RSA__' + [Convert]::ToBase64String($cipher)
}

# ---------------------------------------------------------------- HTTP 工具
# 手动跟踪重定向的 GET（返回最终响应对象与内容）
function Invoke-GetNoRedirect {
    param([string]$Url, [object]$Cookies, [string]$Referer = '', [int]$TimeoutSec = 30)
    $req = [Net.HttpWebRequest]::Create($Url)
    $req.Method = 'GET'
    $req.AllowAutoRedirect = $false
    $req.CookieContainer = $Cookies
    $req.Timeout = $TimeoutSec * 1000
    $req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36'
    $req.Accept = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    $req.Headers['Accept-Language'] = 'zh-CN,zh;q=0.9,en;q=0.8'
    if ($Referer) { $req.Referer = $Referer }
    $resp = $req.GetResponse()
    $sr = New-Object IO.StreamReader($resp.GetResponseStream(), [Text.Encoding]::UTF8)
    $content = $sr.ReadToEnd(); $sr.Close()
    return @{ Response = $resp; Content = $content }
}

# 跟随重定向，最多 N 次，返回最终 URL 和响应内容
function Invoke-FollowRedirects {
    param([string]$Url, [object]$Cookies, [int]$Max = 8, [int]$TimeoutSec = 30)
    $cur = $Url
    $lastContent = ''
    $respObj = $null
    for ($i = 0; $i -lt $Max; $i++) {
        $r = Invoke-GetNoRedirect -Url $cur -Cookies $Cookies -TimeoutSec $TimeoutSec
        $respObj = $r.Response
        $lastContent = $r.Content
        $status = [int]$respObj.StatusCode
        if ($status -ge 300 -and $status -lt 400) {
            $loc = $respObj.Headers['Location']
            if (-not $loc) { break }
            if ($loc -match '^https?://') { $cur = $loc }
            else { $cur = ([uri]$cur).GetLeftPart([UriPartial]::Authority) + $loc }
            $respObj.Close()
            continue
        }
        return @{ FinalUrl = $cur; Content = $lastContent; Status = $status }
    }
    if ($respObj) { try { $respObj.Close() } catch {} }
    return @{ FinalUrl = $cur; Content = $lastContent; Status = 0 }
}

# ---------------------------------------------------------------- 在线检测
function Test-IsOnline {
    param([object]$Cfg)
    $mode = $Cfg.options.checkMode
    $domainList = @($Cfg.options.portalDomains)
    $timeout = [int]$Cfg.options.requestTimeoutSec

    switch ($mode) {
        'ping' {
            try {
                $gw = $Cfg.network.gatewayIp
                if (-not $gw) { return $false }
                return (Test-Connection -TargetName $gw -Count 1 -Quiet -TimeoutSeconds 2)
            } catch { return $false }
        }
        default {  # redirect / http：访问外网，看是否被劫持到门户域名
            try {
                $url = $Cfg.network.checkUrl
                if (-not $url) { $url = 'https://www.baidu.com' }
                $cookies = New-Object Net.CookieContainer
                $r = Invoke-FollowRedirects -Url $url -Cookies $cookies -Max 5 -TimeoutSec $timeout
                $final = $r.FinalUrl
                foreach ($d in $domainList) {
                    if ($final -like "*$d*" -or $r.Content -match [regex]::Escape($d)) { return $false }
                }
                return ($r.Status -ge 200 -and $r.Status -lt 400)
            } catch {
                return $false
            }
        }
    }
}

# ---------------------------------------------------------------- 客户端 IP
function Get-ClientIp {
    param([string]$Configured, [string]$GatewayIp)
    if ($Configured -and $Configured -notmatch '^\s*$') { return $Configured }
    # 优先取与网关同网段的网卡 IP
    if ($GatewayIp) {
        $gwParts = $GatewayIp.Split('.')
        if ($gwParts.Count -eq 4) {
            $prefix = '{0}.{1}.{2}.' -f $gwParts[0], $gwParts[1], $gwParts[2]
            $candidates = Get-NetIPConfiguration | ForEach-Object { $_.IPv4Address.IPAddress } | Where-Object { $_ -like "$prefix*" }
            if ($candidates) { return @($candidates)[0] }
        }
    }
    # 回退：第一个非回环、非 169.254 的 IPv4
    $fallback = Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
        Select-Object -First 1 -ExpandProperty IPAddress
    if ($fallback) { return $fallback }
    throw '无法自动获取客户端 IP，请在 config.json 的 network.clientIp 中手动填写'
}

# ---------------------------------------------------------------- 核心登录
function Invoke-CasLogin {
    param([object]$Cfg)

    $casBase = $Cfg.network.casBaseUrl.TrimEnd('/')
    $gwHost  = $Cfg.network.gatewayHost
    $gwPort  = $Cfg.network.gatewayPort
    $gwIp    = $Cfg.network.gatewayIp
    $timeout = [int]$Cfg.options.requestTimeoutSec
    $clientIp = Get-ClientIp -Configured $Cfg.network.clientIp -GatewayIp $gwIp
    Write-Log "客户端 IP: $clientIp" 'DEBUG'

    $cookies = New-Object Net.CookieContainer

    # 1) 门户首页 → 建立会话（允许 302，取得 cookie）
    Write-Log '步骤 1/6 建立门户会话'
    $portalReq = [Net.HttpWebRequest]::Create($Cfg.network.portalUrl)
    $portalReq.CookieContainer = $cookies
    $portalReq.AllowAutoRedirect = $true
    $portalReq.Timeout = $timeout * 1000
    $portalReq.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36'
    $portalResp = $portalReq.GetResponse()
    $portalResp.Close()

    # 2) cas/create → 取得 CAS 授权地址
    Write-Log '步骤 2/6 请求 CAS 授权地址'
    $createUrl = 'https://{0}:{1}/eportal/portal/cas/create?callback=dr1003&login_method=1&wlan_user_ip={2}&wlan_user_ipv6=&wlan_user_mac={3}&wlan_ac_ip=&wlan_ac_name=&authex_enable=&mac_type=0&jsVersion=4.2.2&v={4}&lang=zh' -f `
        $gwHost, $gwPort, $clientIp, $Cfg.network.clientMac, (Get-Random)
    $r2 = Invoke-GetNoRedirect -Url $createUrl -Cookies $cookies -TimeoutSec $timeout
    $createBody = $r2.Content
    $r2.Response.Close()
    $m = [regex]::Match($createBody, 'authorize_uri"\s*:\s*"([^"]+)"')
    if (-not $m.Success) {
        # 兼容未指定 IP 的情况：state 由服务端生成
        throw "未取得 CAS 授权地址。响应: $($createBody.Substring(0, [Math]::Min(300, $createBody.Length)))"
    }
    $authorizeUri = $m.Groups[1].Value -replace '\\/', '/'
    Write-Log "授权地址: $authorizeUri" 'DEBUG'

    # 3) CAS 登录页 → 取 execution
    Write-Log '步骤 3/6 获取登录页与 execution 令牌'
    $r3 = Invoke-GetNoRedirect -Url $authorizeUri -Cookies $cookies -TimeoutSec $timeout
    $loginPage = $r3.Content
    $r3.Response.Close()
    $me = [regex]::Match($loginPage, 'name="execution"\s+value="([^"]+)"')
    if (-not $me.Success) { throw '未找到 execution 令牌，登录页结构可能已变化' }
    $execution = $me.Groups[1].Value

    # 4) 取 RSA 公钥
    Write-Log '步骤 4/6 获取 RSA 公钥'
    $pkUrl = "$casBase/cas/jwt/publicKey"
    $r4 = Invoke-GetNoRedirect -Url $pkUrl -Cookies $cookies -TimeoutSec $timeout
    $publicKey = $r4.Content.Trim()
    $r4.Response.Close()
    if ($publicKey -notmatch 'BEGIN PUBLIC KEY') { throw 'RSA 公钥格式异常' }

    # 5) 提交登录表单
    Write-Log '步骤 5/6 提交加密登录表单'
    $encPwd = Get-EncryptedPassword -Plain $Cfg.account.password -Pem $publicKey
    $fields = [ordered]@{
        username    = $Cfg.account.username
        password    = $encPwd
        captcha     = ''
        currentMenu = '1'
        failN       = '0'
        mfaState    = ''
        execution   = $execution
        _eventId    = 'submit'
        geolocation = ''
        submit      = 'Login1'
    }
    $body = ($fields.GetEnumerator() | ForEach-Object {
        '{0}={1}' -f $_.Key, [uri]::EscapeDataString($_.Value)
    }) -join '&'
    $bodyBytes = [Text.Encoding]::UTF8.GetBytes($body)
    $postReq = [Net.HttpWebRequest]::Create($authorizeUri)
    $postReq.Method = 'POST'
    $postReq.AllowAutoRedirect = $false
    $postReq.CookieContainer = $cookies
    $postReq.Timeout = $timeout * 1000
    $postReq.ContentType = 'application/x-www-form-urlencoded'
    $postReq.ContentLength = $bodyBytes.Length
    $postReq.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36'
    $postReq.Referer = $authorizeUri
    $stream = $postReq.GetRequestStream()
    $stream.Write($bodyBytes, 0, $bodyBytes.Length)
    $stream.Close()
    $postResp = $postReq.GetResponse()
    $status = [int]$postResp.StatusCode
    $location = $postResp.Headers['Location']
    $postResp.Close()
    if ($status -lt 300 -or $status -ge 400 -or -not $location) {
        throw "CAS 登录提交失败，HTTP $status"
    }

    # 6) 跟随回调，解析 RetCode / ErrorMsg
    Write-Log '步骤 6/6 处理认证回调'
    $callback = Invoke-FollowRedirects -Url $location -Cookies $cookies -Max 8 -TimeoutSec $timeout
    $finalUrl = $callback.FinalUrl
    $content = $callback.Content

    # 从 URL 或正文提取 RetCode / ErrorMsg
    $retCode = ''
    $errMsg = ''
    $mRet = [regex]::Match($finalUrl, '[?&]RetCode=([^&]+)')
    if ($mRet.Success) { $retCode = [uri]::UnescapeDataString($mRet.Groups[1].Value) }
    $mErr = [regex]::Match($finalUrl, '[?&]ErrorMsg=([^&]+)')
    if ($mErr.Success) { $errMsg = [uri]::UnescapeDataString($mErr.Groups[1].Value) }
    if (-not $errMsg) {
        $mErr2 = [regex]::Match($content, 'ErrorMsg=([^"&<]+)')
        if ($mErr2.Success) { $errMsg = [uri]::UnescapeDataString($mErr2.Groups[1].Value) }
    }

    if ($errMsg) {
        $plain = ''
        try { $plain = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($errMsg)) } catch { $plain = $errMsg }
        throw "网关返回错误 (RetCode=$retCode): $plain"
    }

    # 复核在线状态
    Start-Sleep -Milliseconds 800
    if (Test-IsOnline -Cfg $Cfg) { return $true }
    throw 'CAS 认证完成但在线检测未通过，可能被网关拒绝或账号状态异常'
}

# ---------------------------------------------------------------- 主流程
function Invoke-OneRound {
    param([object]$Cfg, [switch]$Force)
    if (-not $Force) {
        if (Test-IsOnline -Cfg $Cfg) { Write-Log '当前已在线，无需登录'; return $true }
    }
    $retries = [int]$Cfg.options.loginRetries
    for ($i = 1; $i -le $retries; $i++) {
        Write-Log "开始登录尝试 $i/$retries"
        try {
            if (Invoke-CasLogin -Cfg $Cfg) { Write-Log '登录成功' 'OK'; return $true }
        } catch {
            Write-Log "登录失败: $($_.Exception.Message)" 'ERROR'
        }
        if ($i -lt $retries) { Start-Sleep -Seconds ([int]$Cfg.options.retryIntervalSec) }
    }
    return $false
}

function Show-Help {
    Write-Host @'
用法: CampusLogin.ps1 [-Mode <模式>] [-Config <路径>] [-LogFile <路径>]

模式:
  check    仅检测当前是否在线
  once     若离线则登录一次（在线则跳过）
  force    忽略在线状态，强制登录一次
  daemon   守护模式：循环检测，掉线自动重连（Ctrl+C 退出）
  help     显示本帮助

无 -Mode 参数时，读取 config.json 的 features.autoReconnect：
  true  -> daemon 模式
  false -> once 模式
'@
}

# ---------------------------------------------------------------- 入口
try {
    $cfg = Load-Config
    switch ($Mode) {
        'help'   { Show-Help; return }
        'check'  { if (Test-IsOnline -Cfg $cfg) { Write-Log '状态: 在线' 'OK'; exit 0 } else { Write-Log '状态: 离线' 'WARN'; exit 1 } }
        'once'   { if (Invoke-OneRound -Cfg $cfg) { exit 0 } else { exit 1 } }
        'force'  { if (Invoke-OneRound -Cfg $cfg -Force) { exit 0 } else { exit 1 } }
        'daemon' {
            Write-Log '进入守护模式'
            $interval = [int]$cfg.options.checkIntervalSec
            while ($true) {
                try {
                    if (Test-IsOnline -Cfg $cfg) {
                        Write-Log '在线检测: 正常'
                    } else {
                        Write-Log '在线检测: 掉线，触发重连' 'WARN'
                        $null = Invoke-OneRound -Cfg $cfg -Force
                    }
                } catch { Write-Log "守护循环异常: $($_.Exception.Message)" 'ERROR' }
                Start-Sleep -Seconds $interval
            }
        }
        default {
            if ($cfg.features.autoReconnect) {
                Write-Log '未指定模式，按配置进入 daemon'
                & $MyInvocation.MyCommand.Path -Mode daemon -Config $Config -LogFile $LogFile
            } else {
                & $MyInvocation.MyCommand.Path -Mode once -Config $Config -LogFile $LogFile
            }
        }
    }
} catch {
    Write-Log "致命错误: $($_.Exception.Message)" 'FATAL'
    exit 1
}
