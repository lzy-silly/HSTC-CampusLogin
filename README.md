# 校园网一键登录 / 自动登录脚本

适用于韩山师范学院的 **ePortal 网关 + CAS 统一身份认证** 体系，完整复现浏览器登录链路，支持一键登录、掉线自动重连、定时保活与开机自启。

## 一、文件说明

| 文件 | 用途 |
|------|------|
| `config.json` | 账号密码与各项配置（**首次使用必须先填写**） |
| `CampusLogin.ps1` | 主脚本：登录 / 检测 / 守护 |
| `install-autostart.ps1` | 开机自启计划任务的安装 / 卸载 / 查看 |

## 二、快速开始

### 1. 填写配置

用记事本打开 `config.json`，至少修改以下两项：

```json
"account": {
  "username": "你的学号",
  "password": "你的密码"
}
```

其余字段一般无需改动，说明见文末。

### 2. 手动登录

在 PowerShell 中进入本目录：

```powershell
cd "D:\AI workspace\CampusLogin"
.\CampusLogin.ps1 -Mode once      # 离线时登录一次
.\CampusLogin.ps1 -Mode force     # 强制重新登录一次
.\CampusLogin.ps1 -Mode check     # 仅检测是否在线
```

若提示"执行策略"错误，用管理员 PowerShell 执行一次：
```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

### 3. 守护模式（掉线自动重连 + 定时保活）

```powershell
.\CampusLogin.ps1 -Mode daemon
```

按 `Ctrl+C` 退出。该模式下每隔 `checkIntervalSec` 秒检测一次，掉线则自动重新登录。

### 4. 开机自启

右键"开始菜单 → Windows PowerShell → 以管理员身份运行"，然后：

```powershell
cd "D:\AI workspace\CampusLogin"
.\install-autostart.ps1 -Action install    # 安装（并可选择立即启动）
.\install-autostart.ps1 -Action status     # 查看状态
.\install-autostart.ps1 -Action remove     # 卸载
```

安装后，每次登录 Windows 会自动在后台运行守护进程（无黑窗口）。

## 三、功能开关

在 `config.json` 的 `features` 节点中，各项自动化能力可独立开关：

```json
"features": {
  "autoReconnect": true,   // 不带 -Mode 参数时是否直接进入守护模式
  "keepAlive":     true,   // 预留：定时保活（守护模式已含定时检测）
  "autoStart":     true    // 是否需要开机自启（决定是否安装计划任务）
}
```

## 四、认证链路（脚本内部流程）

1. `GET https://rz.hstc.edu.cn/` —— 建立会话
2. `GET :802/eportal/portal/cas/create` —— 获取 CAS 授权地址（服务端自动生成含客户端 IP 的 base64 state，脚本无需手工构造）
3. `GET hscas.hstc.edu.cn/cas/login?service=...` —— 取登录页，提取动态令牌 `execution`
4. `GET /cas/jwt/publicKey` —— 获取 RSA 公钥（2048 位）
5. `POST /cas/login` —— 提交 `username` 与 `__RSA__`+RSA(PKCS#1 v1.5) 加密的密码
6. 跟随回调至 ePortal，解析 `RetCode` / `ErrorMsg` 判定结果，并复核在线状态

## 五、配置项说明

| 字段 | 说明 |
|------|------|
| `network.clientIp` | 客户端 IP；留空则自动检测（优先取与网关同网段网卡） |
| `network.clientMac` | MAC 地址，默认 `000000000000`（抓包中即此值） |
| `network.checkUrl` | 在线检测时访问的外网地址，默认百度 |
| `options.checkMode` | `redirect`（默认，检测是否被劫持到门户域名）/ `ping`（仅 ping 网关） |
| `options.portalDomains` | 门户域名关键字列表，用于识别"被劫持/未登录"状态 |
| `options.checkIntervalSec` | 守护模式检测间隔（秒） |
| `options.loginRetries` | 单轮登录失败重试次数 |
| `options.requestTimeoutSec` | 单次请求超时（秒） |

## 六、常见问题

- **提示"账号被冻结/停机/欠费"**：这是账号本身状态问题（抓包中即为此情况），与脚本无关，请先恢复账号。
- **提示"未找到 execution 令牌"**：登录页结构有变，需重新抓包核对。
- **提示"无法自动获取客户端 IP"**：在 `config.json` 手动填写 `network.clientIp`（如 `192.168.248.82`）。
- **验证码**：当前账号体系前 3 次失败免验证码，正常登录无需处理；若连续失败触发验证码，脚本会提示，需人工登录一次后再用。
- **中文乱码**：两个 `.ps1` 脚本已保存为 UTF-8 with BOM，请勿用会去除 BOM 的编辑器另存。

## 七、安全提示

- 密码以明文存于本机 `config.json`，请仅在本机保存，不要上传或分享该文件。
- 如需更高安全级别，可将密码移入系统凭据管理器（当前版本未内置此功能）。
- 本脚本仅用于本人账号的合法自动登录，请遵守学校网络管理规定。
