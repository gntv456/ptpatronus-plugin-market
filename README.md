# PTPatronus Plugin Market

官方插件市场 for [PTPatronus](https://ptang.top)。用户在 App「插件」页填入本仓库地址即可浏览、安装、升级已签名的插件。

```
gntv456/ptpatronus-plugin-market
```

PTPatronus 主程序闭源,但插件平台是开放开发面。本仓库收录 **PTPatronus Community** 维护的官方插件,每个插件 zip 由市场私钥 Ed25519 签名,安装前由宿主校验签名与 sha256。

## 官方插件

| 插件 | 作用 | 版本 |
|---|---|---|
| `auto-speed` | 简易下载测速（迁移自 MoviePilot auto-speed）。 | v1.1.0 |
| `cloudflare-subscribe` | 定时拉取订阅源并更新本地 hosts 片段（迁移自 MoviePilot）。 | v1.0.5 |
| `cron-helper` | 校验 Cron 表达式并预览接下来若干次执行时间。 | v1.0.0 |
| `event-audit` | 记录插件事件总线中的关键事件，便于排查 Webhook、测试事件和后续业务事件。 | v1.0.0 |
| `group-chat-zone` | 按站点配置定时发送群聊/喊话消息（开源市场通用版）。 | v3.0.0 |
| `http-probe` | 探测站点/API 的状态码、响应时间与响应片段，适合巡检与可用性检查。 | v1.0.0 |
| `json-toolbox` | 格式化、压缩、取值路径与 JSON 校验工具。 | v1.0.0 |
| `keyword-alert` | 监听事件 payload，命中关键词后发送通知。 | v1.0.0 |
| `notice-forwarder` | 将指定事件转成站内通知，并复用系统通知通道外发。 | v1.0.0 |
| `ptp-ai-subtitle` | 用 faster-whisper 为视频自动转录生成字幕（.srt），可选 OpenAI 兼容接口翻译为目标语言。... | v0.1.0 |
| `ptp-cd2-assistant` | 定时检查 CloudDrive2 实例：探测上传任务错误/账号失效并通知；提供重启、查看系统信息、提交离线下载等动... | v0.1.0 |
| `ptp-custom-command` | 按行配置本地命令并定时/手动执行（工作目录与超时可配）。 | v1.0.0 |
| `ptp-drama-scrape` | 扫描短剧目录，调用寸光集等源补齐元数据/封面（开源市场版）。 | v1.0.0 |
| `ptp-ffmpeg-thumb` | 定时扫描媒体库，为每个缺少缩略图的视频用 FFmpeg 截取一帧作为 <文件名>-thumb.jpg。需要宿主机已... | v0.1.0 |
| `ptp-forum-signin` | 对已配置站点执行论坛签到（开源市场版，支持通用 URL 签到模板）。 | v1.0.0 |
| `ptp-library-scrape` | 定时扫描媒体库目录，调用宿主媒体元数据 API（复用 PTPatronus 的 TMDB/豆瓣等源）补齐 Kodi... | v0.1.0 |
| `ptp-mcp-server` | MCP 相关配置与工具清单查看（完整 MCP HTTP 端点仍由宿主提供；本插件承接配置与可观测动作）。 | v1.0.0 |
| `ptp-miwifi` | 连接小米/红米路由器（含 AX9000/ra81 三频优化）：系统状态、设备、Wi-Fi、WAN/LAN/DHCP... | v0.2.2 |
| `ptp-playlet-category` | 扫描目录，按集数/命名规则将短剧移动到分类文件夹。 | v1.0.0 |
| `ptp-plex-suite` | 连接 Plex，刷新库/应用基础维护任务（开源市场版）。 | v1.0.0 |
| `text-toolbox` | 常用文本处理：统计、大小写、替换、分割、去重、哈希。 | v1.0.0 |
| `twofa-helper` | 基于 Base32 密钥生成 TOTP 验证码（迁移自 MoviePilot）。 | v1.2.7 |
| `webhook-transformer` | 监听 Webhook 事件，按映射规则提取字段并转发为通知或新事件。 | v1.0.0 |
| `xiaomi-router` | 登录小米路由器，查看状态并管理端口映射（开源市场版；完整增强见 ptp-miwifi）。 | v1.0.0 |

## 安装

1. PTPatronus → 插件页 → 添加市场源 → 填 `gntv456/ptpatronus-plugin-market`
2. 浏览列表 → 选插件 → 安装(管理员需批准其声明的权限)
3. 在插件配置页填各插件所需参数(扫描路径 / CD2 实例 / cron 等)

市场源经 `normalizeMarketSource` 自动解析为
`https://raw.githubusercontent.com/gntv456/ptpatronus-plugin-market/main/plugin-market.json`,
插件 zip 以相对路径 `archives/<id>-<ver>.zip` 指向同目录,安装时一并从 raw 拉取。

## 信任级

每个 entry 带 Ed25519 `signature`,顶层 `public_key` 校验。当前插件显示信任级 **signed**。
> 注:`publisher.verified` 字段是**自声明** UI 信号(无服务端可信发布者注册表),**不是**额外的密码学保证。密码学可信完全来自 signature ↔ public_key 的 Ed25519 校验。

## 仓库结构

```
plugins/<id>/         插件源码(plugin.json + plugin.py [+ web/])
archives/<id>-<ver>.zip   已签名 zip(提交进 git,数 KB)
packages/<id>.json    单插件签名元数据(aggregate 的输入)
keys/plugin-market.public.key   市场公钥(进 git,校验用)
tools/ptpatronus/     vendored pluginctl.py + schema(CI 依赖)
plugin-market.json    聚合后的市场索引(CI 自动生成/提交)
.github/workflows/
  aggregate.yml       packages/ 变动时重生成 index 并校验签名
  publish.yml         打 v* tag 时重新打包+签名+聚合(版本升级用)
```

## 升级官方插件

改 `plugins/<id>/plugin.json` 的 `version` → 提交 → 打 tag(如 `v0.2.0`)→ `publish.yml` 自动:
对每个插件 `pluginctl package --private-key $PTP_PLUGIN_MARKET_PRIVATE_KEY`(重签)→ `market aggregate` 重生成 `plugin-market.json` → 提交回 main。用户 App 下次刷新即见 `UpdateAvailable`。

> 首版(`v0.1.0`)的 archives/packages 是预先签名提交的,push 后立即可用,无需先跑 CI。

## 第三方作者接入(可选)

第三方插件可自带签名 zip(放你自己的 GitHub Release),把生成的 `plugin-package.json`(含绝对 `archive` URL + signature)以 PR 提交到本仓 `packages/`。`aggregate.yml` 的 metadata-only 模式会直接吸纳,相对路径与绝对 URL 在 index 内可共存。
