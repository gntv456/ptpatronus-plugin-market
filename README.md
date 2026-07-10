# PTPatronus Plugin Market

官方插件市场 for [PTPatronus](https://ptang.top)。用户在 App「插件」页填入本仓库地址即可浏览、安装、升级已签名的插件。

```
gntv456/ptpatronus-plugin-market
```

PTPatronus 主程序闭源,但插件平台是开放开发面。本仓库收录 **PTPatronus Community** 维护的官方插件,每个插件 zip 由市场私钥 Ed25519 签名,安装前由宿主校验签名与 sha256。

## 官方插件

| 插件 | 作用 | 依赖 |
|---|---|---|
| `ptp-cd2-assistant` | 定时检查 CloudDrive2 实例(上传错误/账号失效)+ 仪表盘(CPU/内存/任务/速度/容量) | 宿主 `pip install clouddrive`、真实 CD2 实例 |
| `ptp-ffmpeg-thumb` | 扫描媒体库,用 FFmpeg 为缺缩略图的视频截一帧 `<名>-thumb.jpg` | 宿主机 `ffmpeg` |
| `ptp-library-scrape` | 扫描媒体库,复用宿主 TMDB/豆瓣等源补齐 Kodi 兼容 nfo + 海报 | 无需自备 key(用宿主 media API) |

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
