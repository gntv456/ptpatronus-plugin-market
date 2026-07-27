# ptp-miwifi · 小米路由器助手

开源 PTPatronus 插件：连接小米/红米路由器管理后台（Luci Web API），查看并修改常用设置。

## 功能（v0.2.1）

- 登录路由器（管理密码，无需小米云账号）
- 系统状态：CPU / 内存 / 运行时长 / 在线数 / WAN
- 在线设备列表（IP / MAC / 上下行）
- 设备改名、限速、踢下线/恢复上网
- Wi-Fi 详情与修改（SSID / 密码 / 开关 / 信道等）
- WAN / LAN / DHCP / DNS 查看与配置
- MAC 过滤、**端口映射**（列表/添加/删除/启停）
- 系统时间、网络检测、重启、路由名称
- 交互式仪表盘 + 可选定时巡检关注设备

## 配置

| 项 | 说明 |
|---|---|
| base_url | 默认 http://192.168.31.1 |
| username | 默认 admin |
| password | 路由器后台密码（不是小米账号） |
| extra_routers | 可选多路由，每行 name#url#password |
| cron / watch_macs | 可选定时巡检与离线通知 |

## 常用 action

```text
ping
dashboard
devices {"online_only": true}
wifi_set {"wifi_index":1, "ssid":"Home", "password":"secret", "on":1}
device_authority {"mac":"aa:bb:cc:dd:ee:ff", "kick":true}
device_limit {"mac":"aa:bb:cc:dd:ee:ff", "maxdownload":1024, "maxupload":256}
dhcp_set {"start":"192.168.31.100", "end":"192.168.31.200"}
dns_set {"dns1":"223.5.5.5", "dns2":"119.29.29.29"}
port_forward {"op":"list"}
port_forward {"op":"add","name":"ssh","ip":"192.168.31.20","sport":2222,"dport":22,"protocol":"tcp"}
port_forward {"op":"delete","fwid":1}
port_forward {"op":"add","external_port":8080,"internal_port":80,"dest_ip":"192.168.31.30"}
reboot {"confirm": true}
```

## 兼容性

基于社区公开的经典 Luci API（`/cgi-bin/luci/;stok=.../api/...`），关键接口做多路径回退。

- 适用于多数小米/红米路由器旧版/经典 Web 管理页
- 部分新 UI / 云管固件接口不同时，对应 action 会返回明确错误
- 密码仅保存在宿主插件配置中

## 开发

```bash
python tools/ptpatronus/pluginctl.py validate plugins/ptp-miwifi
python tools/ptpatronus/pluginctl.py run plugins/ptp-miwifi --action ping --once
# 官方市场签名发布（需 PTP_PLUGIN_MARKET_PRIVATE_KEY）：
#  bump version -> git tag vX.Y.Z && git push origin vX.Y.Z
```

## License

MIT