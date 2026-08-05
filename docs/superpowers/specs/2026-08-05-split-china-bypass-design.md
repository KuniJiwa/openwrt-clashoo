# Split China IP Bypass Design

## 背景

现有 `bypass_china` 同时控制大陆 IPv4 与 IPv6 目的地址的防火墙直连。Issue #41 的用户需要关闭大陆 IPv4 绕过，让游戏连接统一进入 Mihomo，同时保留大陆 IPv6 原生直连，使目标网站继续看到终端自己的 GUA。

单一开关无法独立表达这组需求，因此需要把大陆 IPv4、IPv6 绕过拆开，同时保证已有安装升级后行为不变。

## 目标

- 保留 `bypass_china`，将其明确为大陆 IPv4 绕过开关。
- 新增 `bypass_china_ipv6`，独立控制大陆 IPv6 绕过。
- 新字段缺失时回退读取 `bypass_china`，保证旧配置升级后 v4/v6 行为不变。
- LuCI 必须明确保存 `0/1`，避免关闭状态被删除后错误回退到旧值。
- 支持用户组合：IPv4 绕过关闭、IPv6 绕过开启。

## 非目标

- 不改变 `ipv4_proxy`、`ipv6_proxy` 或 IPv4/IPv6 DNS 劫持语义。
- 不在本次拆分 Clashoo 现有 `enable_ipv6` 对 Mihomo 全局 `ipv6` 与 `dns.ipv6` 的共同控制；该设计问题单独评估和测试。
- 不为路由器本机新增 IPv6 local-output 透明代理规则。
- 不扩大 QUIC 绕过逻辑到 IPv6。
- 不在本次修改中判断游戏掉线最终发生在 IPv4 还是 IPv6；该结论由用户使用新组合实测。
- 不把本地 `Add IPv6 policy routing for TPROXY` 提交并入本次功能提交。

## Nikki 对照结论

对照 OpenWrt-nikki `388f34e` 后确认：

- Mihomo 全局 `ipv6` 与 `dns.ipv6` 分别由 `nikki.mixin.ipv6`、`nikki.mixin.dns_ipv6` 控制，默认均为 `1`。
- `ipv4_proxy`、`ipv6_proxy`、`ipv4_dns_hijack`、`ipv6_dns_hijack` 是四个独立开关。
- 大陆 IPv4、IPv6 绕过分别使用 `bypass_china_mainland_ip`、`bypass_china_mainland_ip6`，LuCI 两个 Flag 均设置 `rmempty=false`。
- Nikki 为旧配置执行一次迁移：IPv6 绕过字段缺失时，把旧 IPv4 绕过值写入 IPv6 字段。

本设计采用相同的协议拆分与明确写值原则，但不直接照搬默认值和一次性迁移：Clashoo 需要保持现有新装默认开启绕过；同时 Issue #41 已证明旧 `bypass_china` 可能因 LuCI 关闭操作而完全缺失，因此运行时与 LuCI 读取回退比假设旧字段必然存在的迁移更安全。

### 后续单独评估的 IPv6 配置差异

以下差异与本次大陆绕过拆分有关联，但影响整个 Mihomo 配置生成与启动流程，不合并处理：

- Nikki 的 `uci_bool()` 在 UCI 字段缺失时返回 `null`，后续清理空值后不写对应 YAML 字段；Clashoo 的 `b()` 将缺失值视为 `false`，因此会显式生成 `ipv6: false` 和 `dns.ipv6: false`。
- 两者都让后合并的 mixin 覆盖原始配置。差别在于 Nikki 未设置时不写字段，可保留用户 YAML；Clashoo 会用显式 `false` 覆盖用户 YAML 中的 `ipv6: true`。若调整此行为，需要单独验证升级兼容、LuCI 表示和最终生成配置。
- Nikki 默认同时开启全局 IPv6、DNS IPv6 与 IPv6 代理；Clashoo 当前前两项由 `enable_ipv6` 共同控制且默认关闭，而 `ipv6_proxy` 默认开启。是否拆分或增加一致性提示另行设计。
- Nikki 向 Mihomo 传入 `SKIP_SYSTEM_IPV6_CHECK`，但仅凭 Nikki 代码不能确认 Mihomo 对该变量的完整行为，暂不据此修改 Clashoo。
- Nikki 在 DNS 劫持启用时显式校验生成配置中的 `dns.enable` 与 `dns.listen`。Clashoo 已有 Mihomo 配置 dry-run 预检，但没有这项跨设置的一致性校验；若补充，应作为独立改动。

## 配置设计

| UCI 字段 | 语义 | 新安装默认值 | 升级兼容 |
|---|---|---:|---|
| `bypass_china` | 大陆 IPv4 绕过 | `1` | 继续使用原字段 |
| `bypass_china_ipv6` | 大陆 IPv6 绕过 | `1` | 缺失时回退到 `bypass_china` |

运行时提供两个读取函数：

- `config_bypass_china()`：读取 `clashoo.config.bypass_china`，仅用于 IPv4。
- `config_bypass_china_ipv6()`：优先读取 `clashoo.config.bypass_china_ipv6`；字段缺失时读取 `config_bypass_china()`。

不增加第三个迁移字段，也不强制修改旧用户 UCI。用户第一次在 LuCI 保存后，新 IPv6 字段会被明确写入。

## LuCI 行为

「系统 → 绕过规则」显示两个 Flag：

- 大陆 IPv4 绕过：绑定 `bypass_china`。
- 大陆 IPv6 绕过：绑定 `bypass_china_ipv6`，读取不到时回退显示 `bypass_china`。

两个 Flag 均设置：

```javascript
o.default = '0';
o.rmempty = false;
```

新安装的配置文件会显式写入两个 `1`，不受界面默认值影响。旧配置字段缺失时，LuCI 显示关闭，与 Shell 的 `bool_enabled "" → false` 保持一致；保存后会明确写入 `0/0`，不会因打开页面并保存而静默开启大陆绕过。IPv6 Flag 还需要自定义 `cfgvalue()`：新字段存在时返回新值，新字段缺失但旧字段存在时回退显示旧值，两个字段均缺失时返回 `null` 并使用默认值 `0`。该回退只改变读取，不改变写入目标。

## 防火墙行为

### redirect 主链

- `ip daddr @clashoo_china return` 只由 `bypass_china` 控制。
- `meta nfproto ipv6 ip6 daddr @clashoo_china6 return` 只由 `bypass_china_ipv6` 控制。

### TPROXY / TUN ACL mangle 分支

现有同一个 `if` 同时输出 v4/v6 两条 return，改成两个独立判断，分别生成对应协议规则。

### local output 与 QUIC

`apply_local_output_rule()` 使用 `table ip`，`apply_block_quic_rule()` 当前也只装载 IPv4 中国地址集合。两者继续读取 `bypass_china`，不新增 IPv6 行为。

### 规则组合

| IPv4 | IPv6 | 预期中国地址 return |
|---:|---:|---|
| `1` | `1` | 同时生成 v4、v6 |
| `0` | `1` | 只生成 v6 |
| `1` | `0` | 只生成 v4 |
| `0` | `0` | 两者都不生成 |

## 白名单更新

`update_china_ip.sh` 继续下载和更新两套地址文件，不因开关关闭而停止更新。

更新完成后：

- 任一开关开启：重新应用防火墙规则。
- 两个开关均关闭：只更新白名单文件，不重新加载绕过规则。

日志改为同时表达 v4/v6 状态，不能继续写死“`bypass_china` 未启用”。

## 文件范围

### clashoo 包

- `clashoo/files/etc/config/clashoo`
- `clashoo/files/usr/share/clashoo/net/fw4.sh`
- `clashoo/files/usr/share/clashoo/update/update_china_ip.sh`
- `clashoo/Makefile`

### luci-app-clashoo

- `luci-app-clashoo/htdocs/luci-static/resources/view/clashoo/system.js`
- `luci-app-clashoo/po/zh-cn/clashoo.po`
- `luci-app-clashoo/po/templates/clashoo.pot`
- `luci-app-clashoo/Makefile`

### 文档与测试

- `.github/skills/clashoo-user-guide/SKILL.md`
- 新增针对配置回退、LuCI 保存语义和 nft 规则组合的测试脚本或等价验证入口。

`luci-app-clashoo/root/usr/share/rpcd/ucode/luci.clashoo` 没有引用 `bypass_china`，不修改。

## 验证设计

### 静态检查

- `sh -n` 检查 `fw4.sh` 与 `update_china_ip.sh`。
- `node --check` 检查 `system.js`。
- 检查中英文翻译条目和模板条目同步。

### 兼容检查

- 只有旧 `bypass_china=1`：LuCI 两个开关均显示开启，运行规则同时包含 v4/v6。
- 只有旧 `bypass_china=0`：LuCI 两个开关均显示关闭，运行规则不包含 v4/v6 中国地址 return。
- `bypass_china` 与 `bypass_china_ipv6` 均不存在：LuCI 两个开关均显示关闭，运行规则不包含 v4/v6 中国地址 return；保存后明确写入 `0/0`。
- LuCI 保存 IPv4/IPv6 开启后，UCI 值均为 `1`。
- LuCI 保存 IPv4/IPv6 关闭后，UCI 值均为 `0`，不能为空。
- 第一次保存后生成明确的 `bypass_china_ipv6`，后续运行不再依赖旧值回退。

### 规则检查

在 redirect 与 TPROXY 模式分别验证四种 v4/v6 组合，检查生成的 `fw4_dstnat.nft` 与 `fw4_mangle.nft`。

### 252 验证边界

252 可验证 UCI、LuCI 保存结果和 nft 规则生成。252 没有公网 IPv6 及 IPv6 默认路由，不能验证目标网站是否看到终端 GUA。最终端到端 IPv6 效果由 Issue #41 用户安装测试包后验证。

测试结束必须恢复临时文件和配置，设置 `clashoo.config.enable=0`，停止 Clashoo 并确认服务 inactive。

## 版本与提交

- 保留本地 `Add IPv6 policy routing for TPROXY` 独立提交。
- `clashoo` 从本地 `2026.08.05~a939fc1-r2` bump 到 `r3`。
- `luci-app-clashoo` bump 到 `1.30.0-r1`。
- 功能实现使用独立提交，不 amend IPv6 策略路由提交。
- 未经确认不 push。

## 成功标准

- 旧用户升级后默认行为不变。
- 新旧配置在 LuCI 显示与运行行为一致。
- IPv4、IPv6 大陆绕过可独立控制。
- `IPv4=0 / IPv6=1` 时，生成规则只放行大陆 IPv6。
- 所有静态检查和 252 规则验证通过，252 测试后 Clashoo 保持停止状态。
