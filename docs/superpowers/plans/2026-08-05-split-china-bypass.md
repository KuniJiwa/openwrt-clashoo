# Split China IP Bypass Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split mainland China IPv4 and IPv6 firewall bypass into independent controls without changing existing users' behavior on upgrade.

**Architecture:** Keep `bypass_china` as the IPv4 switch and add `bypass_china_ipv6` for IPv6. Runtime and LuCI reads fall back from the new IPv6 key to the legacy key, while both LuCI flags explicitly write `0/1`; nft rule generation receives the two resolved values independently.

**Tech Stack:** POSIX shell/BusyBox ash, nftables/fw4, OpenWrt UCI, LuCI JavaScript forms, gettext PO/POT, shell regression tests.

---

## Reference constraints

- OpenWrt-nikki commit `388f34e` confirms that global Mihomo IPv6, DNS IPv6, IPv6 proxying, IPv6 DNS hijack, and IPv4/IPv6 mainland bypass are separate controls.
- Follow Nikki's per-family bypass and `rmempty=false` pattern, but preserve Clashoo's current new-install default (`1/1`) and handle the valid legacy case where both bypass fields are absent.
- Do not modify `clashoo/files/usr/share/clashoo/runtime/mixin.uc` or split `enable_ipv6` in this implementation; that is a separate behavior change requiring its own design and tests.
- Do not add `SKIP_SYSTEM_IPV6_CHECK` or Nikki's DNS-hijack consistency checks here. The environment variable's Mihomo-side behavior is not yet verified, and Clashoo's existing core dry-run is different from Nikki's explicit `dns.enable`/`dns.listen` cross-setting validation.

---

### Task 1: Add a temporary failing regression test for legacy fallback

**Files:**
- Create temporarily: `/tmp/clashoo-china-bypass-test.sh`
- Read: `clashoo/files/usr/share/clashoo/net/fw4.sh:1-850`

The test script is execution-only evidence. It must remain outside the repository, must not be staged, and must not be committed; the repository preflight intentionally rejects new `test_*.sh` files.

- [ ] **Step 1: Create the shell regression test**

Create `/tmp/clashoo-china-bypass-test.sh` with this complete content:

```sh
#!/bin/sh
set -eu

REPO_DIR="${REPO_DIR:-$(pwd)}"
FW4_SH="$REPO_DIR/clashoo/files/usr/share/clashoo/net/fw4.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

# Source function definitions without executing fw4.sh's command dispatcher.
awk '$0 == "case \"${1:-}\" in" { exit } { print }' "$FW4_SH" > "$TMP_DIR/fw4-lib.sh"
. "$TMP_DIR/fw4-lib.sh"

TEST_BYPASS_V4="__unset__"
TEST_BYPASS_V6="__unset__"

uci_get() {
	case "$1" in
		clashoo.config.bypass_china)
			[ "$TEST_BYPASS_V4" = "__unset__" ] || printf '%s\n' "$TEST_BYPASS_V4"
			;;
		clashoo.config.bypass_china_ipv6)
			[ "$TEST_BYPASS_V6" = "__unset__" ] || printf '%s\n' "$TEST_BYPASS_V6"
			;;
	esac
	return 0
}

assert_equal() {
	label="$1"
	expected="$2"
	actual="$3"
	if [ "$actual" != "$expected" ]; then
		printf 'FAIL %s: expected <%s>, got <%s>\n' "$label" "$expected" "$actual" >&2
		exit 1
	fi
}

assert_values() {
	label="$1"
	TEST_BYPASS_V4="$2"
	TEST_BYPASS_V6="$3"
	expected_v4="$4"
	expected_v6="$5"

	resolved_v4="$(config_bypass_china)"
	resolved_v6="$(config_bypass_china_ipv6)"
	assert_equal "$label v4" "$expected_v4" "$resolved_v4"
	assert_equal "$label v6" "$expected_v6" "$resolved_v6"
}

assert_values 'both missing'   '__unset__' '__unset__' '' ''
assert_values 'legacy enabled' 1           '__unset__' 1  1
assert_values 'legacy disabled' 0          '__unset__' 0  0
assert_values 'explicit v6 off' 1          0           1  0
assert_values 'explicit v6 on'  0          1           0  1

printf 'PASS china bypass fallback\n'
```

- [ ] **Step 2: Make the test executable**

Run:

```sh
chmod +x /tmp/clashoo-china-bypass-test.sh
```

- [ ] **Step 3: Run the test and confirm it fails before implementation**

Run:

```sh
REPO_DIR="$(pwd)" sh /tmp/clashoo-china-bypass-test.sh
```

Expected: non-zero exit with `config_bypass_china_ipv6: not found`.

---

### Task 2: Implement independent backend switches and update reload behavior

**Files:**
- Modify: `clashoo/files/etc/config/clashoo:62-63`
- Modify: `clashoo/files/usr/share/clashoo/net/fw4.sh:154-160`
- Modify: `clashoo/files/usr/share/clashoo/net/fw4.sh:635-755`
- Modify: `clashoo/files/usr/share/clashoo/update/update_china_ip.sh:80-126`
- Modify: `clashoo/Makefile:5-9`
- Test temporarily: `/tmp/clashoo-china-bypass-test.sh`

- [ ] **Step 1: Add the explicit IPv6 default for new installations**

In `clashoo/files/etc/config/clashoo`, keep the legacy IPv4 key and add the new IPv6 key:

```uci
	option bypass_china '1'
	option bypass_china_ipv6 '1'
```

- [ ] **Step 2: Add the runtime fallback reader**

Immediately after `config_bypass_china()` in `fw4.sh`, add:

```sh
config_bypass_china_ipv6() {
	local value
	value="$(uci_get clashoo.config.bypass_china_ipv6)"
	if [ -n "$value" ]; then
		printf '%s\n' "$value"
	else
		config_bypass_china
	fi
}
```

- [ ] **Step 3: Resolve both values once during rule generation**

Extend `generate_rules()` so its local variables and assignments include IPv6:

```sh
local bypass_china bypass_china_ipv6
```

```sh
bypass_china="$(config_bypass_china)"
bypass_china_ipv6="$(config_bypass_china_ipv6)"
```

Do not change `apply_local_output_rule()` or `apply_block_quic_rule()` beyond confirming that both continue to call `config_bypass_china()` for their IPv4-only tables.

- [ ] **Step 4: Split the redirect pair without changing its rule text**

Keep the existing two nft statements and change only their controlling values:

```sh
$( bool_enabled "$bypass_china_ipv6" && printf '%s\n' 'ip6 daddr @clashoo_china6 return' )
$( bool_enabled "$bypass_china" && printf '%s\n' 'ip daddr @clashoo_china return' )
```

- [ ] **Step 5: Split the mangle branch without changing its rule text**

Replace the single `if bool_enabled "$bypass_china"` block that prints both families with:

```sh
if bool_enabled "$bypass_china_ipv6"; then
	printf 'meta nfproto ipv6 ip6 daddr @clashoo_china6 return\n'
fi
if bool_enabled "$bypass_china"; then
	printf 'ip daddr @clashoo_china return\n'
fi
```

This is the critical replacement for the existing combined block around lines 746-749.

- [ ] **Step 6: Make the whitelist updater fall back and reload when either family is enabled**

Add this helper near the top of `update_china_ip.sh` with the other functions:

```sh
bool_enabled() {
	case "$1" in
		1|true|TRUE|yes|on) return 0 ;;
		*) return 1 ;;
	esac
}
```

Read both values after the URLs:

```sh
bypass_china="$(uci -q get clashoo.config.bypass_china 2>/dev/null || true)"
bypass_china_ipv6="$(uci -q get clashoo.config.bypass_china_ipv6 2>/dev/null || true)"
[ -n "$bypass_china_ipv6" ] || bypass_china_ipv6="$bypass_china"
```

Replace the final `case "$bypass_china"` with:

```sh
if bool_enabled "$bypass_china" || bool_enabled "$bypass_china_ipv6"; then
	if /usr/share/clashoo/net/fw4.sh apply >/dev/null 2>&1; then
		log "大陆白名单规则已重载（IPv4=${bypass_china:-0}，IPv6=${bypass_china_ipv6:-0}）"
	else
		log '大陆白名单规则重载失败'
		exit 1
	fi
else
	log '大陆 IPv4/IPv6 绕过均未启用，仅更新白名单文件'
fi
```

- [ ] **Step 7: Bump the Clashoo package release**

In `clashoo/Makefile`, change:

```make
PKG_RELEASE:=2
```

to:

```make
PKG_RELEASE:=3
```

The resulting package version must be `2026.08.05~a939fc1-r3`.

- [ ] **Step 8: Run backend tests and syntax checks**

Run:

```sh
REPO_DIR="$(pwd)" sh /tmp/clashoo-china-bypass-test.sh
sh -n clashoo/files/usr/share/clashoo/net/fw4.sh
sh -n clashoo/files/usr/share/clashoo/update/update_china_ip.sh
git diff --check
```

Expected: the regression test prints `PASS china bypass fallback and rule matrix`; all remaining commands exit `0` with no output.

- [ ] **Step 9: Commit the backend change**

Run:

```sh
git add \
  clashoo/files/etc/config/clashoo \
  clashoo/files/usr/share/clashoo/net/fw4.sh \
  clashoo/files/usr/share/clashoo/update/update_china_ip.sh \
  clashoo/Makefile
/Users/kenzo/kenzo-app/.claude/skills/ship-pkg/preflight.sh
git commit -m "Split China IP bypass by address family" \
  -m $'改动：拆分大陆 IPv4/IPv6 绕过规则并兼容旧配置，clashoo bump 到 2026.08.05~a939fc1-r3。\n\n原因：允许大陆 IPv4 进入代理的同时保留大陆 IPv6 原生直连。'
```

---

### Task 3: Add independent LuCI controls with safe missing-value behavior

**Files:**
- Modify: `luci-app-clashoo/htdocs/luci-static/resources/view/clashoo/system.js:1004-1015`
- Modify: `luci-app-clashoo/po/zh-cn/clashoo.po:207-211`
- Modify: `luci-app-clashoo/po/templates/clashoo.pot:200-204`
- Modify: `luci-app-clashoo/Makefile:3-6`

- [ ] **Step 1: Replace the single Flag with two explicit controls**

Replace the existing `bypass_china` Flag in `system.js` with:

```javascript
    o = s.option(form.Flag, 'bypass_china', _('Bypass China IPv4'));
    o.default = '0';
    o.rmempty = false;

    o = s.option(form.Flag, 'bypass_china_ipv6', _('Bypass China IPv6'));
    o.default = '0';
    o.rmempty = false;
    o.cfgvalue = function (section_id) {
      var value = uci.get('clashoo', section_id, 'bypass_china_ipv6');
      return (value != null) ? value : uci.get('clashoo', section_id, 'bypass_china');
    };
```

The missing/missing case intentionally returns `null`, so the widget uses `default='0'` and displays disabled.

- [ ] **Step 2: Replace the old translation entry with two entries**

In `luci-app-clashoo/po/zh-cn/clashoo.po`, replace the old entry with:

```po
msgid "Bypass China IPv4"
msgstr "大陆 IPv4 绕过"

msgid "Bypass China IPv6"
msgstr "大陆 IPv6 绕过"
```

In `luci-app-clashoo/po/templates/clashoo.pot`, replace it with:

```po
msgid "Bypass China IPv4"
msgstr ""

msgid "Bypass China IPv6"
msgstr ""
```

- [ ] **Step 3: Bump the LuCI package version**

In `luci-app-clashoo/Makefile`, set:

```make
PKG_VERSION:=1.30.0
PKG_RELEASE:=1
```

- [ ] **Step 4: Run LuCI static checks**

Run:

```sh
node --check luci-app-clashoo/htdocs/luci-static/resources/view/clashoo/system.js
rg -n 'Bypass China IPv(4|6)|大陆 IPv(4|6) 绕过' \
  luci-app-clashoo/htdocs/luci-static/resources/view/clashoo/system.js \
  luci-app-clashoo/po/zh-cn/clashoo.po \
  luci-app-clashoo/po/templates/clashoo.pot
git diff --check
```

Expected: `node --check` and `git diff --check` exit `0`; the search shows both IPv4 and IPv6 entries in JS, PO and POT.

- [ ] **Step 5: Commit the LuCI change**

Run:

```sh
git add \
  luci-app-clashoo/htdocs/luci-static/resources/view/clashoo/system.js \
  luci-app-clashoo/po/zh-cn/clashoo.po \
  luci-app-clashoo/po/templates/clashoo.pot \
  luci-app-clashoo/Makefile
git commit -m "Add IPv6 China bypass control" \
  -m $'改动：新增独立的大陆 IPv4/IPv6 绕过开关并保证缺失配置安全显示，luci-app-clashoo bump 到 1.30.0-r1。\n\n原因：避免保存旧配置时重新开启绕过，并支持分别控制两种地址族。'
```

---

### Task 4: Update maintainer documentation

**Files:**
- Modify: `.github/skills/clashoo-user-guide/SKILL.md:177`

- [ ] **Step 1: Replace the outdated single-switch description**

Change the China IP portion of the bypass paragraph to state:

```markdown
中国 IP（`bypass_china=1` 控制 IPv4 `geoip_cn.nft`，`bypass_china_ipv6=1` 控制 IPv6 `geoip6_cn.nft`；IPv6 字段缺失时回退旧 `bypass_china`）
```

Keep the remainder of the paragraph unchanged.

- [ ] **Step 2: Verify all production references use the intended semantics**

Run:

```sh
rg -n 'bypass_china' clashoo luci-app-clashoo .github/skills/clashoo-user-guide/SKILL.md \
  --glob '!*.po' --glob '!*.pot'
```

Expected:

- `apply_local_output_rule()` and `apply_block_quic_rule()` still use only `config_bypass_china()`.
- redirect and mangle rule generation resolve both switches.
- `update_china_ip.sh` resolves both switches.
- LuCI exposes both fields.
- the Skill documents both fields.
- `luci.clashoo` still has no references and remains unchanged.

- [ ] **Step 3: Commit the documentation update**

Run:

```sh
git add .github/skills/clashoo-user-guide/SKILL.md
git commit -m "Document per-family China bypass" \
  -m $'改动：更新 Clashoo 指南中的大陆 IPv4/IPv6 绕过字段与兼容语义。\n\n原因：避免维护和排障时继续按旧单开关行为判断。'
```

---

### Task 5: Run repository-level verification

**Files:**
- Verify: all files modified in Tasks 1-4

- [ ] **Step 1: Run all targeted checks from a clean shell**

Run:

```sh
REPO_DIR="$(pwd)" sh /tmp/clashoo-china-bypass-test.sh
sh -n clashoo/files/usr/share/clashoo/net/fw4.sh
sh -n clashoo/files/usr/share/clashoo/update/update_china_ip.sh
node --check luci-app-clashoo/htdocs/luci-static/resources/view/clashoo/system.js
git diff --check
git status --short --branch
```

Expected: the regression test prints `PASS`; syntax and whitespace checks exit `0`; the branch is ahead of `origin/main` with no uncommitted files.

- [ ] **Step 2: Confirm package versions from the final files**

Run:

```sh
sed -n '/^PKG_VERSION\|^PKG_RELEASE/p' clashoo/Makefile
sed -n '/^PKG_VERSION\|^PKG_RELEASE/p' luci-app-clashoo/Makefile
```

Expected:

```text
PKG_VERSION:=$(PKG_COMMIT_DATE)~$(PKG_SHORT_SHA)
PKG_RELEASE:=3
PKG_VERSION:=1.30.0
PKG_RELEASE:=1
```

- [ ] **Step 3: Review the exact diff against the last published commit**

Run:

```sh
git diff --stat origin/main..HEAD
git diff origin/main..HEAD -- \
  clashoo/files/etc/config/clashoo \
  clashoo/files/usr/share/clashoo/net/fw4.sh \
  clashoo/files/usr/share/clashoo/update/update_china_ip.sh \
  luci-app-clashoo/htdocs/luci-static/resources/view/clashoo/system.js \
  luci-app-clashoo/po/zh-cn/clashoo.po \
  luci-app-clashoo/po/templates/clashoo.pot \
  .github/skills/clashoo-user-guide/SKILL.md \
  clashoo/Makefile \
  luci-app-clashoo/Makefile
```

Expected: only the local IPv6 policy-routing commit, the approved design/plan documents, and the scoped per-family bypass changes appear; no unrelated source changes.

Also confirm that `clashoo/files/usr/share/clashoo/runtime/mixin.uc` is absent from the diff.

- [ ] **Step 4: Remove the temporary regression script after recording the result**

Run:

```sh
trash /tmp/clashoo-china-bypass-test.sh
```

Expected: the temporary test is removed without adding any repository file.

---

### Task 6: Validate UCI, LuCI and nft output on test router 252

**Files:**
- Deploy temporarily: `clashoo/files/usr/share/clashoo/net/fw4.sh`
- Deploy temporarily: `clashoo/files/usr/share/clashoo/update/update_china_ip.sh`
- Deploy temporarily: `luci-app-clashoo/htdocs/luci-static/resources/view/clashoo/system.js`

- [ ] **Step 1: Read `openwrt-router-lab` and confirm 252 starts inactive**

Run the router-lab checklist, then verify:

```sh
ssh -p 9167 root@192.168.3.252 \
  'uci -q get clashoo.config.enable; /etc/init.d/clashoo status; pidof mihomo clash-meta || true'
```

Expected: `enable=0`, service `inactive`, and no core PID.

- [ ] **Step 2: Back up only the files and UCI config in scope**

On 252, create `/tmp/clashoo-bypass-test` and copy:

```text
/etc/config/clashoo
/usr/share/clashoo/net/fw4.sh
/usr/share/clashoo/update/update_china_ip.sh
/www/luci-static/resources/view/clashoo/system.js
```

Do not copy subscription files, runtime YAML, passwords or dashboard credentials.

- [ ] **Step 3: Upload to a temporary directory and install only the test files**

Upload the three changed runtime/UI files into `/tmp/clashoo-bypass-test/new/`, then copy them into their exact destination paths. Preserve executable mode on both shell scripts. Clear LuCI caches without restarting unrelated services:

```sh
rm -rf /tmp/luci-indexcache /tmp/luci-indexcache.* /tmp/luci-modulecache
```

- [ ] **Step 4: Verify the three legacy/missing UI states**

Use the LuCI page and SSH together:

1. Set `bypass_china=1`, delete `bypass_china_ipv6`, reload the page: both flags must show enabled.
2. Set `bypass_china=0`, delete `bypass_china_ipv6`, reload the page: both flags must show disabled.
3. Delete both fields, reload the page: both flags must show disabled. Click Save; then both commands must print `0`:

```sh
uci -q get clashoo.config.bypass_china
uci -q get clashoo.config.bypass_china_ipv6
```

Use the configured browser automation skill for the LuCI interaction; do not infer UI state from UCI alone.

- [ ] **Step 5: Verify four nft rule combinations in redirect and TPROXY modes**

For each pair `1/1`, `0/1`, `1/0`, `0/0`:

1. Set and commit both UCI values.
2. Set `tcp_mode=redirect`, run `/usr/share/clashoo/net/fw4.sh apply`, inspect `/var/run/clash/fw4_dstnat.nft`.
3. Set `tcp_mode=tproxy` and `udp_mode=tproxy`, apply again, inspect `/var/run/clash/fw4_mangle.nft`.
4. Confirm the presence or absence of these exact lines:

```nft
ip daddr @clashoo_china return
meta nfproto ipv6 ip6 daddr @clashoo_china6 return
```

Expected matrix:

```text
1/1: v4 present, v6 present
0/1: v4 absent,  v6 present
1/0: v4 present, v6 absent
0/0: v4 absent,  v6 absent
```

- [ ] **Step 6: Restore 252 and prove Clashoo is stopped**

Restore the four backed-up files and `/etc/config/clashoo`, then run:

```sh
uci set clashoo.config.enable='0'
uci commit clashoo
/etc/init.d/clashoo stop
/etc/init.d/clashoo status
pidof mihomo clash-meta || true
```

Expected: service `inactive` and no core PID. If the stop command reports an absent ubus service after already stopping, verify status and PID rather than treating that message alone as failure.

---

### Task 7: Hand off the end-to-end IPv6 test to Issue #41

**Files:**
- No repository changes

- [ ] **Step 1: Prepare the maintainer reply only after local and 252 checks pass**

The reply must state:

- the two switches are now independent;
- test with mainland IPv4 bypass disabled and mainland IPv6 bypass enabled;
- 252 verified rule generation but cannot verify public IPv6 because it has no GUA/default IPv6 route;
- the reporter should confirm both device GUA visibility and game stability;
- reappearance of game drops would indicate the affected game path may involve IPv6.

- [ ] **Step 2: Do not publish until explicitly approved**

Before any push, run `gh auth status`, present the final commits, package versions, verification evidence and 252 cleanup status to Kenzo. Push only after explicit approval.
