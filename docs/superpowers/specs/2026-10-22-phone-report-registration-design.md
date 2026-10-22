# Phone Report & Phone Registration — Design Spec

**Date:** 2026-10-22
**Status:** Draft for owner review
**Plugin id:** `phone_report`
**Part of:** Image Anarchy v4.0. This is project 1 of 3 (Phone Report → Remote Repair Session → Fixer Marketplace).

## 1. Why this exists

Image Anarchy v4.0's goal is to let two people fix a phone together: an **owner** with a broken or
misbehaving phone, and a **fixer** with the skills, possibly earning some income for it. Before
anyone touches a phone, three things must be true:

1. **Everyone knows exactly what the phone is and what state it's in.** Most "made it worse"
   outcomes come from flashing the wrong thing, on a low battery, onto a phone with anti-rollback,
   or without a backup. The owner can't be expected to know any of that, so the report must
   gather it **automatically**.
2. **The person asking for help owns the phone.** This is the #1 rule of the whole service.
3. **There's a record of the phone's state before work starts,** so the state afterward can be
   compared to it objectively.

This project builds those three things. It is useful by itself right away: owners can diagnose
their own phones. It is also the foundation the Remote Repair Session and the Fixer Marketplace
build on.

**Phone Registration** makes ownership verification something owners *want* to do: "register your
phone while it's healthy, and if it ever breaks, help is unlocked." Registered phones unlock gated
features (Patch Modem now, TCL firmware downloads later), can be marked lost, and get an ownership
proof packet the owner can take to Google, the manufacturer, or their carrier.

## 2. Goals, non-goals, anti-goals

**Goals**
- One click: plug in the phone and get a complete report in any mode (Android, recovery, fastboot,
  Qualcomm EDL, MediaTek BROM/preloader, or "nothing detected"). No manual setup beyond drivers.
- Risk flags in plain language that **block** dangerous operations until acknowledged.
- A redacted, shareable report, plus a before/after comparison function.
- Phone registration with a possession check, stolen-phone check, lost-phone registry, transfer,
  and a server-signed ownership proof packet.
- Gate Patch Modem behind a registered phone and a same-device match.

**Non-goals (this project)**
- Remote sessions, screen sharing, and the marketplace (projects 2 and 3).
- The TCL firmware plugin itself. This project only provides the verification API it will use.
- iOS.
- Fixing anything. The report is diagnosis only.

**Anti-goals (failure even if it "works")**
- The report **changes the phone** in any way. It must be strictly read-only (see §4).
- The report reboots or bricks a phone. LG reboots on `fastboot getvar all`, and loader-less EDL
  probes can wedge the PBL. The report must never trigger either.
- Raw IMEIs or serials stored on the server or shared without the owner choosing to.
- Any path that helps someone keep a phone that isn't theirs. **No FRP removal, ever, registered
  or not** (owner decision, see `ACCEPTABLE_USE_POLICY.md` "Hard Lines").
- Pretending a client-side gate is security. Only gates the server enforces count as real; §8
  says which are which.

## 3. What already exists (build on it)

| Need | Existing code |
|---|---|
| OEM-unlock state, `ro.frp.pst`, verified boot | `plugins/adb_toolkit/plugin.py` `_get_oem_state()` |
| LG-safe fastboot vars | `plugins/fastboot_toolkit/plugin.py` `_get_device_info()` (`lg_safe` var list) |
| EDL identity (serial, HWID, PK hash, secure boot) without a loader | `plugins/qualcomm_edl_toolkit/qedl_ident.py` + `ident.parse_ident_json()` |
| EDL loader availability | `loader_manager.match(loaders, hwid, pkhash)` |
| MTK security config (SBC/SLA/DAA), IMEI read, GPT | `plugins/mtk_toolkit/plugin.py` `get_target_config()`, `read_imei()`, `get_gpt()` |
| Plugin lookup from core | `PluginManager.get_plugin()` / `load_plugin()` in `image_anarchy.py` |
| Accounts | `plugin_store/server.js`: Express + MySQL `users`, bcrypt, JWT (`/api/auth/register`, `/api/auth/login`) |
| FRP write guards | the `_frp_blocked()` guard in each toolkit (PR #4) |
| Cross-platform tool lookup | `_is_runnable()` pattern (PR #3) |

## 4. Hard constraints

1. **Read-only.**
   - adb: `getprop`, `settings get`, `dumpsys` (battery, account, diskstats), and reading logs only.
   - fastboot: always use the **LG-safe individual `getvar` list**, never `getvar all`.
   - EDL: Sahara identification only. **No loader upload** during a report.
   - MTK: BROM/preloader handshake info and target config only. **No DA upload** during a basic
     report. Reading the IMEI needs the DA, so it happens only inside the registration match flow
     (§7.4), never in a basic report.
   - Nothing is written, erased, or rebooted. A probe that cannot avoid side effects is left out.
2. **Plugins stay self-contained.** Store plugins update independently, so `phone_report` must work
   when a toolkit is missing or outdated. It says "Install/update MTK Toolkit for MediaTek details"
   instead of failing.
3. **Cross-platform.** Windows and Linux are first class, macOS best-effort. Use the `_is_runnable()`
   finder pattern and never assume `.exe`.
4. **Privacy.**
   - The server never stores raw IMEIs or serials; see §7.2 for the hashing.
   - Shared or exported reports show the IMEI and serial redacted to their last 4 digits, unless
     the owner explicitly unchecks redaction.
5. **Branding.** Follow the CLAUDE.md anarchy tone for labels and status text ("Breaking free…",
   "Freedom achieved!"), but warnings and risk text stay **plain and serious**.

## 5. Phase 0: put the server under version control (prerequisite)

`plugin_store/server.js` (~6,700 lines) and `temp_relay_server.js` live only on the owner's machine.
Registration needs server endpoints, so the server must go into the repo first.

- **Secrets:** `server.js` currently has **hardcoded fallback values for secrets** (JWT secret,
  MySQL/Redis passwords, Stripe keys, mail password, Cloudflare Access credentials, `APP_SECRET`).
  Before committing:
  - Replace every `process.env.X || '<literal>'` with env-only reads, failing fast on missing
    required secrets.
  - Add `plugin_store/.env.example` listing the variables, with no values.
  - Make sure `.env` is gitignored.
- **Verification:** confirm the deployed server matches the local copy before committing. The
  aaPanel listing came back empty in this session, so this is unverified.
- **Rotation:** owner decides whether to rotate the secrets. They were never committed, so
  rotation is precautionary.
- **Placement (owner decision):** commit to `plugin_store/` in this **public** repo. Going public
  means the server's code holds no secrets and protects nothing by obscurity:
  - Rate limits, bans, and admin checks must hold up with the code visible.
  - The client `APP_SECRET` HMAC signature only identifies the app; it doesn't secure anything,
    since it was always extractable from the client.
- **Pip installs and user data:** auth tokens (`plugin_store_auth.json`) and other user data are
  written to `get_app_dir()`, which is site-packages for pip installs and often read-only on
  Linux. Move user data to the per-user config directory (`%APPDATA%\ImageAnarchy`,
  `~/.config/image-anarchy`), migrating any existing file.

## 6. The Phone Report

### 6.1 Mode detection

1. **USB scan:** enumerate USB devices at the OS level, without libusb, because drivers vary.
   - Windows: PnP query.
   - Linux: `/sys/bus/usb/devices/*/idVendor|idProduct`.
   - Known signatures: Qualcomm EDL `05C6:9008`, MediaTek BROM `0E8D:0003`, MediaTek
     preloader `0E8D:2000`, MediaTek DA/other `0E8D:*`.
2. **Tool checks:** `adb devices -l` gives device, recovery, sideload or unauthorized. `fastboot
   devices` gives fastboot or fastbootd.
3. **Nothing found:** show a guided "get your phone into a mode" helper with button combos per
   brand. Report the USB scan results so a missing driver is obvious (for example, "a MediaTek
   device appeared and vanished": the preloader timing out).

### 6.2 Probes per mode

| Mode | Collected |
|---|---|
| Android (adb) | brand, model, device, product, `ro.board.platform`/`ro.hardware` (chipset), Android version, security patch, fingerprint, `ro.serialno`, active slot, verified boot state, bootloader lock (`ro.boot.flash.locked`, `ro.boot.verifiedbootstate`), OEM unlock state (reuse `_get_oem_state` logic), `ro.frp.pst`, `user_setup_complete`, Google account present (`dumpsys account`, see spike S1), battery level/health/temp (`dumpsys battery`), storage free (`dumpsys diskstats`/`df /data`), root present (`which su`), anti-rollback props where exposed, recent crash/bootloop evidence (last few `dumpsys dropbox` system_server crash and `SYSTEM_TOMBSTONE` entries, if readable) |
| Recovery / sideload | whatever `getprop` returns in recovery; flag "phone boots to recovery" |
| Unauthorized adb | model from `adb devices -l`; flag "unlock the phone and accept the USB debugging prompt" |
| Fastboot / fastbootd | LG-safe getvar list plus `is-userspace`, `anti` (if present), `battery-voltage`, `battery-soc-ok` |
| Qualcomm EDL | `qedl_ident.py` (serial, HWID, PK hash, secure boot) and loader match result, via the EDL toolkit |
| MediaTek BROM/preloader | hw code / chip name, SBC/SLA/DAA via MTK toolkit `get_target_config()` |

**Where the probes live (my call):**
- adb and fastboot probes live **inside `phone_report`** (plain commands; reuse the finder
  pattern).
- EDL and MTK probes are provided **by their toolkits** through a new optional hook
  `collect_report() -> dict` on the plugin object. `phone_report` calls
  `plugin_manager.get_plugin(id)` and falls back gracefully when the hook is missing.
- Reason: those toolkits own their engines (edlclient, mtkclient) and driver handling.

**Parsers are pure functions** in `plugins/phone_report/parsers.py`, with no Qt and no subprocess,
so they can be unit-tested against recorded command output.

### 6.3 Report data model

JSON, versioned:

```json
{
  "schema": 1,
  "generated_at": "ISO-8601",
  "app_version": "4.0.0",
  "mode": "android|recovery|sideload|unauthorized|fastboot|fastbootd|edl|mtk_brom|mtk_preloader|none",
  "device":   { "brand": "", "model": "", "product": "", "chipset": "", "soc_vendor": "qualcomm|mediatek|other",
                "android_version": "", "security_patch": "", "fingerprint": "",
                "serial": "", "imei": [] },
  "security": { "bootloader_locked": null, "oem_unlock_allowed": null, "verified_boot": "",
                "secure_boot": null, "frp_present": null, "google_account_present": null, "rooted": null },
  "health":   { "battery_pct": null, "battery_health": "", "battery_temp_c": null, "storage_free_mb": null },
  "boot":     { "slot": "", "slot_count": null, "evidence": [] },
  "mode_details": {},
  "risks":    [ { "id": "", "severity": "block|warn|info", "title": "", "explain": "", "blocks": [] } ],
  "tools":    { "adb": true, "fastboot": true, "mtk_toolkit": "missing|outdated|ok", "edl_toolkit": "..." },
  "registration": { "registered": false, "owned_by_me": false, "reported_lost": false }
}
```

Unknown values are `null`, never guessed. `serial` and `imei` are kept raw locally and redacted on
export (§4.4).

### 6.4 Risk flags

`blocks` names operation categories that phone_report-aware code must refuse until the owner
acknowledges the flag. The categories are `flash`, `erase`, `unlock`, `reset`, and `modem`. In this
project the categories gate Patch Modem and are stored in the report; project 2 will enforce them
across all toolkits.

| id | When | Severity | Plain-language message (gist) |
|---|---|---|---|
| `battery_low` | battery < 30% | warn; **block** below 15% (flash, erase, unlock, modem) | "Charge to at least 30% first. A phone dying mid-flash can brick." |
| `frp_present` | Google account present, or FRP partition in use | info, **warn** before `reset` | "This phone is locked to a Google account. After any reset you'll need that account's email and password. Make sure you know them *before* resetting." |
| `no_backup` | always raised in Android/recovery modes until the owner ticks "I have a backup" (stored per device locally). The app can't see backups made elsewhere, so it asks rather than guesses. | warn (erase, reset, flash) | "Is everything you care about backed up? Photos, messages, 2FA apps." |
| `anti_rollback` | ARB prop or fastboot `anti` present | warn (flash) | "This phone blocks older firmware. Flashing an older version can permanently brick it." |
| `bl_locked_no_oem` | bootloader locked and OEM unlock not allowed | info | "Bootloader unlocking isn't possible right now (and here's why: `blocked_reason`)." |
| `edl_no_loader` | EDL with no matching loader | info | "No matching loader yet. Partition access isn't possible until one is found." |
| `mtk_secure` | SLA/DAA enabled | info | "This MediaTek phone needs a manufacturer-signed DA." |
| `rooted` | su present | info | short root-security explainer |
| `reported_lost` | server says device hash is marked lost | **block everything gated** | "This phone has been reported lost by its owner." Offers a "notify the owner" button (§7.6). |
| `unknown_mode` | nothing detected | info | guided mode helper |

The thresholds (30% / 15%) are my call.

### 6.5 Before/after comparison

`compare(before, after) -> {changes: [...], outcome: "better|same|worse|identity_changed"}`.

- **Reachability ranking:** boots Android > recovery > fastboot/fastbootd > EDL/BROM/preloader >
  none.
- **`identity_changed`:** the IMEI or serial differs between the two reports. This is always
  flagged severe.
- **Other fields:** bootloader and OEM changes are reported, not judged.
- **Use:** the Fixer Marketplace uses this later. It is built and tested now because it's small
  and part of "the report".

### 6.6 UI

A `phone_report` plugin tab:
- **Big button:** "🔍 Scan My Phone" (auto-rescans on USB change).
- **Mode banner:** for example "📱 Android, unlocked & authorized" or "⚡ MediaTek BROM".
- **Sections:** collapsible sections that mirror the JSON.
- **Risk cards** at the top: red for block, amber for warn, blue for info.
- **Share Report:** exports redacted HTML + JSON.
- **Register This Phone:** enabled only when the possession check passes (§7.1).
- **My Phones panel:** registered devices; mark lost, release or transfer, get proof packet.

## 7. Phone Registration

### 7.1 Possession check (phone booted, adb authorized)

All of the following must hold at registration time:
- adb state is `device` (authorized). That requires someone to unlock the screen and accept the
  RSA prompt.
- `settings get secure user_setup_complete` = 1.
- A Google account is present (spike S1). If it can't be read on the phone's Android version, the
  owner confirms it in-app, and that is recorded as "self-attested".
- The IMEI: try an adb read (spike S2; expected to fail on modern Android). Otherwise the owner
  types it from `*#06#`. A typed IMEI is stored as **unverified** until a device-level read (DA or
  EDL) matches it (§7.4).

### 7.2 Identity and hashing

- **Sending:** the client sends the raw IMEI(s) and `ro.serialno` **over TLS** to the server.
- **Storing:** the server stores only `HMAC-SHA256(server_pepper, normalized_value)`.
- **Pepper:** an env secret that never ships in the client.
- **Why not hash on the client:** client-side hashing isn't safe. IMEIs are only ~10⁶ guesses per
  model, so a published hash would be brute-forced instantly.
- **Stolen check:** this is the one place the raw IMEI is used, passed through to the provider and
  then discarded (§7.3).

### 7.3 Stolen-phone check

At registration, the server queries a lost/stolen database for the IMEI. A hit refuses the
registration and logs it.

**Provider and per-lookup cost: OWNER DECISION, see §11.**

Build the provider behind an interface so it can be swapped. Until it's decided, ship with a
`none` provider that logs "not checked".

### 7.4 Same-device match and gated features

Server-side flow:
1. The client reads the identity in the gated mode. For Patch Modem that's MTK DA-mode
   `read_imei()`.
2. The client calls `POST /api/devices/verify {imeis, feature}`.
3. The server checks, all of which must hold:
   - the hash matches a device registered to **this account**
   - the device is not marked lost
   - the feature is allowed
4. The server returns a **short-lived signed grant** (Ed25519, 10 minutes) naming the feature and
   the device hash.
5. If the registration IMEI was typed by the owner, a match here upgrades it to **verified**.

Patch Modem starts only with a valid grant. The client verifies the grant signature with the
server's public key, which is bundled with the app.

**Auth:** the account token is the one held by the core `PluginStoreAPI` instance
(`plugin_store_api.token`). Expose it to plugins through a small core accessor rather than having
plugins read `plugin_store_auth.json` directly.

**MTK identity in the comparison:** a basic report has no IMEI in MTK modes, so `compare()` falls
back to the serial or chip ID for `identity_changed`.

**Honesty note:** the client-side refusal is honest-client enforcement. A modified client can skip
it, as discussed with the owner, and that's acceptable because Patch Modem is legal. Gates that
must actually hold (firmware downloads, remote sessions, the marketplace) are enforced by the
server **delivering** the resource, not by the client.

Gated features:
- **Now:** `patch_modem`.
- **Reserved:** `tcl_firmware` (the TCL plugin calls the same endpoint, and the server serves or
  proxies the firmware only with a valid grant), `remote_repair`.

### 7.5 First registration wins; transfer

- **Conflicts:** a device hash already registered to another account can't be registered again.
  The attempt is logged, and the current owner is notified by email.
- **Release:** the owner releases the phone, which frees the hash.
- **Transfer:** the owner generates a **transfer code**. The buyer enters it in their app, and the
  registration moves to the buyer, keeping a history row.
- **Disputes:** handled manually by the owner (Image Anarchy admin) in v1.

### 7.6 Lost phones

- **Marking:** the owner marks a phone lost.
- **Effect:** the server refuses every gated feature and registration for that hash.
- **Report:** the report shows `reported_lost`.
- **Notify the owner (my call):** a button that sends an anonymous message to the registered owner
  through server-relayed email, with no contact details exchanged unless the finder adds them. It
  is rate-limited.

### 7.7 Ownership proof packet

- **Contents:** a server-signed statement: "Device {model}, IMEI ending {last4}, registered to this
  account on {date}; possession check passed; IMEI verified: yes/no."
- **Export:** an HTML/PDF document plus a short verification code.
- **Verification:** anyone can check the code at `imageanarchy.com/verify/<code>`. The page shows
  the same facts.
- **Full IMEI:** included in the **local** packet only, since the owner needs it for Google,
  carrier, or manufacturer recovery. It is never shown on the public verify page.

### 7.8 Account requirements

- **Registering** requires a **verified email**. The server already has mail configuration; add
  email verification if it doesn't exist.
- **2FA:** not required in this project (my call), but the registration table and API must not
  prevent adding it. The marketplace project will likely require it.

## 8. Server API and storage

New tables (MySQL, same style as existing `CREATE TABLE IF NOT EXISTS` blocks):

- `registered_devices`: `id`, `user_id`, `imei_hashes` (JSON array), `serial_hash`, `model`,
  `brand`, `imei_verified` (bool), `possession` (JSON: checks passed, self-attested flags),
  `status` (`active|lost|released`), `registered_at`, `updated_at`.
- `device_events`: `id`, `device_id`, `user_id`, `event` (registered, verify_ok, verify_fail,
  conflict, lost, found_notice, transfer, released), `detail` (JSON), `ip`, `created_at`.
- `device_transfers`: `code_hash`, `device_id`, `from_user`, `expires_at`, `used_at`.

Endpoints, all JWT-authenticated except `verify/:code` and `found`:

| Method & path | Purpose |
|---|---|
| `POST /api/devices/register` | possession data + IMEIs + serial → stolen check → hash → store |
| `GET /api/devices` | my registered devices |
| `POST /api/devices/:id/lost`, `/found`, `/release`, `/transfer` | status changes |
| `POST /api/devices/claim-transfer` | buyer redeems code |
| `POST /api/devices/verify` | same-device match → signed grant (§7.4) |
| `POST /api/devices/status` | the report asks about given IMEIs/serial; the reply is only `{mine, lost}` and never says "registered to someone else" (rate-limited) |
| `POST /api/devices/found` | anonymous notify-owner (rate-limited) |
| `GET /api/devices/proof/:id`, `GET /verify/:code` | proof packet / public verification |

Rate-limit with the existing limiter pattern (`authLoginLimiter`-style). New env vars:
`DEVICE_HASH_PEPPER`, `GRANT_SIGNING_KEY` (Ed25519 private), `STOLEN_CHECK_PROVIDER`,
`STOLEN_CHECK_API_KEY`.

## 9. Testing

- **Parsers:** unit tests (Python `unittest`, matching `tests/`) against recorded fixtures:
  getprop dumps (≥3 vendors, including LG and a TCL MT8786), `dumpsys battery`, fastboot getvar
  outputs, EDL ident JSON, MTK target config.
- **Risk evaluation and `compare()`:** table-driven tests.
- **Server:** tests for hashing and normalization, first-wins conflicts, lost blocking, grant
  signing/expiry, and transfer codes. Use `node:test` or whatever fits `plugin_store/`.
- **CI:** tests run on Ubuntu and Windows via `.github/workflows/tests.yml` (from PR #3).
- **Manual:** a real-device checklist per mode (Android, fastboot, EDL on the onn 8Core, MTK
  preloader on the TCL tablet), confirming **no reboots and no writes**.

## 10. Spikes to run before committing to details

| # | Question | Fallback |
|---|---|---|
| S1 | Does `dumpsys account` list accounts from an unprivileged adb shell on Android 9–15? | owner self-attests |
| S2 | Can the IMEI be read via adb without root on modern Android? (expected: no) | owner types it |
| S3 | Is MTK DA-mode `read_imei()` reliable across ≥2 devices (TCL MT8786 + one other)? | match on `proinfo` serial or ME ID instead; owner to confirm which is stable |
| S4 | OS-level USB enumeration on Windows (PnP) and Linux (sysfs) | per-tool detection only |

## 11. Decisions

**Owner (decided in conversation)**
- Ownership is the #1 rule. Bypassing FRP or a screen lock, or modifying an IMEI, means an
  automatic permanent ban; one worldwide legal standard.
- No FRP removal, even for registered phones (client gates can't stop a determined user; the only
  real stop is not coding it).
- Erase FRP and Write IMEI removed (PR #4); NCK network unlock kept; Patch Modem kept but gated
  behind registration.
- The phone report must be as automatic as possible, to limit situations made worse.
- Registration unlocks gated features; TCL firmware downloads will require proving ownership.
- Work order: Phone Report + Registration → Remote Repair Session → Fixer Marketplace.
- Server code goes into this public repo.

**My calls (owner to check while reading)**
- adb and fastboot probes inside `phone_report`; EDL and MTK via a `collect_report()` hook on their
  toolkits.
- Battery thresholds of 30% (warn) and 15% (block).
- Email verification required to register; 2FA deferred.
- "Notify the owner" button for found phones.
- 10-minute Ed25519 grants; release + transfer-code flow; manual dispute handling in v1.
- Redact the IMEI and serial to the last 4 digits by default on export.
- `no_backup` asks the owner rather than guessing.
- The status endpoint never reveals that a phone is registered to someone else.
- Move user data out of site-packages to the per-user config directory.

**Owner, still open**
- Stolen-phone check provider and cost (§7.3).
- Whether to rotate the server secrets before going public (§5).

**Left to the builder**
- UI layout details, report HTML styling, and exact command flags within the read-only rule.
- USB enumeration implementation (S4).
- Internal module structure of `phone_report` beyond `parsers.py` being pure.
