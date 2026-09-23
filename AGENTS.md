# AuthForge SDK: AI Agent Reference

> This file is optimized for AI coding agents (Cursor, Copilot, Claude Code, etc.).
> It contains everything needed to correctly integrate AuthForge licensing into a project.

## What AuthForge does

AuthForge is a license key validation service. Your app activates a license key online: it sends the key plus a hardware ID to `POST /auth/validate`, and the server checks revocation, expiry, HWID binding, and credits, then returns an Ed25519-signed session with a TTL. By default the app then runs through the grace period: it keeps running on that signed session without contacting AuthForge (the SDK re-verifies the signed session locally in the background) until the TTL expires. Optionally, you can enable online check-ins: periodic calls to `POST /auth/heartbeat` for fast revocation and concurrent-use detection. If the license is revoked or the session becomes invalid, the background check fails and you handle it (typically exit the app).

There is also a **separate** mode for machines that can never reach the internet: **offline license files (`.authforge`)**. The operator mints a signed file in the AuthForge cloud; `LoginFromFile()` verifies it locally with the app public key and the machine HWID, with zero network calls. Do not ship the App Secret in those builds (pass `""`). Only use it when the user explicitly asks for air-gapped / offline-file licensing. The default integration is always online `Login()` + grace period. To collect the HWID for a bound file, write an **activation request** (`.authforge-request`) with `CreateActivationRequest`. It is not a license, is not signed, and does not mint anything. Prefer it over printing the raw HWID.

## Installation

Add `authforge_sdk.h` and `authforge_sdk.cpp` to your project, or consume the library via CMake `find_package` after installing from source (see README). Requires C++17, **libsodium**, OpenSSL, and libcurl.

## Minimal working integration

```cpp
#include "authforge_sdk.h"
#include <atomic>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

int main() {
  // Set when the license is lost; the main loop checks it, saves work, then exits.
  std::atomic<bool> licenseLost{false};

  // Default policy: activate online once, then run through the grace period
  // (no network until the session TTL expires). To enable online check-ins,
  // pass authforge::OnlineHeartbeat::On as the 4th argument.
  authforge::AuthForgeClient client(
      "YOUR_APP_ID",
      "YOUR_APP_SECRET",
      "YOUR_PUBLIC_KEY", // required: base64 Ed25519 key from the dashboard
      authforge::OnlineHeartbeat::Off,
      900,
      authforge::AuthForgeClient::kDefaultApiBaseUrl,
      [&licenseLost](const std::string &reason, const std::exception *exc) {
        if (auto *e = dynamic_cast<const authforge::AuthForgeError *>(exc); e && e->isTransient()) {
          return; // network blip / rate_limited: the SDK checks in again next interval
        }
        std::cerr << "AuthForge: " << reason << "\n";
        if (exc) std::cerr << exc->what() << "\n";
        licenseLost = true; // may run on the heartbeat thread: signal, do not std::exit here
      });

  std::string license_key;
  std::cout << "Enter license key: ";
  std::getline(std::cin, license_key);

  if (!client.Login(license_key)) {
    std::cerr << "Login failed.\n";
    return 1;
  }

  // --- Your application code starts here ---
  std::cout << "Running with a valid license.\n";
  while (!licenseLost) {
    std::this_thread::sleep_for(std::chrono::seconds(1)); // replace with short units of work
  }
  // --- Your application code ends here ---

  // Save the user's work here, then stop.
  client.Logout();
  return 1;
}
```

## Constructor parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `appId` | `std::string` | yes | none | Application ID |
| `appSecret` | `std::string` | for online APIs | none | Application secret. Required for `Login` / `ValidateLicense` / `SelfBan`. Pass `""` for `LoginFromFile` only; do not ship it in air-gapped binaries. |
| `publicKey` | `std::string` / `std::vector<std::string>` | yes | none | Base64 Ed25519 public key from the dashboard (3rd positional arg). The string overload accepts a comma-separated trust list; a `std::vector<std::string>` overload takes a rotation set. The SDK trusts a signature matching **any** key |
| `onlineHeartbeat` | `authforge::OnlineHeartbeat` | no | `OnlineHeartbeat::Off` | `Off` (default): after activation, run through the grace period on the signed session with no network calls. `On`: enable online check-ins via `/auth/heartbeat` for fast revocation and concurrent-use detection |
| `heartbeatInterval` | `int` | no | `900` | Seconds between background checks (minimum `10`). With online check-ins enabled, revocations apply on the next check-in |
| `apiBaseUrl` | `std::string` | no | `kDefaultApiBaseUrl` (`https://auth.authforge.cc`) | API base URL |
| `onFailure` | `std::function<void(const std::string&, const std::exception*)>` | no | `nullptr` | Failure callback for `Login` / background checks (not used by `ValidateLicense`). If null, a transient background check failure prints a one-line warning to `std::cerr` and check-ins continue; any other failure calls `std::exit(1)` |
| `requestTimeout` | `int` | no | `15` | HTTP timeout (seconds) |
| `ttlSeconds` | `int` | no | `0` (server default: 86400) | Requested grace period duration in seconds (the session token lifetime). `0` means "server default" (24h). Server clamps to `[3600, 604800]` (1h to 7d); preserved across heartbeat refreshes. |
| `hwidOverride` | `std::string` | no | `""` | Optional custom HWID/subject string. When non-empty (for example `tg:123456789`), the SDK sends it instead of generating a machine fingerprint. |

For Telegram/Discord bot flows, prefer immutable IDs (`tg:<user_id>`, `discord:<user_id>`) instead of usernames.

## Migrating from heartbeatMode

Earlier versions took a `std::string heartbeatMode` (`"LOCAL"` or `"SERVER"`) as the 4th constructor parameter:

- `"LOCAL"` maps to the default (grace period behavior): drop the argument entirely.
- `"SERVER"` maps to `authforge::OnlineHeartbeat::On`.

The old string-mode constructors still work and behave exactly as before, but they emit a deprecation warning at compile time. Never describe the grace period as a "LOCAL mode" or "offline mode"; it is the default behavior of every activated session.

## Billing model

- Each `Login()` or `ValidateLicense()` calls `/auth/validate` and costs **1 credit**.
- Online check-ins cost **1 credit per 10 successful calls** (billed on every 10th heartbeat).
- The default grace period policy makes no network calls after activation and costs nothing until the next activation.
- **1 offline file mint = 1 credit** (charged to the operator when the file is minted). `LoginFromFile()` / `VerifyLicenseFile()` cost nothing.
- Keep the check-in interval at or above 10 seconds. `/auth/heartbeat` is limited to 6 requests/minute per license key; cost still scales with how many check-ins you send.
- Revocations take effect on the **next** check-in regardless of interval.

## Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `Login(const std::string&)` | `bool` | Activates the license online and starts the background check loop |
| `ValidateLicense(const std::string&)` | `ValidateLicenseResult` | Same validate + signatures; no session/background checks; **never** calls `onFailure` or `std::exit` |
| `LoginFromFile(const std::string&)` | `bool` | Offline mode: verifies a `.authforge` file locally (no network), authenticates the client, never starts background checks. Failures -> `onFailure("offline_login_failed", &exc)` (`exc.what()` = code) + `false`; never `std::exit` |
| `VerifyLicenseFile(const std::string&, long long nowEpochMs = 0)` | `VerifyLicenseFileResult` | Same offline checks without changing client state |
| `GetOfflineLicense()` | `std::optional<OfflineLicense>` | `jti`, `expiresAt`, `hwidPolicy`, … of the offline file in use |
| `GetSessionKind()` | `SessionKind` | `SessionKind::Online`, `SessionKind::Offline`, or `SessionKind::None` when logged out |
| `GetHwid()` | `const std::string&` | HWID this client sends; the customer reports it so the operator can mint a bound file |
| `CreateActivationRequest(const ActivationRequestOptions& = {})` | `std::string` | Unsigned `.authforge-request` for this machine. No network, no secret, callable before `Login()`. Hostname omitted unless `includeMachineName` |
| `Logout()` | `void` | Stops background checks and clears state |
| `IsAuthenticated()` | `bool` | Whether authenticated |
| `GetSessionDataJson()` | `std::optional<std::string>` | Payload JSON string |
| `GetAppVariablesJson()` | `std::optional<std::string>` | App variables JSON |
| `GetLicenseVariablesJson()` | `std::optional<std::string>` | License variables JSON |

## Error codes the server can return

Full set: invalid_app, invalid_key, expired, revoked, hwid_mismatch, no_credits, demo_quota_exceeded, app_burn_cap_reached, blocked, rate_limited, replay_detected, app_disabled, session_expired, revoke_requires_session, bad_request, malformed_request, system_error. Unknown snake_case codes are passed through unchanged.

Non-2xx responses with a JSON body surface the clean code on both `Login` and check-ins (`exc->what()` is `invalid_key`, not `http_error_401: {...}`). Only non-JSON error pages become `http_error_<status>`.

Notes:
- `replay_detected` is validate-only. `rate_limited` can be returned by `/auth/validate` and `/auth/heartbeat` (heartbeat is license-limited at 6/min and has no app-layer IP limit).
- `app_burn_cap_reached` means the app's configured credit burn cap is hit; `revoke_requires_session` means a pre-session self-ban tried to revoke a license (only session-authenticated self-ban can revoke).
- `session_expired` is what the default background check reports when the grace period ends; the session is cleared and the app must activate online again.

## Common patterns

### Reading license variables (feature gating)

```cpp
if (auto json = client.GetLicenseVariablesJson()) {
  std::cout << "licenseVariables=" << *json << "\n";
}
```

Parse the JSON string with your JSON library, then read keys for gating.

### Graceful shutdown

```cpp
client.Logout();
```

### Offline license file (air-gapped machine, only when asked)

```cpp
// Step 1 (customer machine): print the HWID so the operator can bind the file to it.
std::cout << client.GetHwid() << "\n";

// Step 2 (operator): mint the .authforge file in the dashboard or via
// POST /v1/licenses/{licenseKey}/offline-files and deliver it out-of-band.

// Step 3 (customer machine): authorize with the file. No network, no check-ins.
if (!client.LoginFromFile("license.authforge")) {
  // onFailure already received ("offline_login_failed", &exc) where exc.what() is one of
  // bad_armor | bad_signature | unsupported_version | malformed_payload | wrong_app | expired | hwid_mismatch
  return 1;
}
```

Offline file error codes (in check order): `bad_armor`, `bad_signature`, `unsupported_version`, `malformed_payload`, `wrong_app`, `expired`, `hwid_mismatch`.

### Failure handling

`onFailure(reason, exc)` receives `reason` = `login_failed`, `heartbeat_failed`, `selfban_failed` or `offline_login_failed`. There is no `network_error` reason: network failures arrive as `heartbeat_failed` / `login_failed` with code `network_error` or `timeout`. For online APIs `exc` is an `authforge::AuthForgeError` with `code()`, `isTransient()` and `isFatal()`; for server codes `exc->what()` equals the code. `authforge::IsTransientErrorCode(code)` gives the same classification.

| Class | Codes | Background check behavior |
|-------|-------|---------------------------|
| Definitive | `revoked`, `expired`, `hwid_mismatch`, `blocked`, `session_expired`, `malformed_request`, `app_disabled`, `invalid_app`, `signature_mismatch` | Session cleared (`Logout()`) before `onFailure`; `IsAuthenticated()` is `false`; check-ins stop |
| Transient | Everything else, including `rate_limited`, `system_error`, `no_credits`, `demo_quota_exceeded`, `app_burn_cap_reached`, `bad_request`, `invalid_key`, `unexpected_response`, `http_error_<status>`, `network_error`, `timeout` and unknown codes | Session kept; `onFailure` runs; check-ins continue |

- A transient failure after the signed session TTL is reported as `session_expired` (definitive).
- On check-ins, `hwid_mismatch` means the HWID is no longer bound to the license (for example after an HWID reset); `blocked` means the HWID or IP is blacklisted or not whitelisted.
- `unexpected_response`: a check-in failure body that is not `{"status":"failed","error":"<code>"}`; never treated as a verdict.
- Only `rate_limited` (or a 429 with no error code) is retried (2s, then 5s). `no_credits`, `demo_quota_exceeded` and `app_burn_cap_reached` are not retried.

```cpp
[&licenseLost](const std::string &reason, const std::exception *exc) {
  if (auto* e = dynamic_cast<const authforge::AuthForgeError*>(exc); e && e->isTransient()) return;
  std::cerr << "AuthForge: " << reason << (exc ? std::string(": ") + exc->what() : "") << "\n";
  licenseLost = true; // std::atomic<bool> the main loop checks before saving and returning
}
```

`std::exit(1)` inside `onFailure` is a last resort: it skips stack destructors on every thread, so save the user's work first.

Thread safety: background `onFailure` calls run on the heartbeat thread with no SDK lock held. Calling `Logout()` / `IsAuthenticated()` from the callback, or destroying the client inside it, is safe. The destructor stops and joins the heartbeat thread.

## Do NOT

- Do not hardcode the app secret as a plain string literal in source; use environment variables or encrypted config
- Do not embed the App Secret in air-gapped / `LoginFromFile()` builds; pass `""`; verification only needs app id + public key
- Do not omit `onFailure`; without it, transient check-in failures only print a stderr warning, but definitive ones (and a failed `Login`) call `std::exit(1)` without your cleanup
- Do not call `std::exit` from `onFailure` as the normal shutdown path; set a `std::atomic<bool>` (or post to the UI thread) so the main thread can save work and exit cleanly
- Do not call `Login` on every app action; call once at startup, the background checks handle the rest
- Do not pass the deprecated `heartbeatMode` strings (`"LOCAL"` / `"SERVER"`) in new code; use the default for grace period behavior or `authforge::OnlineHeartbeat::On` for online check-ins
- Do not enable online check-ins if the app loses internet access after initial activation; the default grace period behavior covers that case within the session TTL
- Do not treat the grace period as persistent offline licensing; it is session continuation after one successful online activation, and revocations are only picked up at the next online validate or check-in
- Do not reach for `LoginFromFile()` unless the user explicitly needs air-gapped / offline-file licensing; the default is online `Login()` + grace period
- Do not expect an online revoke to disable an offline file that is already on a customer machine; the file stays valid until its own `expiresAt`; prefer short expiries and HWID-bound files
- Do not mint or accept `hwid.mode: "any"` files casually; anyone who copies an unbound file has a working license
- Do not call `LoginFromFile()` with another app's public key or app id; the file is rejected with `bad_signature` / `wrong_app` by design
- Do not try to build `.authforge` files client-side; only the AuthForge cloud holds the signing key; there is no BYO issuer
- Do not call `SelfBan()` or any other online method after `LoginFromFile()`; an offline session has no server session (`GetSessionKind()` is `SessionKind::Offline`), so `SelfBan()` returns `false` with `onFailure("selfban_failed", offline_session)` without contacting the server, and online check-ins never start; machines that can reach AuthForge should use online `Login()`
- Do not bind an offline file to an HWID reported by a different SDK or language; HWID fingerprints are not portable across SDKs, so collect the HWID from the exact SDK build that will load the file (or use the HWID override with an identifier you control)

## Activation request vectors

`activation_request_vectors.json` is generated by `authforge-node/generate_activation_request_vectors.mjs`. Regenerating it means copying the file unmodified into all six SDK repos and `platform/frontend/src/test/fixtures/activation_request_vectors.json` in the same change. The vector `sdk` value is a frozen encoding fixture, not the live SDK tag.
