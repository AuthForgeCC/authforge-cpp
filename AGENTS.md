# AuthForge SDK: AI Agent Reference

> This file is optimized for AI coding agents (Cursor, Copilot, Claude Code, etc.).
> It contains everything needed to correctly integrate AuthForge licensing into a project.

## What AuthForge does

AuthForge is a license key validation service. Your app activates a license key online: it sends the key plus a hardware ID to `POST /auth/validate`, and the server checks revocation, expiry, HWID binding, and credits, then returns an Ed25519-signed session with a TTL. By default the app then runs through the grace period: it keeps running on that signed session without contacting AuthForge (the SDK re-verifies the signed session locally in the background) until the TTL expires. Optionally, you can enable online check-ins: periodic calls to `POST /auth/heartbeat` for fast revocation and concurrent-use detection. If the license is revoked or the session becomes invalid, the background check fails and you handle it (typically exit the app).

## Installation

Add `authforge_sdk.h` and `authforge_sdk.cpp` to your project, or consume the library via CMake `find_package` after installing from source (see README). Requires C++17, **libsodium**, OpenSSL, and libcurl.

## Minimal working integration

```cpp
#include "authforge_sdk.h"
#include <cstdlib>
#include <iostream>
#include <string>

int main() {
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
      [](const std::string &reason, const std::exception *exc) {
        std::cerr << "AuthForge: " << reason << "\n";
        if (exc) std::cerr << exc->what() << "\n";
        std::exit(1);
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
  // --- Your application code ends here ---

  client.Logout();
  return 0;
}
```

## Constructor parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `appId` | `std::string` | yes | none | Application ID |
| `appSecret` | `std::string` | yes | none | Application secret |
| `publicKey` | `std::string` / `std::vector<std::string>` | yes | none | Base64 Ed25519 public key from the dashboard (3rd positional arg). The string overload accepts a comma-separated trust list; a `std::vector<std::string>` overload takes a rotation set. The SDK trusts a signature matching **any** key |
| `onlineHeartbeat` | `authforge::OnlineHeartbeat` | no | `OnlineHeartbeat::Off` | `Off` (default): after activation, run through the grace period on the signed session with no network calls. `On`: enable online check-ins via `/auth/heartbeat` for fast revocation and concurrent-use detection |
| `heartbeatInterval` | `int` | no | `900` | Seconds between background checks (minimum `10`). With online check-ins enabled, revocations apply on the next check-in |
| `apiBaseUrl` | `std::string` | no | `kDefaultApiBaseUrl` (`https://auth.authforge.cc`) | API base URL |
| `onFailure` | `std::function<void(const std::string&, const std::exception*)>` | no | `nullptr` | Failure callback for `Login` / background checks; if null, `std::exit(1)` (not used by `ValidateLicense`) |
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
- Keep the check-in interval at or above 10 seconds. `/auth/heartbeat` is limited to 6 requests/minute per license key; cost still scales with how many check-ins you send.
- Revocations take effect on the **next** check-in regardless of interval.

## Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `Login(const std::string&)` | `bool` | Activates the license online and starts the background check loop |
| `ValidateLicense(const std::string&)` | `ValidateLicenseResult` | Same validate + signatures; no session/background checks; **never** calls `onFailure` or `std::exit` |
| `Logout()` | `void` | Stops background checks and clears state |
| `IsAuthenticated()` | `bool` | Whether authenticated |
| `GetSessionDataJson()` | `std::optional<std::string>` | Payload JSON string |
| `GetAppVariablesJson()` | `std::optional<std::string>` | App variables JSON |
| `GetLicenseVariablesJson()` | `std::optional<std::string>` | License variables JSON |

## Error codes the server can return

Full set: invalid_app, invalid_key, expired, revoked, hwid_mismatch, no_credits, app_burn_cap_reached, blocked, rate_limited, replay_detected, app_disabled, session_expired, revoke_requires_session, bad_request, malformed_request, system_error

Notes:
- `replay_detected` is validate-only. `rate_limited` can be returned by `/auth/validate` and `/auth/heartbeat` (heartbeat is license-limited at 6/min and has no app-layer IP limit).
- `app_burn_cap_reached` means the app's configured credit burn cap is hit; `revoke_requires_session` means a pre-session self-ban tried to revoke a license (only session-authenticated self-ban can revoke).
- `session_expired` is what the default background check reports when the grace period ends; the app must activate online again.

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

### Custom error handling

Use the `onFailure` callback; distinguish `reason` (`login_failed`, `heartbeat_failed`, `network_error`) and inspect `exc` when non-null.

## Do NOT

- Do not hardcode the app secret as a plain string literal in source; use environment variables or encrypted config
- Do not omit `onFailure`; without it, failures call `std::exit(1)` without your cleanup
- Do not call `Login` on every app action; call once at startup, the background checks handle the rest
- Do not pass the deprecated `heartbeatMode` strings (`"LOCAL"` / `"SERVER"`) in new code; use the default for grace period behavior or `authforge::OnlineHeartbeat::On` for online check-ins
- Do not enable online check-ins if the app loses internet access after initial activation; the default grace period behavior covers that case within the session TTL
