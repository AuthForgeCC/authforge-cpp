# AuthForge C++ SDK

Official C++ SDK for [AuthForge](https://authforge.cc): credit-based license key authentication with Ed25519-verified responses.

**Single-source CMake library.** Public headers plus one implementation file (`authforge_sdk.cpp`) packaged as `authforge_sdk`, linking **libsodium** (Ed25519), **OpenSSL** (SHA and helpers), and **libcurl** (HTTP). Targets C++17. Works on Windows (MSVC), Linux (GCC/Clang), and macOS (Clang).

## How licensing works

1. **Activate**: the SDK validates the license key online via `POST /auth/validate`. The server checks revocation, expiry, HWID binding, and credits, then returns an Ed25519-signed session with a TTL.
2. **Grace period**: by default the app keeps running on that signed session without contacting AuthForge for the length of the session TTL (default 24h, server clamps 1h to 7d). A background loop re-verifies the signed session locally and fails when the grace period ends.
3. **Online check-ins (optional)**: opt in with `authforge::OnlineHeartbeat::On` to have the SDK call `POST /auth/heartbeat` every `heartbeatInterval` seconds for fast revocation and concurrent-use detection.

## Features

Everything in this list ships in `authforge_sdk.h` / `authforge_sdk.cpp` today:

- **License activation** via `POST /auth/validate`, returning a signed `ValidateLicenseResult`.
- **Ed25519 signature verification** (libsodium) on every `/auth/validate` and `/auth/heartbeat` response; tampered or unsigned responses are rejected.
- **Key rotation**: a single-key constructor (also accepts a comma-separated string) and a `std::vector<std::string>` rotation-set constructor. The SDK trusts a signature that matches **any** key, so you can roll the server-side signing key without breaking deployed clients.
- **Nonce anti-replay**: a fresh 128-bit nonce is sent on every request and the echoed nonce in the signed payload is checked before the response is accepted.
- **HWID fingerprinting**: deterministic device hash from MAC + CPU + disk serial, with graceful per-component fallback.
- **`hwidOverride`**: bind to any identity instead of the machine (for example `tg:<id>`, `discord:<id>`).
- **Seat enforcement**: the server binds each HWID into a license's free slots up to `maxHwidSlots`; `maxHwidSlots` / `hwidCount` are surfaced on the validate result. A shared (unlimited-seat) key skips per-device binding.
- **Grace period by default, online check-ins on demand** (see [Grace period and online check-ins](#grace-period-and-online-check-ins)).
- **Offline license files (`.authforge`)**: `LoginFromFile()` / `VerifyLicenseFile()` verify a cloud-minted, Ed25519-signed file with zero network access for air-gapped machines.
- **Self-ban** (`SelfBan(...)`) for anti-tamper response, both pre-session and post-session.
- **Grace period duration control** (`ttlSeconds`) with server-side clamping to `[3600, 604800]`.
- **App variables / license variables** for feature flags and tiered licensing.
- **Automatic retries** for rate-limited and transient network failures, with a fresh nonce per rate-limit retry.
- **Typed failures**: `authforge::AuthForgeError` carries the server code plus a transient/definitive classification (see [Failure Handling](#failure-handling)).

There is **no C++ package registry** for this SDK. Ship source via **GitHub Releases** (tag `v*`, source archive) or by **cloning** the repository, then build with CMake as below.

## Quick Start

Add `authforge_sdk.h` and `authforge_sdk.cpp` to your project, then:

```cpp
#include "authforge_sdk.h"
#include <iostream>
#include <string>

int main() {
    authforge::AuthForgeClient client(
        "YOUR_APP_ID",           // from your AuthForge dashboard
        "YOUR_APP_SECRET",       // from your AuthForge dashboard
        "YOUR_PUBLIC_KEY"        // base64 Ed25519 public key from dashboard
    );
    // Default policy: activate online once, then run through the grace
    // period (no network). Pass authforge::OnlineHeartbeat::On as the 4th
    // argument to enable online check-ins.

    std::string key;
    std::cout << "Enter license key: ";
    std::getline(std::cin, key);

    if (client.Login(key)) {
        std::cout << "Authenticated!" << std::endl;
        // Your app logic here; the background session check runs automatically
    } else {
        std::cout << "Invalid license key." << std::endl;
        return 1;
    }

    return 0;
}
```

## Building

### CMake

```bash
cmake -S . -B build
cmake --build build
cmake --install build --prefix /your/prefix
```

CMake must be able to find **libsodium**, **OpenSSL**, and **libcurl** (headers and libraries). Examples:

- **Linux (Debian/Ubuntu):** `sudo apt install libsodium-dev libssl-dev libcurl4-openssl-dev`
- **macOS (Homebrew):** `brew install libsodium openssl curl`. If CMake does not pick up Homebrew paths automatically, set `CMAKE_PREFIX_PATH` to your prefix (often `/opt/homebrew` on Apple Silicon, `/usr/local` on Intel).
- **Windows:** Install dependencies with [vcpkg](https://vcpkg.io/), then configure with its toolchain file, for example:  
  `vcpkg install libsodium:x64-windows openssl:x64-windows curl:x64-windows`  
  `cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake`  
  (Adjust triplet and `VCPKG_ROOT` to match your setup.)

### Using from another CMake project

```cmake
find_package(AuthForge CONFIG REQUIRED)
target_link_libraries(yourapp PRIVATE AuthForge::authforge_sdk)
```

## Configuration

| Parameter | Type | Default | Description |
|---|---|---|---|
| `appId` | string | required | Your application ID from the AuthForge dashboard |
| `appSecret` | string | required for online APIs; `""` for `LoginFromFile` only | Your application secret from the AuthForge dashboard. Do not ship it in air-gapped binaries. |
| `publicKey` | `std::string` / `std::vector<std::string>` | required | App Ed25519 public key(s) (base64) from dashboard. The single-string overload accepts a comma-separated trust list; the `std::vector<std::string>` overload takes a rotation set. The SDK trusts a signature matching **any** key (see [Key rotation](#key-rotation)). |
| `onlineHeartbeat` | `authforge::OnlineHeartbeat` | `OnlineHeartbeat::Off` | `Off` (default): run through the grace period on the signed session, no network after activation. `On`: enable online check-ins via `/auth/heartbeat` (see below). |
| `heartbeatInterval` | int | `900` | Seconds between background checks (minimum `10`; default 15 min). With online check-ins enabled, this is the check-in cadence. |
| `apiBaseUrl` | string | `https://auth.authforge.cc` | API endpoint |
| `onFailure` | std::function | `nullptr` | Callback `(const string&, const exception*)` on auth failure |
| `requestTimeout` | int | `15` | HTTP request timeout in seconds |
| `ttlSeconds` | int | `0` (server default: 86400) | Requested grace period duration in seconds (the session token lifetime). `0` means "server default" (24h). Server clamps to `[3600, 604800]` (1h to 7d); preserved across heartbeat refreshes. |
| `hwidOverride` | string | `""` | Optional custom hardware/subject identifier. When non-empty, the SDK uses this value instead of generated device fingerprint data. |

### Identity-based binding example (Telegram/Discord)

```cpp
authforge::AuthForgeClient client(
    "YOUR_APP_ID",
    "YOUR_APP_SECRET",
    "YOUR_PUBLIC_KEY",
    authforge::OnlineHeartbeat::On,
    900,
    authforge::AuthForgeClient::kDefaultApiBaseUrl,
    onFailure,
    15,
    0,
    "tg:" + std::to_string(telegramUserId) // or "discord:" + std::to_string(discordUserId)
);
```

### Key rotation

To rotate the server-side signing key without a flag-day, construct the client
with the **new** and **previous** keys via the `std::vector<std::string>`
overload; the SDK accepts a signature matching any entry:

```cpp
authforge::AuthForgeClient client(
    "YOUR_APP_ID",
    "YOUR_APP_SECRET",
    std::vector<std::string>{ "NEW_PUBLIC_KEY", "PREVIOUS_PUBLIC_KEY" }
);
```

`client.GetPublicKeys()` returns the full trust list. A comma-separated single
string (`"NEW,PREVIOUS"`) works too, for env-var convenience.

## Billing

- **One `Login()` or `ValidateLicense()` call = 1 credit** (one `/auth/validate` debit each).
- **10 online check-ins on the same session = 1 credit** (debited on every 10th successful heartbeat).
- The default grace period policy costs nothing after activation: no network calls are made until the next activation.

A desktop app with online check-ins running 6h/day at a 15-minute interval burns ~3-4 credits/day. `/auth/heartbeat` is limited to 6 requests/minute per license key, so keep intervals at 10 seconds or higher and choose cadence based on revocation speed needs (revocations always land on the **next** check-in).

## Methods

| Method | Returns | Description |
|---|---|---|
| `Login(const std::string&)` | `bool` | Activates the key online and stores the signed session (`sessionToken`, `expiresIn`, `appVariables`, `licenseVariables`) |
| `ValidateLicense(const std::string&)` | `ValidateLicenseResult` | Same `/auth/validate` + signatures as `Login`; does not persist session or start background checks; **never** calls `onFailure` or `std::exit`; inspect `valid` / `errorCode` |
| `SelfBan(...)` | `bool` | Requests `/auth/selfban` to blacklist HWID/IP and optionally revoke (session-authenticated only) |
| `LoginFromFile(const std::string&)` | `bool` | Authorizes from an offline `.authforge` file (path or text) with no network; never starts background checks; failures go to `onFailure("offline_login_failed", …)` |
| `VerifyLicenseFile(const std::string&, long long nowEpochMs = 0)` | `VerifyLicenseFileResult` | Verifies a `.authforge` file with this client's app id / keys / HWID without changing state |
| `GetOfflineLicense()` | `std::optional<OfflineLicense>` | Metadata of the offline file in use (`jti`, `expiresAt`, `hwidPolicy`, …) |
| `GetSessionKind()` | `SessionKind` | `SessionKind::Online`, `SessionKind::Offline`, or `SessionKind::None` when logged out |
| `GetHwid()` | `const std::string&` | The HWID this client sends (or `hwidOverride`); customers share it to receive a bound file |
| `CreateActivationRequest(const ActivationRequestOptions& = {})` | `std::string` | Unsigned `.authforge-request` for this machine. No network, no secret. Hostname omitted unless `includeMachineName` |
| `Logout()` | `void` | Stops background checks and clears all session/auth state |
| `IsAuthenticated()` | `bool` | True when an active authenticated session exists |
| `GetSessionDataJson()` | `std::optional<std::string>` | Full decoded payload JSON |
| `GetAppVariablesJson()` | `std::optional<std::string>` | App variables JSON (if present) |
| `GetLicenseVariablesJson()` | `std::optional<std::string>` | License variables JSON (if present) |

## Grace period and online check-ins

**Grace period (default).** After a successful online activation, the app keeps running on the Ed25519-signed session without contacting AuthForge. The background loop re-verifies the signed session locally and triggers failure with `session_expired` when the grace period ends. The grace period equals the session TTL: default 24h, and the server clamps requested values (`ttlSeconds`) to 1h to 7d. This is session continuation after one successful online activation, not persistent offline licensing, and a mid-session revocation cannot take effect until the next online activation.

**Online check-ins (opt-in).** Construct the client with `authforge::OnlineHeartbeat::On` and the SDK calls `/auth/heartbeat` every `heartbeatInterval` seconds with a fresh nonce, verifies signature + nonce, and triggers failure on invalid session state. Definitive failures clear the session and stop check-ins; transient ones (network, server errors, `no_credits`, ...) are reported and check-ins continue (see [Failure Handling](#failure-handling)). Choose this for fast revocation and concurrent-use detection.

## Offline license files (`.authforge`)

For machines that never connect to the internet, the operator mints a **signed offline license file** in the AuthForge dashboard (License page -> *Mint .authforge file*) or via `POST /v1/licenses/{licenseKey}/offline-files`. The file is a standalone Ed25519-signed document; the SDK verifies it with **only** your app public key and the machine HWID. It never contacts AuthForge and never starts the background thread. Pass an empty `appSecret` so the air-gapped binary does not contain the App Secret.

| | Grace period (default) | Offline license file |
| --- | --- | --- |
| Needs network | Once, at `Login()` | Never on the end machine |
| What is verified | Signed *session* from `/auth/validate` | Signed *document* minted in the cloud |
| Lifetime | Session TTL: 1h to 7d | Operator-chosen expiry or lifetime (perpetual licenses only) |
| Revocation | Picked up at the next online validate / check-in | **Not** reachable: the file stays valid until its own expiry |
| Cost | 1 credit per `Login()` | 1 credit per mint; verifying is free |

```cpp
authforge::AuthForgeClient client(
    "YOUR_APP_ID",
    "",  // LoginFromFile does not use the App Secret; do not ship it in air-gapped builds
    "YOUR_PUBLIC_KEY",
    authforge::OnlineHeartbeat::Off, 900, authforge::AuthForgeClient::kDefaultApiBaseUrl,
    [](const std::string &reason, const std::exception *exc) {
      std::cerr << reason << (exc ? std::string(": ") + exc->what() : "") << "\n";
    });

// 1. Write an activation request the operator drops into the mint dialog:
std::string request = client.CreateActivationRequest();

// 2. Later, authorize from the minted file (path or armored text). No network.
if (client.LoginFromFile("license.authforge")) {
  const auto info = client.GetOfflineLicense();
  std::cout << "Offline license OK until " << (info->expiresAt ? *info->expiresAt : "forever") << "\n";
}
```

Collect the HWID from the same SDK build that will load the file: fingerprints are not portable across SDKs or languages. After `LoginFromFile()`, `GetSessionKind()` returns `SessionKind::Offline` (`SessionKind::Online` after `Login()`, `SessionKind::None` when logged out).

`authforge::VerifyLicenseFile(text, appId, publicKeys, hwid)` (free function) and `client.VerifyLicenseFile(pathOrText)` perform the same checks without touching client state and return a `VerifyLicenseFileResult` (`ok`, `error`, `license`). Failure codes, in check order: `bad_armor`, `bad_signature`, `unsupported_version`, `malformed_payload`, `wrong_app`, `expired`, `hwid_mismatch`. `LoginFromFile()` reports them through `onFailure("offline_login_failed", &exc)` (with `exc.what()` = code) and returns `false`; it never calls `std::exit`.

File format (version 1): PEM-style armor with informational headers, a base64 JSON payload (`v`, `appId`, `licenseKey`, `jti`, `kid`, `issuedAt`, `expiresAt`, `hwid` policy, optional label/variable snapshots) and a detached Ed25519 signature over the UTF-8 bytes of the base64 payload string - the same contract as `/auth/validate`. See `offline_license_vectors.json` for conformance vectors and `tests/offline_vectors_test.cpp` (build with `-DAUTHFORGE_BUILD_TESTS=ON`, run with `ctest`).

## Migrating from heartbeatMode

Earlier versions took a `std::string heartbeatMode` (`"LOCAL"` or `"SERVER"`) as the 4th constructor parameter. That parameter is replaced by `authforge::OnlineHeartbeat`:

- `"LOCAL"` maps to the default (grace period behavior): drop the argument entirely.
- `"SERVER"` maps to `authforge::OnlineHeartbeat::On`.

```cpp
// Before:
authforge::AuthForgeClient client("APP_ID", "APP_SECRET", "PUBLIC_KEY", "LOCAL");
// After (grace period is the default):
authforge::AuthForgeClient client("APP_ID", "APP_SECRET", "PUBLIC_KEY");

// Before:
authforge::AuthForgeClient client("APP_ID", "APP_SECRET", "PUBLIC_KEY", "SERVER");
// After:
authforge::AuthForgeClient client("APP_ID", "APP_SECRET", "PUBLIC_KEY",
                                  authforge::OnlineHeartbeat::On);
```

The old string-mode constructors still work and behave exactly as before, but they emit a deprecation warning at compile time.

## Failure Handling

If authentication fails, the SDK calls your `onFailure` callback if one is provided. If no callback is set, **the SDK calls `std::exit(1)` to terminate the process.** This is intentional: it prevents your app from running without a valid license.

**`ValidateLicense()`** always returns a `ValidateLicenseResult` and does not invoke `onFailure` or exit the process.

`Login()`, `SelfBan()` and background checks pass an `authforge::AuthForgeError` as `exc`, with `code()`, `isTransient()` and `isFatal()`. For server codes `exc->what()` equals the code. A non-2xx response with a JSON body yields the server's clean code on both login and check-ins (`what()` is `invalid_key`, not `http_error_401: {...}`); only non-JSON error pages become `http_error_<status>`. `authforge::IsTransientErrorCode(code)` exposes the same classification.

| Class | Codes | Background check (`heartbeat_failed`) |
|---|---|---|
| Definitive | `revoked`, `expired`, `hwid_mismatch`, `blocked`, `session_expired`, `malformed_request`, `app_disabled`, `invalid_app`, `signature_mismatch` | The session is cleared (`Logout()`) before `onFailure` runs, so `IsAuthenticated()` is `false`; check-ins stop |
| Transient | Everything else: `rate_limited`, `system_error`, `no_credits`, `demo_quota_exceeded`, `app_burn_cap_reached`, `bad_request`, `invalid_key`, `replay_detected`, `unexpected_response`, `http_error_<status>`, `invalid_json_response`, `response_not_json_object`, `network_error`, `timeout`, and any unknown code | The session is kept, `onFailure` runs, and check-ins continue at the next interval |

- A transient failure after the session's signed TTL has passed is reported as `session_expired` (definitive). The grace period check also ends with `session_expired`.
- On check-ins, `hwid_mismatch` means this device's HWID is no longer bound to the license (for example after an HWID reset), and `blocked` means the HWID or IP is blacklisted or not on the app's whitelist.
- `unexpected_response` means a check-in failure body that is not `{"status":"failed","error":"<code>"}` (for example a proxy error in JSON). It is never treated as a verdict; `what()` keeps the raw `status`/`error`.
- Unknown snake_case server codes are passed through as-is instead of becoming `unknown_error`.

Request retries are automatic inside the internal HTTP layer:
- `rate_limited` (or HTTP 429 without an error code): retry after 2s, then 5s (max 3 attempts total), each with a fresh nonce
- `no_credits`, `demo_quota_exceeded` and `app_burn_cap_reached` also use HTTP 429 but are not retried; the next check-in happens at the next interval
- network failure: retry once after 2s, then fail with `network_error` or `timeout` (`what()` starts with `url_error: `)

```cpp
authforge::AuthForgeClient client(
    "YOUR_APP_ID",
    "YOUR_APP_SECRET",
    "YOUR_PUBLIC_KEY",
    authforge::OnlineHeartbeat::On,
    900,
    authforge::AuthForgeClient::kDefaultApiBaseUrl,
    [](const std::string& reason, const std::exception* exc) {
        if (auto* e = dynamic_cast<const authforge::AuthForgeError*>(exc); e && e->isTransient()) {
            std::cerr << "AuthForge " << reason << " (transient): " << e->code() << std::endl;
            return; // session kept; check-ins continue (Login() still returns false)
        }
        std::cerr << "Auth failed: " << reason << std::endl;
        if (exc) std::cerr << "Details: " << exc->what() << std::endl;
        std::exit(1);
    }
);
```

**Thread safety.** Background `onFailure` calls run on the heartbeat thread with no SDK lock held. Calling `Logout()`, `IsAuthenticated()` or `Login()` from the callback, or destroying the client inside it, is safe. `Logout()` stops check-ins without blocking; the destructor stops the heartbeat thread and joins it (waiting for an in-flight check-in, if any).

## Self-ban (tamper response)

Use `SelfBan(...)` when anti-tamper checks trigger:

```cpp
// Post-session (authenticated): defaults to revoke + HWID/IP blacklist.
client.SelfBan();

// Pre-session: pass license key, SDK automatically disables revokeLicense.
client.SelfBan("AF-XXXX-XXXX-XXXX");

// Custom flags:
client.SelfBan("", "", false, true, true);
```

`SelfBan(...)` chooses request mode automatically:
- Uses post-session mode when a session token is available (`sessionToken` arg or current SDK session).
- Falls back to pre-session mode with `licenseKey` + nonce + app secret.
- In pre-session mode, revoke is always disabled client-side to avoid unsafe key revocations.
- Not available after `LoginFromFile()`: offline sessions have no server session, so `SelfBan()` with no explicit `licenseKey` / `sessionToken` returns `false` and reports `onFailure("selfban_failed", &exc)` with `exc.what()` = `offline_session`, without contacting the server.

## How It Works

1. **Activate**: `Login` uses `hwidOverride` when non-empty; otherwise it collects a hardware fingerprint (MAC, CPU, disk serial). It then generates a random nonce and sends everything to the AuthForge API. The server validates the license key, binds the HWID, deducts a credit, and returns a signed payload. The SDK verifies the Ed25519 signature and nonce to prevent replay attacks.

2. **Background checks**: a background thread runs at the configured interval (`Logout()` stops it; the destructor joins it). By default it re-verifies the stored signed session locally and enforces the grace period without network calls. With online check-ins enabled, it instead sends a fresh nonce to `/auth/heartbeat` and verifies the response.

3. **Crypto**: both `/validate` and `/heartbeat` responses are signed by AuthForge with your app's Ed25519 private key. The SDK verifies every signed `payload` using your configured `publicKey` and rejects tampered responses.

## Test Vectors

The shared `test_vectors.json` file validates cross-language Ed25519 verification behavior. `offline_license_vectors.json` (generated from a fixed test seed in the Node SDK repo) is the cross-SDK conformance suite for `.authforge` offline license files: good files plus the `bad_signature`, wrong key, `wrong_app`, `expired`, `hwid_mismatch`, `unsupported_version` and `bad_armor` rejects. `tests/heartbeat_test.cpp` covers the heartbeat failure contract (classification, retries, session clearing, callback thread safety) against a fake transport. Run both with:

```bash
cmake -S . -B build -DAUTHFORGE_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

## Requirements

- C++17
- libsodium
- OpenSSL
- libcurl

## License

MIT
