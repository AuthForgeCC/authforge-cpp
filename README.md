# AuthForge C++ SDK

Official C++ SDK for [AuthForge](https://authforge.cc) — credit-based license key authentication with Ed25519-verified responses.

**Minimal dependencies.** libsodium (Ed25519 verification), OpenSSL (SHA-256/HWID hashing), and libcurl (HTTP). Targets C++17. Works on Windows (MSVC), Linux (GCC/Clang), and macOS (Clang).

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
        "YOUR_PUBLIC_KEY",       // base64 Ed25519 public key from dashboard
        "SERVER"                 // "SERVER" or "LOCAL"
    );

    std::string key;
    std::cout << "Enter license key: ";
    std::getline(std::cin, key);

    if (client.Login(key)) {
        std::cout << "Authenticated!" << std::endl;
        // Your app logic here — heartbeats run automatically in the background
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
mkdir build && cd build
cmake ..
cmake --build .
```

Requires OpenSSL, libsodium, and libcurl to be findable by CMake. On Linux, for example: `apt install libssl-dev libsodium-dev libcurl4-openssl-dev`.

## Configuration

| Parameter | Type | Default | Description |
|---|---|---|---|
| `appId` | string | required | Your application ID from the AuthForge dashboard |
| `appSecret` | string | required | Your application secret from the AuthForge dashboard |
| `publicKey` | string | required | App Ed25519 public key (base64) from dashboard |
| `heartbeatMode` | string | required | `"SERVER"` or `"LOCAL"` (see below) |
| `heartbeatInterval` | int | `900` | Seconds between heartbeat checks (default 15 min) |
| `apiBaseUrl` | string | `https://auth.authforge.cc` | API endpoint |
| `onFailure` | std::function | `nullptr` | Callback `(const string&, const exception*)` on auth failure |
| `requestTimeout` | int | `15` | HTTP request timeout in seconds |

## Methods

| Method | Returns | Description |
|---|---|---|
| `Login(const std::string&)` | `bool` | Validates key and stores signed session (`sessionToken`, `expiresIn`, `appVariables`, `licenseVariables`) |
| `Logout()` | `void` | Stops heartbeat and clears all session/auth state |
| `IsAuthenticated()` | `bool` | True when an active authenticated session exists |
| `GetSessionDataJson()` | `std::optional<std::string>` | Full decoded payload JSON |
| `GetAppVariablesJson()` | `std::optional<std::string>` | App variables JSON (if present) |
| `GetLicenseVariablesJson()` | `std::optional<std::string>` | License variables JSON (if present) |

## Heartbeat Modes

**SERVER** — The SDK calls `/auth/heartbeat` every `heartbeatInterval` seconds with a fresh nonce, verifies signature + nonce, and triggers failure on invalid session state.

**LOCAL** — No network calls. The SDK re-verifies stored signature state and checks expiry timestamp locally. If expired, it triggers failure with `session_expired`.

## Failure Handling

If authentication fails, the SDK calls your `onFailure` callback if one is provided. If no callback is set, **the SDK calls `std::exit(1)` to terminate the process.** This is intentional — it prevents your app from running without a valid license.

Recognized server errors:
`invalid_app`, `invalid_key`, `expired`, `revoked`, `hwid_mismatch`, `no_credits`, `blocked`, `rate_limited`, `replay_detected`, `app_disabled`, `session_expired`, `bad_request`

Request retries are automatic inside the internal HTTP layer:
- `rate_limited`: retry after 2s, then 5s (max 3 attempts total)
- network failure: retry once after 2s
- every retry regenerates a fresh nonce

```cpp
authforge::AuthForgeClient client(
    "YOUR_APP_ID",
    "YOUR_APP_SECRET",
    "YOUR_PUBLIC_KEY",
    "SERVER",
    900,
    authforge::AuthForgeClient::kDefaultApiBaseUrl,
    [](const std::string& reason, const std::exception* exc) {
        std::cerr << "Auth failed: " << reason << std::endl;
        if (exc) std::cerr << "Details: " << exc->what() << std::endl;
        std::exit(1);
    }
);
```

## How It Works

1. **Login** — Collects a hardware fingerprint (MAC, CPU, disk serial), generates a random nonce, and sends everything to the AuthForge API. The server validates the license key, binds the HWID, deducts a credit, and returns a signed payload. The SDK verifies the Ed25519 signature and nonce to prevent replay attacks.

2. **Heartbeat** — A detached background thread checks in at the configured interval. In SERVER mode, it sends a fresh nonce and verifies the response. In LOCAL mode, it re-verifies the stored signature and checks expiry without network calls.

3. **Crypto** — Both `/validate` and `/heartbeat` responses are signed by AuthForge with your app's Ed25519 private key. The SDK verifies every signed `payload` using your configured `publicKey` and rejects tampered responses.

## Test Vectors

The shared `test_vectors.json` file validates cross-language Ed25519 verification behavior.

## Requirements

- C++17
- OpenSSL
- libsodium
- libcurl

## License

MIT
