# AuthForge C++ SDK

Official C++ SDK for [AuthForge](https://authforge.cc) — credit-based license key authentication with HMAC-verified heartbeats.

**Minimal dependencies.** OpenSSL (crypto) and libcurl (HTTP) only. Targets C++17. Works on Windows (MSVC), Linux (GCC/Clang), and macOS (Clang).

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

Requires OpenSSL and libcurl to be findable by CMake. On most Linux distros these are available via package manager (e.g. `apt install libssl-dev libcurl4-openssl-dev`). On macOS, both ship with Xcode or can be installed via Homebrew. On Windows, use vcpkg or provide paths manually.

## Configuration

| Parameter | Type | Default | Description |
|---|---|---|---|
| `appId` | string | required | Your application ID from the AuthForge dashboard |
| `appSecret` | string | required | Your application secret from the AuthForge dashboard |
| `heartbeatMode` | string | required | `"SERVER"` or `"LOCAL"` (see below) |
| `heartbeatInterval` | int | `900` | Seconds between heartbeat checks (default 15 min) |
| `apiBaseUrl` | string | `https://auth.authforge.cc` | API endpoint |
| `onFailure` | std::function | `nullptr` | Callback `(const string&, const exception*)` on auth failure |
| `requestTimeout` | int | `15` | HTTP request timeout in seconds |

## Heartbeat Modes

**SERVER** — The SDK pings the AuthForge API every `heartbeatInterval` seconds with a fresh nonce. Each response is cryptographically verified. If the license is revoked or the session expires, the failure handler triggers.

**LOCAL** — No network requests during heartbeats. The SDK verifies the stored HMAC signature and checks that the session hasn't expired. When the prepaid block runs out, it makes a single network call to refresh. Use this for apps where you want minimal network overhead.

## Failure Handling

If authentication fails, the SDK calls your `onFailure` callback if one is provided. If no callback is set, **the SDK calls `std::exit(1)` to terminate the process.** This is intentional — it prevents your app from running without a valid license.

```cpp
authforge::AuthForgeClient client(
    "YOUR_APP_ID",
    "YOUR_APP_SECRET",
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

1. **Login** — Collects a hardware fingerprint (MAC, CPU, disk serial), generates a random nonce, and sends everything to the AuthForge API. The server validates the license key, binds the HWID, deducts a credit, and returns a signed payload. The SDK verifies the HMAC-SHA256 signature and nonce to prevent replay attacks.

2. **Heartbeat** — A detached background thread checks in at the configured interval. In SERVER mode, it sends a fresh nonce and verifies the response. In LOCAL mode, it re-verifies the stored signature and checks expiry without network calls.

3. **Crypto** — Every response is signed with a key derived from `SHA256(appSecret + nonce)`. The signing key changes on every call, making replay and MITM attacks impractical.

## Test Vectors

The `generate_vectors.cpp` program and `test_vectors.json` file are provided for cross-SDK verification. This SDK produces identical cryptographic outputs to the Python and C# reference implementations.

## Requirements

- C++17
- OpenSSL
- libcurl

## License

MIT
