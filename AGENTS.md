# AuthForge SDK — AI Agent Reference

> This file is optimized for AI coding agents (Cursor, Copilot, Claude Code, etc.).
> It contains everything needed to correctly integrate AuthForge licensing into a project.

## What AuthForge does

AuthForge is a license key validation service. Your app sends a license key + hardware ID to the AuthForge API, gets back a cryptographically signed response, and runs background heartbeats to maintain the session. If the license is revoked or expired, the heartbeat fails and you handle it (typically exit the app).

## Installation

Add `authforge_sdk.h` and `authforge_sdk.cpp` to your project. Requires C++17, OpenSSL, and libcurl (see README for CMake).

## Minimal working integration

```cpp
#include "authforge_sdk.h"
#include <cstdlib>
#include <iostream>
#include <string>

int main() {
  authforge::AuthForgeClient client(
      "YOUR_APP_ID",
      "YOUR_APP_SECRET",
      "SERVER",
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
| `appId` | `std::string` | yes | — | Application ID |
| `appSecret` | `std::string` | yes | — | Application secret |
| `heartbeatMode` | `std::string` | yes | — | `"SERVER"` or `"LOCAL"` |
| `heartbeatInterval` | `int` | no | `900` | Seconds between heartbeats |
| `apiBaseUrl` | `std::string` | no | `kDefaultApiBaseUrl` (`https://auth.authforge.cc`) | API base URL |
| `onFailure` | `std::function<void(const std::string&, const std::exception*)>` | no | `nullptr` | Failure callback; if null, `std::exit(1)` |
| `requestTimeout` | `int` | no | `15` | HTTP timeout (seconds) |

## Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `Login(const std::string&)` | `bool` | Validates license and starts heartbeat |
| `Logout()` | `void` | Stops heartbeat and clears state |
| `IsAuthenticated()` | `bool` | Whether authenticated |
| `GetSessionDataJson()` | `std::optional<std::string>` | Payload JSON string |
| `GetAppVariablesJson()` | `std::optional<std::string>` | App variables JSON |
| `GetLicenseVariablesJson()` | `std::optional<std::string>` | License variables JSON |

## Error codes the server can return

invalid_app, invalid_key, expired, revoked, hwid_mismatch, no_credits, blocked, rate_limited, replay_detected, checksum_required, checksum_mismatch, session_expired, app_disabled

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

- Do not hardcode the app secret as a plain string literal in source — use environment variables or encrypted config
- Do not omit `onFailure` — without it, failures call `std::exit(1)` without your cleanup
- Do not call `Login` on every app action — call once at startup; heartbeats handle the rest
- Do not use `heartbeatMode` `"LOCAL"` unless the app has no internet after initial auth
