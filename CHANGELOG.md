# Changelog

## 1.4.0

### Behavior changes for callers

- **New `authforge::AuthForgeError`** (`code()`, `isTransient()`, `isFatal()`) is thrown by the online APIs and passed as `exc` to `onFailure` (`login_failed`, `heartbeat_failed`, `selfban_failed`). For server codes `what()` equals the code. `authforge::IsTransientErrorCode(code)` exposes the same classification.
- **Classification.** Only `revoked`, `expired`, `hwid_mismatch`, `blocked`, `session_expired`, `malformed_request`, `app_disabled`, `invalid_app` and the SDK-local `signature_mismatch` are definitive. Everything else is transient, including `no_credits`, `demo_quota_exceeded`, `app_burn_cap_reached`, `bad_request`, `invalid_key`, every `http_error_<status>`, network errors, timeouts and unknown codes. Grace period expiry, and a transient failure after the session TTL has passed, report `session_expired`.
- **Transient heartbeat failures keep checking in.** Previously the background loop stopped after any failure. Now the session is kept, `onFailure` runs, and the next check happens at the next interval.
- **Definitive heartbeat failures clear the session** (as `Logout()` does) before `onFailure` runs, so `IsAuthenticated()` is `false` inside and after the callback, and check-ins stop. Previously the session stayed authenticated.
- **Clean codes for non-2xx JSON responses on both login and heartbeat.** `what()` is `invalid_key` instead of `http_error_401: {...}`; this also changes `ValidateLicenseResult::errorCode`. Only non-JSON error pages become `http_error_<status>`.
- **New `unexpected_response` code (transient).** A failed check-in counts as a verdict only when the body is a JSON object with `"status": "failed"` and a non-empty string `error`.
- **Rate-limit retry.** Only `rate_limited`, or HTTP 429 without an error code, is retried (after 2s, then 5s). HTTP 429 `no_credits`, `app_burn_cap_reached` and `demo_quota_exceeded` are no longer retried. Network failures (after one retry) are `network_error` or `timeout`, with `what()` still `url_error: ...`.
- **Unknown server codes are passed through** (lowercase snake_case) instead of becoming `unknown_error`.
- **The heartbeat thread is no longer detached.** `Logout()` and the destructor interrupt the interval wait; the destructor joins the thread. `onFailure` runs with no SDK lock held, so calling `Logout()` / `IsAuthenticated()` from it, or destroying the client inside it, is supported. A check-in in flight across `Logout()` / `Login()` no longer writes its result back.
- **ABI change.** New private members change the `AuthForgeClient` class layout. Rebuild everything that includes `authforge_sdk.h`.
