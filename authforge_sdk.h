#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <thread>
#include <unordered_set>
#include <string>
#include <utility>
#include <vector>

namespace authforge {

/// True unless `code` is a definitive AuthForge verdict. Definitive codes:
/// revoked, expired, hwid_mismatch, blocked, session_expired,
/// malformed_request, app_disabled, invalid_app and the SDK-local
/// signature_mismatch. Everything else (http_error_N, network_error, timeout,
/// no_credits, rate_limited, unknown codes, ...) is transient.
bool IsTransientErrorCode(const std::string &code);

/// Error thrown by the online APIs and passed to onFailure. For server codes
/// what() equals code().
class AuthForgeError : public std::runtime_error {
public:
  explicit AuthForgeError(const std::string &code) : std::runtime_error(code), code_(code) {}
  AuthForgeError(const std::string &code, const std::string &message)
      : std::runtime_error(message), code_(code) {}

  const std::string &code() const noexcept { return code_; }
  /// Transient failures keep the session; background check-ins continue.
  bool isTransient() const { return IsTransientErrorCode(code_); }
  /// Definitive failures clear the session and stop background check-ins.
  bool isFatal() const { return !isTransient(); }

private:
  std::string code_;
};

struct ValidateLicenseResult {
  bool valid = false;
  std::string errorCode;
  std::string sessionToken;
  long long expiresIn = 0;
  std::string sessionDataJson;
  std::string appVariablesJson;
  std::string licenseVariablesJson;
  std::string keyId;
  std::optional<std::string> sessionExpiresAt;
  bool licenseExpirationKnown = false;
  /// ISO 8601 when `licenseExpirationKnown` and key is dated; empty when lifetime.
  std::string licenseExpiresAt;
  std::optional<int> maxHwidSlots;
  std::optional<int> hwidCount;
  std::optional<std::string> licenseLabel;
};

/// Opt-in policy for online check-ins after a successful activation.
///
/// Off (the default): after the client activates online via /auth/validate it
/// keeps running on the Ed25519-signed session for the duration of the grace
/// period (the session TTL: default 24h, server clamps 1h to 7d) without
/// contacting AuthForge. The background loop re-verifies the signed session
/// locally and fails once the grace period ends.
///
/// On: the client additionally performs online check-ins, periodic calls to
/// POST /auth/heartbeat every heartbeatInterval seconds, for fast revocation
/// and concurrent-use detection.
///
/// Deliberately an enum class rather than bool: a bool fourth parameter would
/// let legacy calls such as AuthForgeClient(a, b, key, "LOCAL") silently bind
/// through the const char* to bool standard conversion.
enum class OnlineHeartbeat { Off, On };

/// Kind of session the client currently holds: an online server session
/// (Login), an offline license file (LoginFromFile), or none.
enum class SessionKind { None, Online, Offline };

// ---------------------------------------------------------------------------
// Offline license files (`.authforge`)
//
// A cloud-minted, Ed25519-signed document for machines that never phone home.
// This is a SEPARATE mode from the grace period: the grace period continues a
// signed session after one online activation, while an offline file is
// verified locally with only the app public key and the machine HWID. Nothing
// here performs network I/O or starts online check-ins.
//
// Format (version 1): PEM-style armor with informational headers, a base64
// JSON payload wrapped at 64 columns, and a detached Ed25519 signature over
// the UTF-8 bytes of the base64 payload string (body lines joined, whitespace
// removed) - the same contract as /auth/validate.
// ---------------------------------------------------------------------------

/// The only `.authforge` format version this SDK accepts.
constexpr int kOfflineLicenseFileVersion = 1;

/// HWID binding policy embedded in a `.authforge` file.
struct OfflineHwidPolicy {
  /// "bound" (verify only when the local HWID is in `hwids`) or "any".
  std::string mode;
  std::vector<std::string> hwids;
};

/// Verified content of a `.authforge` file.
struct OfflineLicense {
  std::string appId;
  std::string licenseKey;
  /// Unique id of this minted file.
  std::string jti;
  /// App signing key id that signed the file.
  std::string keyId;
  std::string issuedAt;
  /// ISO 8601 file expiry; std::nullopt for a lifetime file.
  std::optional<std::string> expiresAt;
  OfflineHwidPolicy hwidPolicy;
  std::optional<std::string> label;
  /// True when the payload carried `licenseExpiresAt` (lifetime licenses use JSON null).
  bool licenseExpirationKnown = false;
  /// License expiry when `licenseExpirationKnown` and dated; empty when lifetime.
  std::string licenseExpiresAt;
  /// Raw JSON object text (empty when absent).
  std::string licenseVariablesJson;
  std::string appVariablesJson;
  /// Full decoded payload JSON text (unknown fields preserved).
  std::string payloadJson;
  /// Canonical signed string and its signature.
  std::string payloadBase64;
  std::string signatureBase64;
};

/// Raw armor split into parts.
struct ParsedLicenseFile {
  std::vector<std::pair<std::string, std::string>> headers;
  /// Exactly the string the signature covers.
  std::string payloadBase64;
  std::string signatureBase64;
};

/// Result of VerifyLicenseFile.
struct VerifyLicenseFileResult {
  bool ok = false;
  /// Cross-SDK error code when !ok: bad_armor, bad_signature,
  /// unsupported_version, malformed_payload, wrong_app, expired,
  /// hwid_mismatch (or "read_error: ..." from the client path helpers).
  std::string error;
  OfflineLicense license;
};

/// Parse armored `.authforge` text. Returns std::nullopt when the armor is
/// malformed. Tolerates CRLF, a UTF-8 BOM, any re-wrapping of the base64 body
/// and text before/after the armor.
std::optional<ParsedLicenseFile> ParseLicenseFile(const std::string &text);

/// Verify armored `.authforge` text with NO network access. Check order
/// (fixed across every SDK): bad_armor -> bad_signature -> unsupported_version
/// -> malformed_payload -> wrong_app -> expired -> hwid_mismatch. The
/// signature is checked before the payload JSON is decoded.
///
/// `publicKeys` are raw-32-byte Ed25519 keys in standard base64 (entries may
/// themselves be comma-separated). `hwid` is the local machine id (required
/// for bound files). `nowEpochMs` overrides the clock (tests); 0 means now.
VerifyLicenseFileResult VerifyLicenseFile(
    const std::string &file,
    const std::string &appId,
    const std::vector<std::string> &publicKeys,
    const std::string &hwid,
    long long nowEpochMs = 0);

/// Parse `YYYY-MM-DDTHH:MM:SS[.fff][Z|+HH:MM]` into epoch milliseconds.
std::optional<long long> ParseIso8601Ms(const std::string &value);

/// Optional fields for AuthForgeClient::CreateActivationRequest.
/// machineName is omitted unless includeMachineName is true.
struct ActivationRequestOptions {
  bool includeMachineName = false;
  bool omitOs = false;
  bool omitSdk = false;
  std::string machineName;
  std::string os;
  std::string sdk;
  std::string licenseKey;
  std::string createdAt;
};

/// Armored `.authforge-request` text from explicit fields. Empty optional
/// strings are omitted from the payload.
std::string FormatActivationRequest(const std::string &appId, const std::string &hwid,
                                    const std::string &createdAt, const std::string &machineName = "",
                                    const std::string &os = "", const std::string &sdk = "",
                                    const std::string &licenseKey = "");

class AuthForgeClient {
public:
  static constexpr const char *kDefaultApiBaseUrl = "https://auth.authforge.cc";

  /// Single-key constructor. The provided string may also be a
  /// comma-separated trust list (current,previous) so callers can roll a key
  /// by re-deploying with an env var change.
  ///
  /// appSecret may be empty when the client will only call LoginFromFile
  /// (air-gapped builds should not ship the secret). Online APIs still
  /// require a non-empty secret.
  ///
  /// ttlSeconds requests the grace period duration in seconds for
  /// /auth/validate (how long the app keeps running on the signed session
  /// without contacting AuthForge). 0 means the server default (24h today);
  /// the server clamps requested values to 1h..7d.
  ///
  /// Without onFailure, a transient background check failure writes a
  /// one-line warning to stderr and check-ins continue; any other failure
  /// calls std::exit(1).
  AuthForgeClient(
      std::string appId,
      std::string appSecret,
      std::string publicKey,
      OnlineHeartbeat onlineHeartbeat = OnlineHeartbeat::Off,
      int heartbeatInterval = 900,
      std::string apiBaseUrl = kDefaultApiBaseUrl,
      std::function<void(const std::string &, const std::exception *)> onFailure = nullptr,
      int requestTimeout = 15,
      int ttlSeconds = 0,
      std::string hwidOverride = "");

  /// Rotation-aware constructor. The first entry should be the *current* key
  /// (it is reflected back through GetPublicKey() for diagnostics);
  /// subsequent entries are still trusted to support overlap windows.
  ///
  /// See the single-key constructor for the onlineHeartbeat and ttlSeconds
  /// (grace period duration) semantics.
  AuthForgeClient(
      std::string appId,
      std::string appSecret,
      std::vector<std::string> publicKeys,
      OnlineHeartbeat onlineHeartbeat = OnlineHeartbeat::Off,
      int heartbeatInterval = 900,
      std::string apiBaseUrl = kDefaultApiBaseUrl,
      std::function<void(const std::string &, const std::exception *)> onFailure = nullptr,
      int requestTimeout = 15,
      int ttlSeconds = 0,
      std::string hwidOverride = "");

  /// Legacy string-mode constructor kept for source compatibility. Validates
  /// heartbeatMode exactly as before (std::invalid_argument unless LOCAL or
  /// SERVER, case-insensitive) and delegates to the OnlineHeartbeat overload.
  [[deprecated("heartbeatMode strings are deprecated: LOCAL maps to the default grace period behavior (drop the argument) and SERVER maps to OnlineHeartbeat::On")]]
  AuthForgeClient(
      std::string appId,
      std::string appSecret,
      std::string publicKey,
      std::string heartbeatMode,
      int heartbeatInterval = 900,
      std::string apiBaseUrl = kDefaultApiBaseUrl,
      std::function<void(const std::string &, const std::exception *)> onFailure = nullptr,
      int requestTimeout = 15,
      int ttlSeconds = 0,
      std::string hwidOverride = "");

  /// Legacy string-mode rotation-aware constructor. See the deprecation note
  /// above; delegates to the OnlineHeartbeat overload.
  [[deprecated("heartbeatMode strings are deprecated: LOCAL maps to the default grace period behavior (drop the argument) and SERVER maps to OnlineHeartbeat::On")]]
  AuthForgeClient(
      std::string appId,
      std::string appSecret,
      std::vector<std::string> publicKeys,
      std::string heartbeatMode,
      int heartbeatInterval = 900,
      std::string apiBaseUrl = kDefaultApiBaseUrl,
      std::function<void(const std::string &, const std::exception *)> onFailure = nullptr,
      int requestTimeout = 15,
      int ttlSeconds = 0,
      std::string hwidOverride = "");

  /// Stops background check-ins and waits for the heartbeat thread. Safe to
  /// call from inside onFailure (the thread is detached instead of joined).
  ~AuthForgeClient();

  AuthForgeClient(const AuthForgeClient &) = delete;
  AuthForgeClient &operator=(const AuthForgeClient &) = delete;

  /// Returns the configured trust list. Useful for tests and observability.
  const std::vector<std::string> &GetPublicKeys() const noexcept { return publicKeys_; }

  bool Login(const std::string &licenseKey);
  /// Same cryptographic validation as Login without persisting session state or starting heartbeats.
  ValidateLicenseResult ValidateLicense(const std::string &licenseKey);
  bool SelfBan(const std::string &licenseKey = "",
               const std::string &sessionToken = "",
               bool revokeLicense = true,
               bool blacklistHwid = true,
               bool blacklistIp = true);
  void Logout();
  bool IsAuthenticated() const;
  /// SessionKind::Online after Login, SessionKind::Offline after
  /// LoginFromFile, SessionKind::None when logged out.
  SessionKind GetSessionKind() const;
  std::optional<std::string> GetSessionDataJson() const;
  std::optional<std::string> GetAppVariablesJson() const;
  std::optional<std::string> GetLicenseVariablesJson() const;

  /// The HWID this client sends to AuthForge (or hwidOverride). Customers on
  /// air-gapped machines report this value to the operator so an offline
  /// `.authforge` file can be bound to it.
  const std::string &GetHwid() const noexcept { return hwid_; }

  /// Build an activation request (`.authforge-request`) for this machine.
  /// No network, no session, no app secret. machineName is omitted unless
  /// options.includeMachineName is true.
  std::string CreateActivationRequest(const ActivationRequestOptions &options = ActivationRequestOptions()) const;

  /// Authorize from a cloud-minted offline license file (`.authforge`) with
  /// NO network access. Accepts a filesystem path or the armored text.
  ///
  /// On success the client is authenticated (IsAuthenticated,
  /// GetSessionDataJson, GetAppVariablesJson, GetLicenseVariablesJson work)
  /// and GetOfflineLicense() describes the file. No grace-period thread and
  /// no online check-ins are started - the file's own expiresAt is the only
  /// clock. Online Login is untouched.
  ///
  /// Failures are reported through onFailure("offline_login_failed", &exc)
  /// (exc.what() is the error code) and return false; unlike Login this never
  /// calls std::exit.
  bool LoginFromFile(const std::string &pathOrText);

  /// Verify a `.authforge` file (filesystem path or armored text) with this
  /// client's app id, public key(s) and HWID, without touching session state.
  VerifyLicenseFileResult VerifyLicenseFile(const std::string &pathOrText, long long nowEpochMs = 0) const;

  /// Details of the offline file the client authenticated with, if any.
  std::optional<OfflineLicense> GetOfflineLicense() const;

private:
  // Test-only: lets tests/offline_vectors_test.cpp drive the private
  // heartbeat entry point to prove it is a no-op for offline sessions.
  friend struct OfflineVectorsTestAccess;
  // Test-only: lets tests/heartbeat_test.cpp install the transport, sleep and
  // nonce seams, seed session state and drive HeartbeatTick directly.
  friend struct HeartbeatTestAccess;

  struct HttpResponse {
    bool transportOk = false;
    bool timedOut = false;
    std::string transportError;
    long status = 0;
    std::string body;
  };

  struct HeartbeatControl {
    std::atomic<bool> stop{false};
  };

  void ApplyOfflineLicense(const OfflineLicense &license);
  static std::string ReadLicenseFileInput(const std::string &pathOrText);
  struct JsonValue {
    bool exists = false;
    bool isString = false;
    std::string value;
  };

  enum class SigningContext { Validate, Heartbeat };

  void StartHeartbeatOnce();
  void HeartbeatLoop(std::shared_ptr<HeartbeatControl> control) noexcept;
  /// One background check. Returns false when check-ins must stop (a
  /// definitive failure). onFailure runs with no lock held and no member is
  /// touched after it returns, so the callback may destroy the client.
  bool HeartbeatTick();
  void ServerHeartbeat();
  /// Grace period check: re-verifies the stored signed session locally (no
  /// network) and fails with session_expired once the grace period ends.
  void GracePeriodCheck();
  void ValidateAndStore(const std::string &licenseKey);
  void ApplySignedResponse(
      const std::string &responseJson,
      const std::string &expectedNonce,
      const std::optional<std::string> &licenseKey,
      SigningContext context,
      bool persistToSession = true,
      ValidateLicenseResult *validateOnlyOut = nullptr,
      std::optional<std::uint64_t> expectedGeneration = std::nullopt);
  /// Clears the session and stops check-ins. With expectedGeneration, does
  /// nothing (and returns false) when the session changed since it was read.
  bool EndSession(std::optional<std::uint64_t> expectedGeneration);
  bool LocalSessionExpired() const;

  std::string PostJson(const std::string &path, const std::string &bodyJson, std::string *usedNonce = nullptr) const;
  static HttpResponse CurlPost(const std::string &url, const std::string &body, long timeoutSeconds);
  std::string ExtractServerError(const std::string &responseJson) const;
  void Fail(const std::string &reason, const std::exception *exc = nullptr) const noexcept;

  std::string ComputeHwid() const;
  std::string SafeMacAddress() const;
  std::string SafeCpuInfo() const;
  std::string SafeDiskSerial() const;
  std::string RunCommand(const std::string &command) const;

  static bool ExtractJsonValue(const std::string &json, const std::string &key, JsonValue &outValue);
  static std::optional<std::string> ExtractJsonString(const std::string &json, const std::string &key);
  static std::optional<long long> ExtractJsonInt(const std::string &json, const std::string &key);
  static std::string BuildJsonBody(const std::vector<std::pair<std::string, std::string>> &pairs);
  static std::string EscapeJsonString(const std::string &value);
  static std::string UnescapeJsonString(const std::string &value, bool &ok);
  static std::string Trim(const std::string &value);
  static std::string ToLower(std::string value);

  static std::string GenerateNonceHex32();
  static std::vector<unsigned char> Sha256Bytes(const std::string &input);
  static std::string Sha256Hex(const std::string &input);
  static std::string BytesToHexLower(const std::vector<unsigned char> &bytes);
  static std::vector<unsigned char> DecodeBase64Any(const std::string &value);
  static std::vector<unsigned char> DecodeBase64WithAlphabet(const std::string &value, bool urlSafe);
  static std::string AddBase64Padding(const std::string &value);
  static bool IsSuccessStatus(const JsonValue &status);
  static std::optional<long long> ExtractExpiresInFromSessionToken(const std::string &sessionToken);
  static std::optional<std::string> DecodeSessionTokenBody(const std::string &sessionToken);
  void VerifySignature(const std::string &rawPayloadB64, const std::string &signature) const;

  static std::vector<std::string> SplitCommaTrustList(const std::string &value);

  std::string appId_;
  std::string appSecret_;
  std::vector<std::string> publicKeys_;
  // True when online check-ins (periodic POST /auth/heartbeat) are enabled.
  bool onlineHeartbeat_;
  int heartbeatInterval_;
  std::string apiBaseUrl_;
  std::function<void(const std::string &, const std::exception *)> onFailure_;
  int requestTimeout_;
  // Requested grace period duration in seconds for /auth/validate (the
  // session token lifetime). 0 means "let the server pick its default"
  // (24h today). Server clamps to [3600, 604800]; preserved across
  // heartbeat refreshes.
  int ttlSeconds_;

  std::function<HttpResponse(const std::string &url, const std::string &body, long timeoutSeconds)> transport_;
  std::function<void(std::chrono::seconds)> sleep_;
  std::function<std::string()> nonce_;
  std::function<void(int)> exit_;

  mutable std::mutex lock_;
  bool heartbeatStarted_;
  std::thread heartbeatThread_;
  std::condition_variable heartbeatCv_;
  std::shared_ptr<HeartbeatControl> heartbeatControl_;
  // Bumped by Logout and every new online session; a heartbeat response only
  // writes back when the generation it started with is still current.
  std::uint64_t sessionGeneration_ = 0;

  std::string licenseKey_;
  std::string sessionToken_;
  std::optional<long long> sessionExpiresIn_;
  std::string lastNonce_;
  std::string rawPayloadB64_;
  std::string signature_;
  std::string keyId_;
  std::vector<std::vector<unsigned char>> verifyPublicKeysBytes_;
  std::string sessionDataJson_;
  std::string appVariablesJson_;
  std::string licenseVariablesJson_;
  bool authenticated_ = false;
  SessionKind sessionKind_ = SessionKind::None;
  std::string hwid_;
  std::optional<OfflineLicense> offlineLicense_;
  std::unordered_set<std::string> knownServerErrors_ = {
      "invalid_app",
      "invalid_key",
      "expired",
      "revoked",
      "hwid_mismatch",
      "no_credits",
      "demo_quota_exceeded",
      "app_burn_cap_reached",
      "blocked",
      "rate_limited",
      "replay_detected",
      "app_disabled",
      "session_expired",
      "revoke_requires_session",
      "bad_request",
      "malformed_request",
      "system_error",
  };
};

} // namespace authforge
