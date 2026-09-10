#pragma once

#include <cstdint>
#include <exception>
#include <functional>
#include <mutex>
#include <optional>
#include <unordered_set>
#include <string>
#include <utility>
#include <vector>

namespace authforge {

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

class AuthForgeClient {
public:
  static constexpr const char *kDefaultApiBaseUrl = "https://auth.authforge.cc";

  /// Single-key constructor. The provided string may also be a
  /// comma-separated trust list (current,previous) so callers can roll a key
  /// by re-deploying with an env var change.
  ///
  /// ttlSeconds requests the grace period duration in seconds for
  /// /auth/validate (how long the app keeps running on the signed session
  /// without contacting AuthForge). 0 means the server default (24h today);
  /// the server clamps requested values to 1h..7d.
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
  std::optional<std::string> GetSessionDataJson() const;
  std::optional<std::string> GetAppVariablesJson() const;
  std::optional<std::string> GetLicenseVariablesJson() const;

private:
  struct JsonValue {
    bool exists = false;
    bool isString = false;
    std::string value;
  };

  enum class SigningContext { Validate, Heartbeat };

  void StartHeartbeatOnce();
  void HeartbeatLoop() noexcept;
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
      ValidateLicenseResult *validateOnlyOut = nullptr);

  std::string PostJson(const std::string &path, const std::string &bodyJson, std::string *usedNonce = nullptr) const;
  std::string ExtractServerError(const std::string &responseJson) const;
  void Fail(const std::string &reason, const std::exception *exc = nullptr) const noexcept;

  std::string GetHwid() const;
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

  mutable std::mutex lock_;
  bool heartbeatStarted_;

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
  bool heartbeatStop_ = false;
  std::string hwid_;
  std::unordered_set<std::string> knownServerErrors_ = {
      "invalid_app",
      "invalid_key",
      "expired",
      "revoked",
      "hwid_mismatch",
      "no_credits",
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
