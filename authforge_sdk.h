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
};

class AuthForgeClient {
public:
  static constexpr const char *kDefaultApiBaseUrl = "https://auth.authforge.cc";

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
  void LocalHeartbeat();
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

  std::string appId_;
  std::string appSecret_;
  std::string publicKey_;
  std::string heartbeatMode_;
  int heartbeatInterval_;
  std::string apiBaseUrl_;
  std::function<void(const std::string &, const std::exception *)> onFailure_;
  int requestTimeout_;
  // Requested session token lifetime in seconds for /auth/validate. 0 means
  // "let the server pick its default" (24h today). Server clamps to
  // [3600, 604800]; preserved across heartbeat refreshes.
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
  std::vector<unsigned char> verifyPublicKeyBytes_;
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
      "system_error",
  };
};

} // namespace authforge
