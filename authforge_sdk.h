#pragma once

#include <cstdint>
#include <exception>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace authforge {

class AuthForgeClient {
public:
  static constexpr const char *kDefaultApiBaseUrl = "https://auth.authforge.cc";

  AuthForgeClient(
      std::string appId,
      std::string appSecret,
      std::string heartbeatMode,
      int heartbeatInterval = 900,
      std::string apiBaseUrl = kDefaultApiBaseUrl,
      std::function<void(const std::string &, const std::exception *)> onFailure = nullptr,
      int requestTimeout = 15);

  bool Login(const std::string &licenseKey);

private:
  struct JsonValue {
    bool exists = false;
    bool isString = false;
    std::string value;
  };

  void StartHeartbeatOnce();
  void HeartbeatLoop() noexcept;
  void ServerHeartbeat();
  void LocalHeartbeat();
  void ValidateAndStore(const std::string &licenseKey);
  void ApplySignedResponse(const std::string &responseJson, const std::string &expectedNonce, const std::optional<std::string> &licenseKey);

  std::string PostJson(const std::string &path, const std::string &bodyJson) const;
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
  std::vector<unsigned char> DeriveKey(const std::string &nonce) const;
  static std::string HmacSha256HexLower(const std::vector<unsigned char> &key, const std::string &message);
  static std::string Sha256Hex(const std::string &input);
  static std::string BytesToHexLower(const std::vector<unsigned char> &bytes);
  static std::vector<unsigned char> DecodeBase64Any(const std::string &value);
  static std::vector<unsigned char> DecodeBase64WithAlphabet(const std::string &value, bool urlSafe);
  static std::string AddBase64Padding(const std::string &value);
  static bool IsSuccessStatus(const JsonValue &status);
  static std::optional<long long> ExtractExpiresInFromSessionToken(const std::string &sessionToken);
  static void VerifySignature(const std::string &rawPayloadB64, const std::vector<unsigned char> &derivedKey, const std::string &signature);

  std::string appId_;
  std::string appSecret_;
  std::string heartbeatMode_;
  int heartbeatInterval_;
  std::string apiBaseUrl_;
  std::function<void(const std::string &, const std::exception *)> onFailure_;
  int requestTimeout_;

  mutable std::mutex lock_;
  bool heartbeatStarted_;

  std::string licenseKey_;
  std::string sessionToken_;
  std::optional<long long> sessionExpiresIn_;
  std::string lastNonce_;
  std::string rawPayloadB64_;
  std::string signature_;
  std::vector<unsigned char> derivedKey_;
  std::string hwid_;
};

} // namespace authforge
