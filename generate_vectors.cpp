#include <cstring>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/hmac.h>
#include <openssl/sha.h>

namespace {

constexpr const char *APP_SECRET = "af_test_secret_2026_reference";
constexpr const char *SIG_KEY = "af_test_sig_key_2026_reference_0123456789abcdef";
constexpr const char *NONCE = "0123456789abcdeffedcba9876543210";
constexpr const char *SESSION_SIGNING_SECRET = "authforge-dev-session-signing-secret-rotate-before-production";

std::string HexLower(const std::vector<unsigned char> &bytes) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (unsigned char b : bytes) {
    out.push_back(kHex[(b >> 4) & 0x0F]);
    out.push_back(kHex[b & 0x0F]);
  }
  return out;
}

std::string Base64Encode(const std::vector<unsigned char> &bytes) {
  static constexpr char kTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((bytes.size() + 2) / 3) * 4);

  std::size_t i = 0;
  while (i + 3 <= bytes.size()) {
    const unsigned int n =
        (static_cast<unsigned int>(bytes[i]) << 16) |
        (static_cast<unsigned int>(bytes[i + 1]) << 8) |
        static_cast<unsigned int>(bytes[i + 2]);
    out.push_back(kTable[(n >> 18) & 0x3F]);
    out.push_back(kTable[(n >> 12) & 0x3F]);
    out.push_back(kTable[(n >> 6) & 0x3F]);
    out.push_back(kTable[n & 0x3F]);
    i += 3;
  }

  const std::size_t rem = bytes.size() - i;
  if (rem == 1) {
    const unsigned int n = static_cast<unsigned int>(bytes[i]) << 16;
    out.push_back(kTable[(n >> 18) & 0x3F]);
    out.push_back(kTable[(n >> 12) & 0x3F]);
    out.push_back('=');
    out.push_back('=');
  } else if (rem == 2) {
    const unsigned int n =
        (static_cast<unsigned int>(bytes[i]) << 16) |
        (static_cast<unsigned int>(bytes[i + 1]) << 8);
    out.push_back(kTable[(n >> 18) & 0x3F]);
    out.push_back(kTable[(n >> 12) & 0x3F]);
    out.push_back(kTable[(n >> 6) & 0x3F]);
    out.push_back('=');
  }
  return out;
}

std::string Base64UrlNoPad(const std::vector<unsigned char> &bytes) {
  std::string out = Base64Encode(bytes);
  for (char &c : out) {
    if (c == '+') {
      c = '-';
    } else if (c == '/') {
      c = '_';
    }
  }
  while (!out.empty() && out.back() == '=') {
    out.pop_back();
  }
  return out;
}

std::vector<unsigned char> Sha256(const std::string &input) {
  std::vector<unsigned char> digest(SHA256_DIGEST_LENGTH);
  SHA256(reinterpret_cast<const unsigned char *>(input.data()), input.size(), digest.data());
  return digest;
}

std::vector<unsigned char> HmacSha256(const std::vector<unsigned char> &key, const std::string &message) {
  unsigned int outLen = SHA256_DIGEST_LENGTH;
  std::vector<unsigned char> digest(SHA256_DIGEST_LENGTH);
  unsigned char *result = HMAC(
      EVP_sha256(),
      key.data(),
      static_cast<int>(key.size()),
      reinterpret_cast<const unsigned char *>(message.data()),
      message.size(),
      digest.data(),
      &outLen);
  if (result == nullptr || outLen != SHA256_DIGEST_LENGTH) {
    throw std::runtime_error("hmac_failed");
  }
  digest.resize(outLen);
  return digest;
}

std::string EscapeJson(const std::string &value) {
  std::ostringstream oss;
  for (unsigned char ch : value) {
    switch (ch) {
    case '\\':
      oss << "\\\\";
      break;
    case '"':
      oss << "\\\"";
      break;
    case '\b':
      oss << "\\b";
      break;
    case '\f':
      oss << "\\f";
      break;
    case '\n':
      oss << "\\n";
      break;
    case '\r':
      oss << "\\r";
      break;
    case '\t':
      oss << "\\t";
      break;
    default:
      if (ch < 0x20U) {
        oss << "\\u00";
        oss << "0123456789abcdef"[(ch >> 4) & 0x0F];
        oss << "0123456789abcdef"[ch & 0x0F];
      } else {
        oss << static_cast<char>(ch);
      }
      break;
    }
  }
  return oss.str();
}

std::string BuildRealisticSessionToken() {
  const std::string bodyJson =
      std::string("{\"appId\":\"test-app\",\"licenseKey\":\"test-key\",\"hwid\":\"testhwid\",\"sigKey\":\"") +
      SIG_KEY +
      "\",\"expiresIn\":1740433200}";
  const std::vector<unsigned char> bodyBytes(bodyJson.begin(), bodyJson.end());
  const std::string bodyB64 = Base64UrlNoPad(bodyBytes);

  const std::vector<unsigned char> keyBytes(SESSION_SIGNING_SECRET, SESSION_SIGNING_SECRET + std::strlen(SESSION_SIGNING_SECRET));
  const std::vector<unsigned char> digest = HmacSha256(keyBytes, bodyB64);
  const std::string sigB64 = Base64UrlNoPad(digest);
  return bodyB64 + "." + sigB64;
}

std::string BuildPayloadB64() {
  const std::string sessionToken = BuildRealisticSessionToken();
  const std::string payloadJson =
      std::string("{\"sessionToken\":\"") + EscapeJson(sessionToken) +
      "\",\"timestamp\":1740429600,\"expiresIn\":1740433200,\"nonce\":\"" + NONCE + "\"}";
  const std::vector<unsigned char> payloadBytes(payloadJson.begin(), payloadJson.end());
  return Base64Encode(payloadBytes);
}

std::string BuildVectorsJson(
    const std::string &payload,
    const std::string &validateKeyHex,
    const std::string &validateSigHex,
    const std::string &heartbeatKeyHex,
    const std::string &heartbeatSigHex) {
  std::ostringstream oss;
  oss
      << "{\n"
      << "  \"validate\": {\n"
      << "    \"algorithm\": {\n"
      << "      \"keyDerivation\": \"SHA256(appSecret + nonce)\",\n"
      << "      \"signature\": \"HMAC-SHA256(raw_base64_payload_string, derivedKey)\"\n"
      << "    },\n"
      << "    \"inputs\": {\n"
      << "      \"appSecret\": \"" << APP_SECRET << "\",\n"
      << "      \"nonce\": \"" << NONCE << "\",\n"
      << "      \"payload\": \"" << EscapeJson(payload) << "\"\n"
      << "    },\n"
      << "    \"outputs\": {\n"
      << "      \"derivedKeyHex\": \"" << validateKeyHex << "\",\n"
      << "      \"signatureHex\": \"" << validateSigHex << "\"\n"
      << "    }\n"
      << "  },\n"
      << "  \"heartbeat\": {\n"
      << "    \"algorithm\": {\n"
      << "      \"keyDerivation\": \"SHA256(sigKey + nonce)\",\n"
      << "      \"signature\": \"HMAC-SHA256(raw_base64_payload_string, derivedKey)\"\n"
      << "    },\n"
      << "    \"inputs\": {\n"
      << "      \"sigKey\": \"" << SIG_KEY << "\",\n"
      << "      \"nonce\": \"" << NONCE << "\",\n"
      << "      \"payload\": \"" << EscapeJson(payload) << "\"\n"
      << "    },\n"
      << "    \"outputs\": {\n"
      << "      \"derivedKeyHex\": \"" << heartbeatKeyHex << "\",\n"
      << "      \"signatureHex\": \"" << heartbeatSigHex << "\"\n"
      << "    }\n"
      << "  }\n"
      << "}";
  return oss.str();
}

} // namespace

int main() {
  const std::string payload = BuildPayloadB64();

  const std::vector<unsigned char> validateKey = Sha256(std::string(APP_SECRET) + NONCE);
  const std::vector<unsigned char> validateSig = HmacSha256(validateKey, payload);

  const std::vector<unsigned char> heartbeatKey = Sha256(std::string(SIG_KEY) + NONCE);
  const std::vector<unsigned char> heartbeatSig = HmacSha256(heartbeatKey, payload);

  const std::string vectorsJson = BuildVectorsJson(
      payload,
      HexLower(validateKey),
      HexLower(validateSig),
      HexLower(heartbeatKey),
      HexLower(heartbeatSig));
  std::ofstream out("test_vectors.json", std::ios::binary);
  if (!out.is_open()) {
    return 1;
  }
  out.write(vectorsJson.data(), static_cast<std::streamsize>(vectorsJson.size()));
  out.close();
  return 0;
}
