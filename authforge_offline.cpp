// Offline license files (`.authforge`) for the AuthForge C++ SDK.
//
// See authforge_sdk.h for the format description. Everything in this file is
// pure and local: no network, no threads. The tiny JSON reader below exists
// because the payload is a small, fully-specified document and the SDK has no
// JSON dependency; it is only ever run *after* the Ed25519 signature has been
// verified, so it never parses attacker-controlled bytes.

#include "authforge_sdk.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>

#include <sodium.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace authforge {

namespace {

constexpr const char *kBeginLicense = "-----BEGIN AUTHFORGE LICENSE-----";
constexpr const char *kEndLicense = "-----END AUTHFORGE LICENSE-----";
constexpr const char *kBeginSignature = "-----BEGIN AUTHFORGE SIGNATURE-----";
constexpr const char *kEndSignature = "-----END AUTHFORGE SIGNATURE-----";

std::string TrimCopy(const std::string &value) {
  std::size_t start = 0;
  while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start])) != 0) {
    ++start;
  }
  std::size_t end = value.size();
  while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1])) != 0) {
    --end;
  }
  return value.substr(start, end - start);
}

std::string StripWhitespace(const std::string &value) {
  std::string out;
  out.reserve(value.size());
  for (const char c : value) {
    if (std::isspace(static_cast<unsigned char>(c)) == 0) {
      out.push_back(c);
    }
  }
  return out;
}

bool IsBase64Text(const std::string &value) {
  if (value.empty()) {
    return false;
  }
  std::size_t idx = 0;
  while (idx < value.size()) {
    const char c = value[idx];
    if (std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '+' || c == '/') {
      ++idx;
      continue;
    }
    break;
  }
  if (idx == 0) {
    return false;
  }
  const std::size_t padding = value.size() - idx;
  if (padding > 2) {
    return false;
  }
  for (std::size_t i = idx; i < value.size(); ++i) {
    if (value[i] != '=') {
      return false;
    }
  }
  return true;
}

std::vector<unsigned char> DecodeStdBase64(const std::string &value) {
  std::vector<unsigned char> out(value.size() / 4 * 3 + 3);
  std::size_t written = 0;
  if (sodium_base642bin(out.data(), out.size(), value.data(), value.size(), nullptr, &written, nullptr,
                        sodium_base64_VARIANT_ORIGINAL) != 0) {
    throw std::runtime_error("invalid_base64");
  }
  out.resize(written);
  return out;
}

// ---------------------------------------------------------------------------
// Minimal JSON reader (RFC 8259 subset sufficient for the v1 payload).
// ---------------------------------------------------------------------------

struct JsonNode {
  enum class Kind { Null, Bool, Number, String, Array, Object };
  Kind kind = Kind::Null;
  bool boolValue = false;
  double numberValue = 0;
  std::string stringValue;
  std::vector<JsonNode> array;
  std::vector<std::pair<std::string, JsonNode>> object;
  /// Raw source slice for this node (used to hand variable maps back as text).
  std::string raw;

  const JsonNode *Get(const std::string &key) const {
    if (kind != Kind::Object) {
      return nullptr;
    }
    for (const auto &entry : object) {
      if (entry.first == key) {
        return &entry.second;
      }
    }
    return nullptr;
  }
};

class JsonReader {
public:
  explicit JsonReader(const std::string &text) : text_(text) {}

  JsonNode ParseDocument() {
    SkipWs();
    JsonNode node = ParseValue();
    SkipWs();
    if (pos_ != text_.size()) {
      throw std::runtime_error("trailing_characters");
    }
    return node;
  }

private:
  void SkipWs() {
    while (pos_ < text_.size() && std::isspace(static_cast<unsigned char>(text_[pos_])) != 0) {
      ++pos_;
    }
  }

  char Peek() const {
    if (pos_ >= text_.size()) {
      throw std::runtime_error("unexpected_end");
    }
    return text_[pos_];
  }

  void Expect(char c) {
    if (Peek() != c) {
      throw std::runtime_error("unexpected_character");
    }
    ++pos_;
  }

  JsonNode ParseValue() {
    const std::size_t start = pos_;
    JsonNode node;
    const char c = Peek();
    if (c == '{') {
      node = ParseObject();
    } else if (c == '[') {
      node = ParseArray();
    } else if (c == '"') {
      node.kind = JsonNode::Kind::String;
      node.stringValue = ParseString();
    } else if (text_.compare(pos_, 4, "true") == 0) {
      node.kind = JsonNode::Kind::Bool;
      node.boolValue = true;
      pos_ += 4;
    } else if (text_.compare(pos_, 5, "false") == 0) {
      node.kind = JsonNode::Kind::Bool;
      node.boolValue = false;
      pos_ += 5;
    } else if (text_.compare(pos_, 4, "null") == 0) {
      node.kind = JsonNode::Kind::Null;
      pos_ += 4;
    } else {
      node.kind = JsonNode::Kind::Number;
      node.numberValue = ParseNumber();
    }
    node.raw = text_.substr(start, pos_ - start);
    return node;
  }

  JsonNode ParseObject() {
    JsonNode node;
    node.kind = JsonNode::Kind::Object;
    Expect('{');
    SkipWs();
    if (Peek() == '}') {
      ++pos_;
      return node;
    }
    while (true) {
      SkipWs();
      if (Peek() != '"') {
        throw std::runtime_error("expected_key");
      }
      std::string key = ParseString();
      SkipWs();
      Expect(':');
      SkipWs();
      JsonNode value = ParseValue();
      node.object.emplace_back(std::move(key), std::move(value));
      SkipWs();
      const char c = Peek();
      if (c == ',') {
        ++pos_;
        continue;
      }
      if (c == '}') {
        ++pos_;
        return node;
      }
      throw std::runtime_error("expected_comma_or_brace");
    }
  }

  JsonNode ParseArray() {
    JsonNode node;
    node.kind = JsonNode::Kind::Array;
    Expect('[');
    SkipWs();
    if (Peek() == ']') {
      ++pos_;
      return node;
    }
    while (true) {
      SkipWs();
      node.array.push_back(ParseValue());
      SkipWs();
      const char c = Peek();
      if (c == ',') {
        ++pos_;
        continue;
      }
      if (c == ']') {
        ++pos_;
        return node;
      }
      throw std::runtime_error("expected_comma_or_bracket");
    }
  }

  static void AppendUtf8(std::string &out, unsigned int codepoint) {
    if (codepoint < 0x80) {
      out.push_back(static_cast<char>(codepoint));
    } else if (codepoint < 0x800) {
      out.push_back(static_cast<char>(0xC0 | (codepoint >> 6)));
      out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
    } else if (codepoint < 0x10000) {
      out.push_back(static_cast<char>(0xE0 | (codepoint >> 12)));
      out.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
    } else {
      out.push_back(static_cast<char>(0xF0 | (codepoint >> 18)));
      out.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
    }
  }

  unsigned int ParseHex4() {
    if (pos_ + 4 > text_.size()) {
      throw std::runtime_error("bad_unicode_escape");
    }
    unsigned int value = 0;
    for (int i = 0; i < 4; ++i) {
      const char c = text_[pos_++];
      value <<= 4;
      if (c >= '0' && c <= '9') {
        value |= static_cast<unsigned int>(c - '0');
      } else if (c >= 'a' && c <= 'f') {
        value |= static_cast<unsigned int>(c - 'a' + 10);
      } else if (c >= 'A' && c <= 'F') {
        value |= static_cast<unsigned int>(c - 'A' + 10);
      } else {
        throw std::runtime_error("bad_unicode_escape");
      }
    }
    return value;
  }

  std::string ParseString() {
    Expect('"');
    std::string out;
    while (true) {
      const char c = Peek();
      ++pos_;
      if (c == '"') {
        return out;
      }
      if (c != '\\') {
        out.push_back(c);
        continue;
      }
      const char esc = Peek();
      ++pos_;
      switch (esc) {
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case 'u': {
          unsigned int codepoint = ParseHex4();
          if (codepoint >= 0xD800 && codepoint <= 0xDBFF) {
            if (pos_ + 6 <= text_.size() && text_[pos_] == '\\' && text_[pos_ + 1] == 'u') {
              pos_ += 2;
              const unsigned int low = ParseHex4();
              codepoint = 0x10000 + ((codepoint - 0xD800) << 10) + (low - 0xDC00);
            }
          }
          AppendUtf8(out, codepoint);
          break;
        }
        default:
          throw std::runtime_error("bad_escape");
      }
    }
  }

  double ParseNumber() {
    const std::size_t start = pos_;
    if (Peek() == '-') {
      ++pos_;
    }
    while (pos_ < text_.size() && (std::isdigit(static_cast<unsigned char>(text_[pos_])) != 0 || text_[pos_] == '.' ||
                                   text_[pos_] == 'e' || text_[pos_] == 'E' || text_[pos_] == '+' ||
                                   text_[pos_] == '-')) {
      ++pos_;
    }
    if (pos_ == start) {
      throw std::runtime_error("expected_number");
    }
    return std::strtod(text_.substr(start, pos_ - start).c_str(), nullptr);
  }

  const std::string &text_;
  std::size_t pos_ = 0;
};

VerifyLicenseFileResult Failure(const char *code) {
  VerifyLicenseFileResult result;
  result.ok = false;
  result.error = code;
  return result;
}

bool NonEmptyString(const JsonNode *node, std::string &out) {
  if (node == nullptr || node->kind != JsonNode::Kind::String || node->stringValue.empty()) {
    return false;
  }
  out = node->stringValue;
  return true;
}

long long DaysFromCivil(long long y, long long m, long long d) {
  y -= m <= 2 ? 1 : 0;
  const long long era = (y >= 0 ? y : y - 399) / 400;
  const long long yoe = y - era * 400;
  const long long mp = (m + 9) % 12;
  const long long doy = (153 * mp + 2) / 5 + d - 1;
  const long long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + doe - 719468;
}

bool ParseFixedInt(const std::string &s, std::size_t from, std::size_t len, long long &out) {
  if (from + len > s.size()) {
    return false;
  }
  long long value = 0;
  for (std::size_t i = from; i < from + len; ++i) {
    if (std::isdigit(static_cast<unsigned char>(s[i])) == 0) {
      return false;
    }
    value = value * 10 + (s[i] - '0');
  }
  out = value;
  return true;
}

long long NowEpochMs() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

} // namespace

std::optional<long long> ParseIso8601Ms(const std::string &value) {
  const std::string s = TrimCopy(value);
  if (s.size() < 19 || s[4] != '-' || s[7] != '-' || (s[10] != 'T' && s[10] != ' ') || s[13] != ':' || s[16] != ':') {
    return std::nullopt;
  }
  long long year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
  if (!ParseFixedInt(s, 0, 4, year) || !ParseFixedInt(s, 5, 2, month) || !ParseFixedInt(s, 8, 2, day) ||
      !ParseFixedInt(s, 11, 2, hour) || !ParseFixedInt(s, 14, 2, minute) || !ParseFixedInt(s, 17, 2, second)) {
    return std::nullopt;
  }
  if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 60) {
    return std::nullopt;
  }

  std::size_t pos = 19;
  long long millis = 0;
  if (pos < s.size() && s[pos] == '.') {
    ++pos;
    const std::size_t digitsStart = pos;
    while (pos < s.size() && std::isdigit(static_cast<unsigned char>(s[pos])) != 0) {
      ++pos;
    }
    if (pos == digitsStart) {
      return std::nullopt;
    }
    std::string digits = s.substr(digitsStart, pos - digitsStart);
    while (digits.size() < 3) {
      digits.push_back('0');
    }
    digits.resize(3);
    millis = std::strtoll(digits.c_str(), nullptr, 10);
  }

  long long offsetSeconds = 0;
  const std::string rest = s.substr(pos);
  if (!(rest.empty() || rest == "Z" || rest == "z")) {
    const char sign = rest[0];
    if (sign != '+' && sign != '-') {
      return std::nullopt;
    }
    const std::string body = rest.substr(1);
    long long oh = 0, om = 0;
    if (body.size() == 5 && body[2] == ':') {
      if (!ParseFixedInt(body, 0, 2, oh) || !ParseFixedInt(body, 3, 2, om)) return std::nullopt;
    } else if (body.size() == 4) {
      if (!ParseFixedInt(body, 0, 2, oh) || !ParseFixedInt(body, 2, 2, om)) return std::nullopt;
    } else if (body.size() == 2) {
      if (!ParseFixedInt(body, 0, 2, oh)) return std::nullopt;
    } else {
      return std::nullopt;
    }
    offsetSeconds = (sign == '-' ? -1 : 1) * (oh * 3600 + om * 60);
  }

  const long long days = DaysFromCivil(year, month, day);
  const long long seconds = days * 86400 + hour * 3600 + minute * 60 + second - offsetSeconds;
  return seconds * 1000 + millis;
}

std::optional<ParsedLicenseFile> ParseLicenseFile(const std::string &text) {
  std::string normalized = text;
  if (normalized.size() >= 3 && static_cast<unsigned char>(normalized[0]) == 0xEF &&
      static_cast<unsigned char>(normalized[1]) == 0xBB && static_cast<unsigned char>(normalized[2]) == 0xBF) {
    normalized.erase(0, 3);
  }
  // Normalise CRLF / CR to LF.
  std::string lf;
  lf.reserve(normalized.size());
  for (std::size_t i = 0; i < normalized.size(); ++i) {
    if (normalized[i] == '\r') {
      lf.push_back('\n');
      if (i + 1 < normalized.size() && normalized[i + 1] == '\n') {
        ++i;
      }
    } else {
      lf.push_back(normalized[i]);
    }
  }

  std::vector<std::string> lines;
  {
    std::string current;
    for (const char c : lf) {
      if (c == '\n') {
        lines.push_back(current);
        current.clear();
      } else {
        current.push_back(c);
      }
    }
    lines.push_back(current);
  }

  auto find = [&lines](const char *marker, std::size_t start) -> std::optional<std::size_t> {
    for (std::size_t i = start; i < lines.size(); ++i) {
      if (TrimCopy(lines[i]) == marker) {
        return i;
      }
    }
    return std::nullopt;
  };

  const auto beginIdx = find(kBeginLicense, 0);
  if (!beginIdx) return std::nullopt;
  const auto endIdx = find(kEndLicense, *beginIdx + 1);
  if (!endIdx) return std::nullopt;
  const auto sigBeginIdx = find(kBeginSignature, *endIdx + 1);
  if (!sigBeginIdx) return std::nullopt;
  const auto sigEndIdx = find(kEndSignature, *sigBeginIdx + 1);
  if (!sigEndIdx) return std::nullopt;

  std::optional<std::size_t> blankIdx;
  for (std::size_t i = *beginIdx + 1; i < *endIdx; ++i) {
    if (TrimCopy(lines[i]).empty()) {
      blankIdx = i;
      break;
    }
  }
  if (!blankIdx) return std::nullopt;

  ParsedLicenseFile parsed;
  for (std::size_t i = *beginIdx + 1; i < *blankIdx; ++i) {
    const std::string line = TrimCopy(lines[i]);
    const std::size_t colon = line.find(':');
    if (colon == std::string::npos || colon == 0) return std::nullopt;
    parsed.headers.emplace_back(TrimCopy(line.substr(0, colon)), TrimCopy(line.substr(colon + 1)));
  }

  std::string payload;
  for (std::size_t i = *blankIdx + 1; i < *endIdx; ++i) {
    payload += lines[i];
  }
  std::string signature;
  for (std::size_t i = *sigBeginIdx + 1; i < *sigEndIdx; ++i) {
    signature += lines[i];
  }
  parsed.payloadBase64 = StripWhitespace(payload);
  parsed.signatureBase64 = StripWhitespace(signature);
  if (!IsBase64Text(parsed.payloadBase64) || !IsBase64Text(parsed.signatureBase64)) {
    return std::nullopt;
  }
  return parsed;
}

VerifyLicenseFileResult VerifyLicenseFile(
    const std::string &file,
    const std::string &appId,
    const std::vector<std::string> &publicKeys,
    const std::string &hwid,
    long long nowEpochMs) {
  const auto parsed = ParseLicenseFile(file);
  if (!parsed) {
    return Failure("bad_armor");
  }

  // The free function may be called without ever constructing an
  // AuthForgeClient (whose constructor initialises libsodium), so make sure
  // the library is ready here too. sodium_init() is idempotent and returns 1
  // when already initialised; only a negative result is a failure.
  if (sodium_init() < 0) {
    return Failure("bad_signature");
  }

  // Signature first - nothing below runs on an unsigned document.
  std::vector<unsigned char> signatureBytes;
  try {
    signatureBytes = DecodeStdBase64(parsed->signatureBase64);
  } catch (...) {
    return Failure("bad_signature");
  }
  if (signatureBytes.size() != crypto_sign_BYTES) {
    return Failure("bad_signature");
  }
  bool verified = false;
  for (const auto &entry : publicKeys) {
    std::stringstream splitter(entry);
    std::string keyText;
    while (std::getline(splitter, keyText, ',')) {
      keyText = TrimCopy(keyText);
      if (keyText.empty()) continue;
      std::vector<unsigned char> keyBytes;
      try {
        keyBytes = DecodeStdBase64(keyText);
      } catch (...) {
        continue;
      }
      if (keyBytes.size() != crypto_sign_PUBLICKEYBYTES) continue;
      if (crypto_sign_verify_detached(
              signatureBytes.data(),
              reinterpret_cast<const unsigned char *>(parsed->payloadBase64.data()),
              static_cast<unsigned long long>(parsed->payloadBase64.size()),
              keyBytes.data()) == 0) {
        verified = true;
        break;
      }
    }
    if (verified) break;
  }
  if (!verified) {
    return Failure("bad_signature");
  }

  std::string payloadJson;
  JsonNode root;
  try {
    const std::vector<unsigned char> bytes = DecodeStdBase64(parsed->payloadBase64);
    payloadJson.assign(bytes.begin(), bytes.end());
    root = JsonReader(payloadJson).ParseDocument();
  } catch (...) {
    return Failure("malformed_payload");
  }
  if (root.kind != JsonNode::Kind::Object) {
    return Failure("malformed_payload");
  }

  const JsonNode *version = root.Get("v");
  if (version == nullptr || version->kind != JsonNode::Kind::Number ||
      version->numberValue != static_cast<double>(kOfflineLicenseFileVersion)) {
    return Failure("unsupported_version");
  }

  OfflineLicense license;
  std::string typ;
  if (!NonEmptyString(root.Get("typ"), typ) || typ != "authforge-license") {
    return Failure("malformed_payload");
  }
  if (!NonEmptyString(root.Get("appId"), license.appId) || !NonEmptyString(root.Get("licenseKey"), license.licenseKey) ||
      !NonEmptyString(root.Get("jti"), license.jti) || !NonEmptyString(root.Get("kid"), license.keyId) ||
      !NonEmptyString(root.Get("issuedAt"), license.issuedAt)) {
    return Failure("malformed_payload");
  }
  const JsonNode *expires = root.Get("expiresAt");
  if (expires == nullptr) {
    return Failure("malformed_payload");
  }
  if (expires->kind == JsonNode::Kind::Null) {
    license.expiresAt = std::nullopt;
  } else if (expires->kind == JsonNode::Kind::String && !expires->stringValue.empty()) {
    license.expiresAt = expires->stringValue;
  } else {
    return Failure("malformed_payload");
  }

  const JsonNode *hwidNode = root.Get("hwid");
  if (hwidNode == nullptr || hwidNode->kind != JsonNode::Kind::Object) {
    return Failure("malformed_payload");
  }
  if (!NonEmptyString(hwidNode->Get("mode"), license.hwidPolicy.mode)) {
    return Failure("malformed_payload");
  }
  if (license.hwidPolicy.mode == "bound") {
    const JsonNode *hwids = hwidNode->Get("hwids");
    if (hwids == nullptr || hwids->kind != JsonNode::Kind::Array || hwids->array.empty()) {
      return Failure("malformed_payload");
    }
    for (const auto &item : hwids->array) {
      if (item.kind != JsonNode::Kind::String || item.stringValue.empty()) {
        return Failure("malformed_payload");
      }
      license.hwidPolicy.hwids.push_back(item.stringValue);
    }
  } else if (license.hwidPolicy.mode != "any") {
    return Failure("malformed_payload");
  }

  if (license.appId != TrimCopy(appId)) {
    return Failure("wrong_app");
  }

  const long long now = nowEpochMs != 0 ? nowEpochMs : NowEpochMs();
  if (license.expiresAt) {
    const auto expMs = ParseIso8601Ms(*license.expiresAt);
    if (!expMs || *expMs <= now) {
      return Failure("expired");
    }
  }

  if (license.hwidPolicy.mode == "bound") {
    const std::string local = TrimCopy(hwid);
    if (local.empty() ||
        std::find(license.hwidPolicy.hwids.begin(), license.hwidPolicy.hwids.end(), local) == license.hwidPolicy.hwids.end()) {
      return Failure("hwid_mismatch");
    }
  }

  if (const JsonNode *label = root.Get("label"); label != nullptr && label->kind == JsonNode::Kind::String) {
    license.label = label->stringValue;
  }
  if (const JsonNode *licenseExp = root.Get("licenseExpiresAt"); licenseExp != nullptr) {
    license.licenseExpirationKnown = true;
    if (licenseExp->kind == JsonNode::Kind::String) {
      license.licenseExpiresAt = licenseExp->stringValue;
    }
  }
  if (const JsonNode *vars = root.Get("licenseVariables"); vars != nullptr && vars->kind == JsonNode::Kind::Object) {
    license.licenseVariablesJson = vars->raw;
  }
  if (const JsonNode *vars = root.Get("appVariables"); vars != nullptr && vars->kind == JsonNode::Kind::Object) {
    license.appVariablesJson = vars->raw;
  }
  license.payloadJson = payloadJson;
  license.payloadBase64 = parsed->payloadBase64;
  license.signatureBase64 = parsed->signatureBase64;

  VerifyLicenseFileResult result;
  result.ok = true;
  result.license = std::move(license);
  return result;
}

// ---------------------------------------------------------------------------
// Client integration
// ---------------------------------------------------------------------------

std::string AuthForgeClient::ReadLicenseFileInput(const std::string &pathOrText) {
  if (pathOrText.empty()) {
    throw std::invalid_argument("license file must be a path or the armored text");
  }
  if (pathOrText.find(kBeginLicense) != std::string::npos) {
    return pathOrText;
  }
  std::ifstream in(pathOrText, std::ios::in | std::ios::binary);
  if (!in) {
    throw std::runtime_error("read_error: cannot open " + pathOrText);
  }
  std::ostringstream buffer;
  buffer << in.rdbuf();
  return buffer.str();
}

VerifyLicenseFileResult AuthForgeClient::VerifyLicenseFile(const std::string &pathOrText, long long nowEpochMs) const {
  std::string text;
  try {
    text = ReadLicenseFileInput(pathOrText);
  } catch (const std::exception &exc) {
    VerifyLicenseFileResult result;
    result.ok = false;
    result.error = std::string("read_error: ") + exc.what();
    return result;
  }
  return authforge::VerifyLicenseFile(text, appId_, publicKeys_, hwid_, nowEpochMs);
}

bool AuthForgeClient::LoginFromFile(const std::string &pathOrText) {
  std::string text;
  try {
    text = ReadLicenseFileInput(pathOrText);
  } catch (const std::exception &exc) {
    if (onFailure_) {
      try {
        onFailure_("offline_login_failed", &exc);
      } catch (...) {
      }
    }
    return false;
  }
  const VerifyLicenseFileResult result = authforge::VerifyLicenseFile(text, appId_, publicKeys_, hwid_, 0);
  if (!result.ok) {
    if (onFailure_) {
      const std::runtime_error exc(result.error);
      try {
        onFailure_("offline_login_failed", &exc);
      } catch (...) {
      }
    }
    return false;
  }
  ApplyOfflineLicense(result.license);
  return true;
}

std::optional<OfflineLicense> AuthForgeClient::GetOfflineLicense() const {
  std::lock_guard<std::mutex> guard(lock_);
  return offlineLicense_;
}

void AuthForgeClient::ApplyOfflineLicense(const OfflineLicense &license) {
  // Stop any online session first so the two modes never overlap.
  Logout();
  std::lock_guard<std::mutex> guard(lock_);
  licenseKey_ = license.licenseKey;
  // Offline files carry no server session token.
  sessionToken_.clear();
  sessionKind_ = SessionKind::Offline;
  if (license.expiresAt) {
    if (const auto ms = ParseIso8601Ms(*license.expiresAt)) {
      sessionExpiresIn_ = *ms / 1000;
    }
  } else {
    sessionExpiresIn_ = std::nullopt;
  }
  rawPayloadB64_ = license.payloadBase64;
  signature_ = license.signatureBase64;
  keyId_ = license.keyId;
  sessionDataJson_ = license.payloadJson;
  appVariablesJson_ = license.appVariablesJson;
  licenseVariablesJson_ = license.licenseVariablesJson;
  offlineLicense_ = license;
  authenticated_ = true;
}

namespace {

constexpr int kArmorLineWidth = 64;
constexpr int kMaxRequestHwid = 256;
constexpr int kMaxRequestMachineName = 128;
constexpr int kMaxRequestOs = 64;
constexpr int kMaxRequestSdk = 64;
constexpr int kMaxRequestLicenseKey = 64;
constexpr const char *kActivationRequestTyp = "authforge-activation-request";
constexpr const char *kBeginActivationRequest = "-----BEGIN AUTHFORGE ACTIVATION REQUEST-----";
constexpr const char *kEndActivationRequest = "-----END AUTHFORGE ACTIVATION REQUEST-----";
constexpr const char *kActivationRequestSdkTag = "cpp/1.3.1";

std::string ClipRequestField(const std::string &value, int max) {
  if (static_cast<int>(value.size()) <= max) {
    return value;
  }
  return value.substr(0, static_cast<std::size_t>(max));
}

std::string JsonEscapeRequest(const std::string &value) {
  std::ostringstream oss;
  oss << '"';
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
  oss << '"';
  return oss.str();
}

std::string WrapArmor64(const std::string &value) {
  std::string out;
  for (std::size_t i = 0; i < value.size(); i += static_cast<std::size_t>(kArmorLineWidth)) {
    if (!out.empty()) {
      out.push_back('\n');
    }
    out.append(value, i, static_cast<std::size_t>(kArmorLineWidth));
  }
  return out;
}

std::string EncodeBase64(const std::string &input) {
  static const char kTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  const auto *data = reinterpret_cast<const unsigned char *>(input.data());
  const std::size_t len = input.size();
  out.reserve(((len + 2) / 3) * 4);
  std::size_t i = 0;
  while (i + 2 < len) {
    const unsigned int n = (static_cast<unsigned int>(data[i]) << 16) | (static_cast<unsigned int>(data[i + 1]) << 8) |
                            static_cast<unsigned int>(data[i + 2]);
    out.push_back(kTable[(n >> 18) & 63]);
    out.push_back(kTable[(n >> 12) & 63]);
    out.push_back(kTable[(n >> 6) & 63]);
    out.push_back(kTable[n & 63]);
    i += 3;
  }
  if (i < len) {
    unsigned int n = static_cast<unsigned int>(data[i]) << 16;
    if (i + 1 < len) {
      n |= static_cast<unsigned int>(data[i + 1]) << 8;
    }
    out.push_back(kTable[(n >> 18) & 63]);
    out.push_back(kTable[(n >> 12) & 63]);
    out.push_back(i + 1 < len ? kTable[(n >> 6) & 63] : '=');
    out.push_back('=');
  }
  return out;
}

std::string Sha256Hex16(const std::string &payloadB64) {
  if (sodium_init() < 0) {
    throw std::runtime_error("sodium_init failed");
  }
  unsigned char digest[crypto_hash_sha256_BYTES];
  crypto_hash_sha256(digest, reinterpret_cast<const unsigned char *>(payloadB64.data()), payloadB64.size());
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out(16, '0');
  for (int i = 0; i < 8; ++i) {
    out[static_cast<std::size_t>(i * 2)] = kHex[(digest[i] >> 4) & 0x0F];
    out[static_cast<std::size_t>(i * 2 + 1)] = kHex[digest[i] & 0x0F];
  }
  return out;
}

std::string CanonicalActivationRequestJson(const std::string &appId, const std::string &hwid, const std::string &createdAt,
                                           const std::string &machineName, const std::string &os, const std::string &sdk,
                                           const std::string &licenseKey) {
  std::string json = "{";
  json += "\"v\":1";
  json += ",\"typ\":" + JsonEscapeRequest(kActivationRequestTyp);
  json += ",\"appId\":" + JsonEscapeRequest(appId);
  json += ",\"hwid\":" + JsonEscapeRequest(ClipRequestField(hwid, kMaxRequestHwid));
  json += ",\"createdAt\":" + JsonEscapeRequest(createdAt);
  if (!machineName.empty()) {
    json += ",\"machineName\":" + JsonEscapeRequest(ClipRequestField(machineName, kMaxRequestMachineName));
  }
  if (!os.empty()) {
    json += ",\"os\":" + JsonEscapeRequest(ClipRequestField(os, kMaxRequestOs));
  }
  if (!sdk.empty()) {
    json += ",\"sdk\":" + JsonEscapeRequest(ClipRequestField(sdk, kMaxRequestSdk));
  }
  if (!licenseKey.empty()) {
    json += ",\"licenseKey\":" + JsonEscapeRequest(ClipRequestField(licenseKey, kMaxRequestLicenseKey));
  }
  json += "}";
  return json;
}

std::string DetectOsLabel() {
#if defined(_WIN32)
  return "Windows";
#elif defined(__APPLE__)
  return "macOS";
#else
  return "Linux";
#endif
}

std::string UtcIsoMsNow() {
  const auto now = std::chrono::system_clock::now();
  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
  const std::time_t t = std::chrono::system_clock::to_time_t(now);
  std::tm tm{};
#ifdef _WIN32
  gmtime_s(&tm, &t);
#else
  gmtime_r(&t, &tm);
#endif
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec, static_cast<int>(ms.count()));
  return buf;
}

std::string DetectHostname() {
#ifdef _WIN32
  char buf[256];
  DWORD n = static_cast<DWORD>(sizeof(buf));
  if (GetComputerNameA(buf, &n) != 0) {
    return buf;
  }
#else
  char buf[256];
  if (gethostname(buf, sizeof(buf)) == 0) {
    return buf;
  }
#endif
  return "";
}

} // namespace

std::string FormatActivationRequest(const std::string &appId, const std::string &hwid, const std::string &createdAt,
                                    const std::string &machineName, const std::string &os, const std::string &sdk,
                                    const std::string &licenseKey) {
  const std::string json = CanonicalActivationRequestJson(appId, hwid, createdAt, machineName, os, sdk, licenseKey);
  const std::string payloadB64 = EncodeBase64(json);
  const std::string checksum = Sha256Hex16(payloadB64);
  std::string clean = appId;
  for (char &ch : clean) {
    if (ch == '\r' || ch == '\n') {
      ch = ' ';
    }
  }
  std::ostringstream oss;
  oss << kBeginActivationRequest << "\n";
  oss << "Version: 1\n";
  oss << "App-Id: " << TrimCopy(clean) << "\n";
  oss << "Checksum: " << checksum << "\n";
  oss << "\n";
  oss << WrapArmor64(payloadB64) << "\n";
  oss << kEndActivationRequest << "\n";
  return oss.str();
}

std::string AuthForgeClient::CreateActivationRequest(const ActivationRequestOptions &options) const {
  const std::string createdAt = options.createdAt.empty() ? UtcIsoMsNow() : options.createdAt;
  std::string machineName;
  if (options.includeMachineName) {
    machineName = options.machineName.empty() ? DetectHostname() : options.machineName;
  }
  std::string os;
  if (!options.omitOs) {
    os = options.os.empty() ? DetectOsLabel() : options.os;
  }
  std::string sdk;
  if (!options.omitSdk) {
    sdk = options.sdk.empty() ? kActivationRequestSdkTag : options.sdk;
  }
  const std::string licenseKey = options.licenseKey.empty() ? licenseKey_ : options.licenseKey;
  return FormatActivationRequest(appId_, hwid_, createdAt, machineName, os, sdk, licenseKey);
}

} // namespace authforge
