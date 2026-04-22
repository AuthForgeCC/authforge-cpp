#include "authforge_sdk.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <utility>

#include <curl/curl.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <sodium.h>

#ifdef _WIN32
#include <iphlpapi.h>
#include <intrin.h>
#include <winsock2.h>
#include <windows.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#endif

#if defined(__linux__) || defined(__APPLE__)
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/types.h>
#endif

#if defined(__linux__)
#include <filesystem>
#include <fstream>
#endif

#if defined(__APPLE__)
#include <net/if_dl.h>
#include <sys/sysctl.h>
#endif

namespace authforge {

namespace {

std::string JoinAndCompactWhitespace(const std::string &input) {
  std::string out;
  out.reserve(input.size());
  bool inSpace = false;
  for (unsigned char ch : input) {
    if (std::isspace(ch) != 0) {
      inSpace = true;
      continue;
    }
    if (inSpace && !out.empty()) {
      out.push_back(' ');
    }
    inSpace = false;
    out.push_back(static_cast<char>(ch));
  }
  return out;
}

std::optional<std::string> ExtractTopLevelObject(const std::string &json, const std::string &key) {
  const std::string needle = "\"" + key + "\"";
  const std::size_t keyPos = json.find(needle);
  if (keyPos == std::string::npos) {
    return std::nullopt;
  }
  std::size_t pos = json.find(':', keyPos + needle.size());
  if (pos == std::string::npos) {
    return std::nullopt;
  }
  ++pos;
  while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos])) != 0) {
    ++pos;
  }
  if (pos >= json.size() || json[pos] != '{') {
    return std::nullopt;
  }

  std::size_t end = pos;
  int depth = 0;
  bool inString = false;
  bool escaping = false;
  for (; end < json.size(); ++end) {
    const char c = json[end];
    if (inString) {
      if (escaping) {
        escaping = false;
      } else if (c == '\\') {
        escaping = true;
      } else if (c == '"') {
        inString = false;
      }
      continue;
    }
    if (c == '"') {
      inString = true;
      continue;
    }
    if (c == '{') {
      ++depth;
      continue;
    }
    if (c == '}') {
      --depth;
      if (depth == 0) {
        return json.substr(pos, (end - pos) + 1);
      }
    }
  }

  return std::nullopt;
}

size_t CurlWriteCallback(char *ptr, size_t size, size_t nmemb, void *userdata) {
  if (userdata == nullptr) {
    return 0;
  }
  const size_t bytes = size * nmemb;
  auto *out = static_cast<std::string *>(userdata);
  out->append(ptr, bytes);
  return bytes;
}

void EnsureCurlInit() {
  static std::once_flag initFlag;
  std::call_once(initFlag, []() {
    const CURLcode rc = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (rc != CURLE_OK) {
      throw std::runtime_error("url_error: curl_global_init_failed");
    }
  });
}

} // namespace

std::string RefreshNonceInBody(const std::string &bodyJson, const std::string &newNonce) {
  const std::string marker = "\"nonce\":\"";
  const std::size_t start = bodyJson.find(marker);
  if (start == std::string::npos) {
    return bodyJson;
  }
  const std::size_t valueStart = start + marker.size();
  const std::size_t valueEnd = bodyJson.find('"', valueStart);
  if (valueEnd == std::string::npos) {
    return bodyJson;
  }

  std::string refreshed = bodyJson;
  refreshed.replace(valueStart, valueEnd - valueStart, newNonce);
  return refreshed;
}

std::optional<std::string> ExtractNonceFromBody(const std::string &bodyJson) {
  const std::string marker = "\"nonce\":\"";
  const std::size_t start = bodyJson.find(marker);
  if (start == std::string::npos) {
    return std::nullopt;
  }
  const std::size_t valueStart = start + marker.size();
  const std::size_t valueEnd = bodyJson.find('"', valueStart);
  if (valueEnd == std::string::npos) {
    return std::nullopt;
  }
  return bodyJson.substr(valueStart, valueEnd - valueStart);
}

AuthForgeClient::AuthForgeClient(
    std::string appId,
    std::string appSecret,
    std::string publicKey,
    std::string heartbeatMode,
    int heartbeatInterval,
    std::string apiBaseUrl,
    std::function<void(const std::string &, const std::exception *)> onFailure,
    int requestTimeout,
    int ttlSeconds)
    : appId_(std::move(appId)),
      appSecret_(std::move(appSecret)),
      publicKey_(std::move(publicKey)),
      heartbeatMode_(ToLower(std::move(heartbeatMode))),
      heartbeatInterval_(heartbeatInterval),
      apiBaseUrl_(std::move(apiBaseUrl)),
      onFailure_(std::move(onFailure)),
      requestTimeout_(requestTimeout),
      ttlSeconds_(ttlSeconds > 0 ? ttlSeconds : 0),
      heartbeatStarted_(false) {
  if (appId_.empty()) {
    throw std::invalid_argument("app_id must be a non-empty string");
  }
  if (appSecret_.empty()) {
    throw std::invalid_argument("app_secret must be a non-empty string");
  }
  if (publicKey_.empty()) {
    throw std::invalid_argument("public_key must be a non-empty string");
  }

  std::transform(heartbeatMode_.begin(), heartbeatMode_.end(), heartbeatMode_.begin(),
                 [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
  if (heartbeatMode_ != "LOCAL" && heartbeatMode_ != "SERVER") {
    throw std::invalid_argument("heartbeat_mode must be LOCAL or SERVER");
  }
  if (heartbeatInterval_ <= 0) {
    throw std::invalid_argument("heartbeat_interval must be > 0");
  }
  while (!apiBaseUrl_.empty() && apiBaseUrl_.back() == '/') {
    apiBaseUrl_.pop_back();
  }
  if (sodium_init() < 0) {
    throw std::runtime_error("sodium_init_failed");
  }
  verifyPublicKeyBytes_ = DecodeBase64Any(publicKey_);
  if (verifyPublicKeyBytes_.size() != crypto_sign_PUBLICKEYBYTES) {
    throw std::invalid_argument("public_key must be 32 bytes (base64 Ed25519 raw key)");
  }

  hwid_ = GetHwid();
}

bool AuthForgeClient::Login(const std::string &licenseKey) {
  if (licenseKey.empty()) {
    throw std::invalid_argument("license_key must be a non-empty string");
  }

  try {
    ValidateAndStore(licenseKey);
    StartHeartbeatOnce();
    return true;
  } catch (const std::exception &exc) {
    Fail("login_failed", &exc);
    return false;
  } catch (...) {
    Fail("login_failed", nullptr);
    return false;
  }
}

void AuthForgeClient::StartHeartbeatOnce() {
  std::lock_guard<std::mutex> guard(lock_);
  if (heartbeatStarted_) {
    return;
  }
  heartbeatStop_ = false;
  heartbeatStarted_ = true;
  std::thread([this]() { HeartbeatLoop(); }).detach();
}

void AuthForgeClient::HeartbeatLoop() noexcept {
  while (true) {
    std::this_thread::sleep_for(std::chrono::seconds(heartbeatInterval_));
    {
      std::lock_guard<std::mutex> guard(lock_);
      if (heartbeatStop_) {
        break;
      }
    }
    try {
      if (heartbeatMode_ == "SERVER") {
        ServerHeartbeat();
      } else {
        LocalHeartbeat();
      }
    } catch (const std::exception &exc) {
      Fail("heartbeat_failed", &exc);
      break;
    } catch (...) {
      Fail("heartbeat_failed", nullptr);
      break;
    }
  }
}

void AuthForgeClient::ServerHeartbeat() {
  std::string sessionToken;
  std::string hwid;
  {
    std::lock_guard<std::mutex> guard(lock_);
    sessionToken = sessionToken_;
    hwid = hwid_;
  }
  if (sessionToken.empty()) {
    throw std::runtime_error("missing_session_token");
  }

  const std::string nonce = GenerateNonceHex32();
  const std::string body = BuildJsonBody({
      {"appId", appId_},
      {"sessionToken", sessionToken},
      {"nonce", nonce},
      {"hwid", hwid},
  });
  std::string usedNonce = nonce;
  const std::string response = PostJson("/auth/heartbeat", body, &usedNonce);
  ApplySignedResponse(response, usedNonce, std::nullopt, SigningContext::Heartbeat);
}

void AuthForgeClient::LocalHeartbeat() {
  std::string rawPayloadB64;
  std::string signature;
  std::optional<long long> expiresIn;
  {
    std::lock_guard<std::mutex> guard(lock_);
    rawPayloadB64 = rawPayloadB64_;
    signature = signature_;
    expiresIn = sessionExpiresIn_;
  }

  if (rawPayloadB64.empty() || signature.empty()) {
    throw std::runtime_error("missing_local_verification_state");
  }
  VerifySignature(rawPayloadB64, signature);

  if (!expiresIn.has_value()) {
    throw std::runtime_error("missing_session_expiry");
  }

  const long long now = static_cast<long long>(std::time(nullptr));
  if (now < *expiresIn) {
    return;
  }
  throw std::runtime_error("session_expired");
}

void AuthForgeClient::ValidateAndStore(const std::string &licenseKey) {
  const std::string nonce = GenerateNonceHex32();
  std::string body = BuildJsonBody({
      {"appId", appId_},
      {"appSecret", appSecret_},
      {"licenseKey", licenseKey},
      {"hwid", hwid_},
      {"nonce", nonce},
  });
  // BuildJsonBody always emits string values; splice ttlSeconds in as a raw
  // integer when the caller requested a custom session lifetime.
  if (ttlSeconds_ > 0 && body.size() >= 2 && body.back() == '}') {
    body.pop_back();
    body += ",\"ttlSeconds\":" + std::to_string(ttlSeconds_) + "}";
  }
  std::string usedNonce = nonce;
  const std::string response = PostJson("/auth/validate", body, &usedNonce);
  ApplySignedResponse(response, usedNonce, licenseKey, SigningContext::Validate);
}

void AuthForgeClient::ApplySignedResponse(
    const std::string &responseJson,
    const std::string &expectedNonce,
    const std::optional<std::string> &licenseKey,
    SigningContext context) {
  JsonValue status;
  ExtractJsonValue(responseJson, "status", status);
  if (!IsSuccessStatus(status)) {
    throw std::runtime_error(ExtractServerError(responseJson));
  }

  const std::optional<std::string> rawPayloadOpt = ExtractJsonString(responseJson, "payload");
  if (!rawPayloadOpt.has_value()) {
    throw std::runtime_error("missing_payload");
  }
  if (rawPayloadOpt->empty()) {
    throw std::runtime_error("empty_payload");
  }

  const std::optional<std::string> signatureOpt = ExtractJsonString(responseJson, "signature");
  if (!signatureOpt.has_value()) {
    throw std::runtime_error("missing_signature");
  }
  if (signatureOpt->empty()) {
    throw std::runtime_error("empty_signature");
  }

  const std::string rawPayloadB64 = *rawPayloadOpt;
  const std::string signature = *signatureOpt;

  std::vector<unsigned char> payloadBytes;
  try {
    payloadBytes = DecodeBase64Any(rawPayloadB64);
  } catch (...) {
    throw std::runtime_error("invalid_payload_json");
  }

  std::string payloadJson(payloadBytes.begin(), payloadBytes.end());
  const std::string payloadTrimmed = Trim(payloadJson);
  if (payloadTrimmed.empty() || payloadTrimmed.front() != '{' || payloadTrimmed.back() != '}') {
    throw std::runtime_error("payload_not_json_object");
  }
  payloadJson = payloadTrimmed;
  JsonValue nonceValue;
  if (!ExtractJsonValue(payloadJson, "nonce", nonceValue)) {
    nonceValue.value.clear();
    nonceValue.isString = true;
    nonceValue.exists = true;
  }
  std::string receivedNonce = Trim(nonceValue.value);
  if (receivedNonce != expectedNonce) {
    throw std::runtime_error("nonce_mismatch");
  }

  (void)context;
  VerifySignature(rawPayloadB64, signature);

  const std::optional<std::string> sessionTokenOpt = ExtractJsonString(payloadJson, "sessionToken");
  const std::string sessionToken = sessionTokenOpt.has_value() ? Trim(*sessionTokenOpt) : "";
  if (sessionToken.empty()) {
    throw std::runtime_error("missing_sessionToken");
  }

  std::optional<long long> expiresIn = ExtractExpiresInFromSessionToken(sessionToken);
  if (!expiresIn.has_value()) {
    expiresIn = ExtractJsonInt(payloadJson, "expiresIn");
  }
  if (!expiresIn.has_value()) {
    throw std::runtime_error("missing_expiresIn");
  }

  {
    std::lock_guard<std::mutex> guard(lock_);
    if (licenseKey.has_value()) {
      licenseKey_ = *licenseKey;
    }
    sessionToken_ = sessionToken;
    sessionExpiresIn_ = *expiresIn;
    lastNonce_ = expectedNonce;
    rawPayloadB64_ = rawPayloadB64;
    signature_ = signature;
    keyId_.clear();
    if (const std::optional<std::string> keyId = ExtractJsonString(responseJson, "keyId"); keyId.has_value()) {
      keyId_ = *keyId;
    }
    sessionDataJson_ = payloadJson;
    appVariablesJson_.clear();
    if (const std::optional<std::string> appVars = ExtractTopLevelObject(payloadJson, "appVariables"); appVars.has_value()) {
      appVariablesJson_ = *appVars;
    }
    licenseVariablesJson_.clear();
    if (const std::optional<std::string> licenseVars = ExtractTopLevelObject(payloadJson, "licenseVariables"); licenseVars.has_value()) {
      licenseVariablesJson_ = *licenseVars;
    }
    authenticated_ = true;
  }
}

std::string AuthForgeClient::PostJson(const std::string &path, const std::string &bodyJson, std::string *usedNonce) const {
  EnsureCurlInit();

  const std::string url = apiBaseUrl_ + path;
  std::array<int, 2> rateRetryDelays = {2, 5};
  std::string mutableBody = bodyJson;
  std::string currentNonce = ExtractNonceFromBody(mutableBody).value_or("");
  bool networkRetried = false;
  int rateAttempt = 0;

  while (true) {
    CURL *curl = curl_easy_init();
    if (curl == nullptr) {
      throw std::runtime_error("url_error: curl_easy_init_failed");
    }

    std::string responseBody;
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, mutableBody.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(mutableBody.size()));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, static_cast<long>(requestTimeout_));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBody);

    const CURLcode rc = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK) {
      if (!networkRetried) {
        networkRetried = true;
        std::this_thread::sleep_for(std::chrono::seconds(2));
        continue;
      }
      throw std::runtime_error(std::string("url_error: ") + curl_easy_strerror(rc));
    }

    const std::string trimmed = Trim(responseBody);
    if (trimmed.empty()) {
      throw std::runtime_error("invalid_json_response");
    }
    if (trimmed.front() != '{' || trimmed.back() != '}') {
      throw std::runtime_error("response_not_json_object");
    }

    const bool isRateLimited = (code == 429) || (ExtractServerError(trimmed) == "rate_limited");
    if (isRateLimited && rateAttempt < static_cast<int>(rateRetryDelays.size())) {
      std::this_thread::sleep_for(std::chrono::seconds(rateRetryDelays[rateAttempt]));
      currentNonce = GenerateNonceHex32();
      mutableBody = RefreshNonceInBody(mutableBody, currentNonce);
      ++rateAttempt;
      continue;
    }

    if (code >= 400) {
      throw std::runtime_error("http_error_" + std::to_string(code) + ": " + trimmed);
    }

    if (usedNonce != nullptr) {
      *usedNonce = currentNonce;
    }
    return trimmed;
  }
}

std::string AuthForgeClient::ExtractServerError(const std::string &responseJson) const {
  JsonValue errorValue;
  if (ExtractJsonValue(responseJson, "error", errorValue) && errorValue.exists) {
    const std::string candidate = ToLower(Trim(errorValue.value));
    if (knownServerErrors_.find(candidate) != knownServerErrors_.end()) {
      return candidate;
    }
  }

  JsonValue statusValue;
  if (ExtractJsonValue(responseJson, "status", statusValue) && statusValue.exists) {
    const std::string candidate = ToLower(Trim(statusValue.value));
    if (knownServerErrors_.find(candidate) != knownServerErrors_.end()) {
      return candidate;
    }
  }

  return "unknown_error";
}

void AuthForgeClient::Fail(const std::string &reason, const std::exception *exc) const noexcept {
  if (onFailure_) {
    try {
      onFailure_(reason, exc);
      return;
    } catch (...) {
    }
  }
  std::exit(1);
}

void AuthForgeClient::Logout() {
  std::lock_guard<std::mutex> guard(lock_);
  heartbeatStop_ = true;
  heartbeatStarted_ = false;
  licenseKey_.clear();
  sessionToken_.clear();
  sessionExpiresIn_ = std::nullopt;
  lastNonce_.clear();
  rawPayloadB64_.clear();
  signature_.clear();
  keyId_.clear();
  sessionDataJson_.clear();
  appVariablesJson_.clear();
  licenseVariablesJson_.clear();
  authenticated_ = false;
}

bool AuthForgeClient::IsAuthenticated() const {
  std::lock_guard<std::mutex> guard(lock_);
  return authenticated_ && !sessionToken_.empty();
}

std::optional<std::string> AuthForgeClient::GetSessionDataJson() const {
  std::lock_guard<std::mutex> guard(lock_);
  if (sessionDataJson_.empty()) {
    return std::nullopt;
  }
  return sessionDataJson_;
}

std::optional<std::string> AuthForgeClient::GetAppVariablesJson() const {
  std::lock_guard<std::mutex> guard(lock_);
  if (appVariablesJson_.empty()) {
    return std::nullopt;
  }
  return appVariablesJson_;
}

std::optional<std::string> AuthForgeClient::GetLicenseVariablesJson() const {
  std::lock_guard<std::mutex> guard(lock_);
  if (licenseVariablesJson_.empty()) {
    return std::nullopt;
  }
  return licenseVariablesJson_;
}

std::string AuthForgeClient::GetHwid() const {
  const std::string mac = SafeMacAddress();
  const std::string cpu = SafeCpuInfo();
  const std::string disk = SafeDiskSerial();
  const std::string material = "mac:" + mac + "|cpu:" + cpu + "|disk:" + disk;
  return Sha256Hex(material);
}

std::string AuthForgeClient::SafeMacAddress() const {
  try {
#ifdef _WIN32
    ULONG size = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, nullptr, nullptr, &size) != ERROR_BUFFER_OVERFLOW) {
      return "mac-unavailable";
    }
    std::vector<unsigned char> buffer(size);
    auto *addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data());
    const ULONG result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, nullptr, addresses, &size);
    if (result != NO_ERROR) {
      return "mac-unavailable";
    }
    for (IP_ADAPTER_ADDRESSES *entry = addresses; entry != nullptr; entry = entry->Next) {
      if (entry->PhysicalAddressLength == 0) {
        continue;
      }
      std::ostringstream oss;
      for (ULONG i = 0; i < entry->PhysicalAddressLength; ++i) {
        oss << std::hex << std::nouppercase;
        oss.width(2);
        oss.fill('0');
        oss << static_cast<int>(entry->PhysicalAddress[i]);
      }
      const std::string mac = oss.str();
      if (!mac.empty()) {
        return mac;
      }
    }
    return "mac-unavailable";
#elif defined(__linux__)
    namespace fs = std::filesystem;
    const fs::path netPath("/sys/class/net");
    if (!fs::exists(netPath)) {
      return "mac-unavailable";
    }
    for (const auto &entry : fs::directory_iterator(netPath)) {
      const fs::path addressPath = entry.path() / "address";
      if (!fs::exists(addressPath)) {
        continue;
      }
      std::ifstream file(addressPath);
      std::string mac;
      std::getline(file, mac);
      mac = ToLower(Trim(mac));
      mac.erase(std::remove(mac.begin(), mac.end(), ':'), mac.end());
      if (!mac.empty() && mac != "000000000000") {
        return mac;
      }
    }
    return "mac-unavailable";
#elif defined(__APPLE__)
    struct ifaddrs *ifaddr = nullptr;
    if (getifaddrs(&ifaddr) != 0 || ifaddr == nullptr) {
      return "mac-unavailable";
    }

    std::string mac = "mac-unavailable";
    for (struct ifaddrs *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
      if (ifa->ifa_addr == nullptr || (ifa->ifa_flags & IFF_LOOPBACK) != 0) {
        continue;
      }
      if (ifa->ifa_addr->sa_family != AF_LINK) {
        continue;
      }
      auto *sdl = reinterpret_cast<sockaddr_dl *>(ifa->ifa_addr);
      const unsigned char *base = reinterpret_cast<const unsigned char *>(LLADDR(sdl));
      if (sdl->sdl_alen <= 0) {
        continue;
      }
      std::ostringstream oss;
      for (int i = 0; i < sdl->sdl_alen; ++i) {
        oss << std::hex << std::nouppercase;
        oss.width(2);
        oss.fill('0');
        oss << static_cast<int>(base[i]);
      }
      mac = oss.str();
      if (!mac.empty()) {
        break;
      }
    }
    freeifaddrs(ifaddr);
    return mac;
#else
    return "mac-unavailable";
#endif
  } catch (...) {
    return "mac-unavailable";
  }
}

std::string AuthForgeClient::SafeCpuInfo() const {
  try {
#ifdef _WIN32
    int cpuInfo[4] = {0, 0, 0, 0};
    __cpuid(cpuInfo, 0);
    char vendor[13] = {};
    std::memcpy(vendor + 0, &cpuInfo[1], 4);
    std::memcpy(vendor + 4, &cpuInfo[3], 4);
    std::memcpy(vendor + 8, &cpuInfo[2], 4);

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    std::ostringstream oss;
    oss << vendor << "-" << static_cast<unsigned long>(sysInfo.dwProcessorType);
    return oss.str();
#elif defined(__linux__)
    std::ifstream cpuFile("/proc/cpuinfo");
    if (!cpuFile.is_open()) {
      return "cpu-unavailable";
    }
    std::string line;
    while (std::getline(cpuFile, line)) {
      if (line.rfind("model name", 0) == 0 || line.rfind("Hardware", 0) == 0 || line.rfind("Processor", 0) == 0) {
        const std::size_t pos = line.find(':');
        if (pos != std::string::npos) {
          return Trim(line.substr(pos + 1));
        }
      }
    }
    cpuFile.clear();
    cpuFile.seekg(0, std::ios::beg);
    std::ostringstream all;
    all << cpuFile.rdbuf();
    const std::string compact = JoinAndCompactWhitespace(all.str());
    return compact.empty() ? "cpu-unavailable" : compact.substr(0, std::min<std::size_t>(compact.size(), 256));
#elif defined(__APPLE__)
    std::array<char, 256> buffer{};
    std::size_t size = buffer.size();
    if (sysctlbyname("machdep.cpu.brand_string", buffer.data(), &size, nullptr, 0) == 0 && size > 1) {
      return std::string(buffer.data());
    }
    size = buffer.size();
    if (sysctlbyname("hw.model", buffer.data(), &size, nullptr, 0) == 0 && size > 1) {
      return std::string(buffer.data());
    }
    return "cpu-unavailable";
#else
    return "cpu-unavailable";
#endif
  } catch (...) {
    return "cpu-unavailable";
  }
}

std::string AuthForgeClient::SafeDiskSerial() const {
  try {
#ifdef _WIN32
    return RunCommand("wmic diskdrive get serialnumber");
#elif defined(__linux__)
    return RunCommand("lsblk -ndo SERIAL");
#elif defined(__APPLE__)
    return RunCommand("system_profiler SPStorageDataType");
#else
    return "disk-unavailable";
#endif
  } catch (...) {
    return "disk-unavailable";
  }
}

std::string AuthForgeClient::RunCommand(const std::string &command) const {
#ifdef _WIN32
  const std::string wrapped = command + " 2>NUL";
  FILE *pipe = _popen(wrapped.c_str(), "r");
#else
  const std::string wrapped = command + " 2>/dev/null";
  FILE *pipe = popen(wrapped.c_str(), "r");
#endif
  if (pipe == nullptr) {
    return "unavailable";
  }

  std::string output;
  std::array<char, 256> buffer{};
  while (std::fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
    output += buffer.data();
  }

#ifdef _WIN32
  const int rc = _pclose(pipe);
#else
  const int rc = pclose(pipe);
#endif
  if (rc != 0 && output.empty()) {
    return "unavailable";
  }

  const std::string compact = JoinAndCompactWhitespace(output);
  if (compact.empty()) {
    return "empty";
  }
  return compact.substr(0, std::min<std::size_t>(compact.size(), 256));
}

bool AuthForgeClient::ExtractJsonValue(const std::string &json, const std::string &key, JsonValue &outValue) {
  outValue = JsonValue{};
  const std::string needle = "\"" + key + "\"";
  std::size_t keyPos = json.find(needle);
  if (keyPos == std::string::npos) {
    return false;
  }

  std::size_t pos = json.find(':', keyPos + needle.size());
  if (pos == std::string::npos) {
    return false;
  }
  ++pos;
  while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos])) != 0) {
    ++pos;
  }
  if (pos >= json.size()) {
    return false;
  }

  outValue.exists = true;
  if (json[pos] == '"') {
    ++pos;
    std::string raw;
    bool escaping = false;
    for (; pos < json.size(); ++pos) {
      const char c = json[pos];
      if (escaping) {
        raw.push_back(c);
        escaping = false;
        continue;
      }
      if (c == '\\') {
        escaping = true;
        raw.push_back(c);
        continue;
      }
      if (c == '"') {
        break;
      }
      raw.push_back(c);
    }
    bool ok = true;
    outValue.isString = true;
    outValue.value = UnescapeJsonString(raw, ok);
    if (!ok) {
      outValue.value.clear();
    }
    return true;
  }

  std::size_t end = pos;
  while (end < json.size() && json[end] != ',' && json[end] != '}') {
    ++end;
  }
  outValue.isString = false;
  outValue.value = Trim(json.substr(pos, end - pos));
  return true;
}

std::optional<std::string> AuthForgeClient::ExtractJsonString(const std::string &json, const std::string &key) {
  JsonValue value;
  if (!ExtractJsonValue(json, key, value) || !value.exists) {
    return std::nullopt;
  }
  if (value.isString) {
    return value.value;
  }
  return Trim(value.value);
}

std::optional<long long> AuthForgeClient::ExtractJsonInt(const std::string &json, const std::string &key) {
  JsonValue value;
  if (!ExtractJsonValue(json, key, value) || !value.exists) {
    return std::nullopt;
  }
  const std::string source = value.isString ? value.value : Trim(value.value);
  if (source.empty()) {
    return std::nullopt;
  }
  try {
    std::size_t idx = 0;
    const long long parsed = std::stoll(source, &idx, 10);
    if (idx != source.size()) {
      return std::nullopt;
    }
    return parsed;
  } catch (...) {
    return std::nullopt;
  }
}

std::string AuthForgeClient::BuildJsonBody(const std::vector<std::pair<std::string, std::string>> &pairs) {
  std::ostringstream oss;
  oss << "{";
  bool first = true;
  for (const auto &item : pairs) {
    if (!first) {
      oss << ",";
    }
    first = false;
    oss << "\"" << EscapeJsonString(item.first) << "\":\"" << EscapeJsonString(item.second) << "\"";
  }
  oss << "}";
  return oss.str();
}

std::string AuthForgeClient::EscapeJsonString(const std::string &value) {
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

std::string AuthForgeClient::UnescapeJsonString(const std::string &value, bool &ok) {
  ok = true;
  std::string out;
  out.reserve(value.size());
  for (std::size_t i = 0; i < value.size(); ++i) {
    const char c = value[i];
    if (c != '\\') {
      out.push_back(c);
      continue;
    }
    if (i + 1 >= value.size()) {
      ok = false;
      return "";
    }
    const char esc = value[++i];
    switch (esc) {
    case '"':
      out.push_back('"');
      break;
    case '\\':
      out.push_back('\\');
      break;
    case '/':
      out.push_back('/');
      break;
    case 'b':
      out.push_back('\b');
      break;
    case 'f':
      out.push_back('\f');
      break;
    case 'n':
      out.push_back('\n');
      break;
    case 'r':
      out.push_back('\r');
      break;
    case 't':
      out.push_back('\t');
      break;
    case 'u':
      if (i + 4 >= value.size()) {
        ok = false;
        return "";
      }
      i += 4;
      out.push_back('?');
      break;
    default:
      ok = false;
      return "";
    }
  }
  return out;
}

std::string AuthForgeClient::Trim(const std::string &value) {
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

std::string AuthForgeClient::ToLower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return value;
}

std::string AuthForgeClient::GenerateNonceHex32() {
  std::array<unsigned char, 16> nonce{};
  randombytes_buf(nonce.data(), nonce.size());
  std::vector<unsigned char> bytes(nonce.begin(), nonce.end());
  return BytesToHexLower(bytes);
}

std::vector<unsigned char> AuthForgeClient::Sha256Bytes(const std::string &input) {
  std::vector<unsigned char> digest(SHA256_DIGEST_LENGTH);
  SHA256(reinterpret_cast<const unsigned char *>(input.data()), input.size(), digest.data());
  return digest;
}

std::string AuthForgeClient::Sha256Hex(const std::string &input) {
  std::vector<unsigned char> digest(SHA256_DIGEST_LENGTH);
  SHA256(reinterpret_cast<const unsigned char *>(input.data()), input.size(), digest.data());
  return BytesToHexLower(digest);
}

std::string AuthForgeClient::BytesToHexLower(const std::vector<unsigned char> &bytes) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (unsigned char b : bytes) {
    out.push_back(kHex[(b >> 4) & 0x0F]);
    out.push_back(kHex[b & 0x0F]);
  }
  return out;
}

std::vector<unsigned char> AuthForgeClient::DecodeBase64Any(const std::string &value) {
  try {
    return DecodeBase64WithAlphabet(value, false);
  } catch (...) {
    return DecodeBase64WithAlphabet(value, true);
  }
}

std::vector<unsigned char> AuthForgeClient::DecodeBase64WithAlphabet(const std::string &value, bool urlSafe) {
  std::string in = value;
  in.erase(std::remove_if(in.begin(), in.end(), [](unsigned char c) { return std::isspace(c) != 0; }), in.end());
  in = AddBase64Padding(in);
  if (in.empty() || (in.size() % 4) != 0) {
    throw std::runtime_error("invalid_base64");
  }

  auto decodeChar = [urlSafe](char c) -> int {
    if (c >= 'A' && c <= 'Z') {
      return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
      return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
      return c - '0' + 52;
    }
    if (urlSafe) {
      if (c == '-') {
        return 62;
      }
      if (c == '_') {
        return 63;
      }
    } else {
      if (c == '+') {
        return 62;
      }
      if (c == '/') {
        return 63;
      }
    }
    return -1;
  };

  std::vector<unsigned char> out;
  out.reserve((in.size() / 4) * 3);
  for (std::size_t i = 0; i < in.size(); i += 4) {
    const char c0 = in[i + 0];
    const char c1 = in[i + 1];
    const char c2 = in[i + 2];
    const char c3 = in[i + 3];
    const int v0 = decodeChar(c0);
    const int v1 = decodeChar(c1);
    const int v2 = (c2 == '=') ? -2 : decodeChar(c2);
    const int v3 = (c3 == '=') ? -2 : decodeChar(c3);

    if (v0 < 0 || v1 < 0 || v2 == -1 || v3 == -1) {
      throw std::runtime_error("invalid_base64");
    }

    const unsigned int triple =
        (static_cast<unsigned int>(v0) << 18) |
        (static_cast<unsigned int>(v1) << 12) |
        (static_cast<unsigned int>((v2 >= 0 ? v2 : 0)) << 6) |
        static_cast<unsigned int>((v3 >= 0 ? v3 : 0));

    out.push_back(static_cast<unsigned char>((triple >> 16) & 0xFF));
    if (v2 >= 0) {
      out.push_back(static_cast<unsigned char>((triple >> 8) & 0xFF));
    }
    if (v3 >= 0) {
      out.push_back(static_cast<unsigned char>(triple & 0xFF));
    }
  }
  return out;
}

std::string AuthForgeClient::AddBase64Padding(const std::string &value) {
  const std::size_t remainder = value.size() % 4;
  if (remainder == 0) {
    return value;
  }
  return value + std::string(4 - remainder, '=');
}

bool AuthForgeClient::IsSuccessStatus(const JsonValue &status) {
  if (!status.exists) {
    return false;
  }
  if (!status.isString) {
    const std::string token = ToLower(Trim(status.value));
    if (token == "true") {
      return true;
    }
    if (token == "false" || token == "null") {
      return false;
    }
    return token == "ok" || token == "success" || token == "valid" || token == "1" || token == "true";
  }
  const std::string token = ToLower(Trim(status.value));
  return token == "ok" || token == "success" || token == "valid" || token == "true" || token == "1";
}

std::optional<std::string> AuthForgeClient::DecodeSessionTokenBody(const std::string &sessionToken) {
  const std::size_t dot = sessionToken.find('.');
  if (dot == std::string::npos) {
    return std::nullopt;
  }
  const std::string payloadPart = sessionToken.substr(0, dot);
  if (payloadPart.empty()) {
    return std::nullopt;
  }

  std::vector<unsigned char> decoded;
  try {
    decoded = DecodeBase64WithAlphabet(payloadPart, true);
  } catch (...) {
    return std::nullopt;
  }

  return std::string(decoded.begin(), decoded.end());
}

std::optional<long long> AuthForgeClient::ExtractExpiresInFromSessionToken(const std::string &sessionToken) {
  const auto body = DecodeSessionTokenBody(sessionToken);
  if (!body.has_value()) {
    return std::nullopt;
  }
  return ExtractJsonInt(*body, "exp");
}

void AuthForgeClient::VerifySignature(
    const std::string &rawPayloadB64,
    const std::string &signature) const {
  const std::vector<unsigned char> signatureBytes = DecodeBase64Any(signature);
  if (signatureBytes.size() != crypto_sign_BYTES) {
    throw std::runtime_error("signature_mismatch");
  }
  if (crypto_sign_verify_detached(
          signatureBytes.data(),
          reinterpret_cast<const unsigned char *>(rawPayloadB64.data()),
          static_cast<unsigned long long>(rawPayloadB64.size()),
          verifyPublicKeyBytes_.data()) != 0) {
    throw std::runtime_error("signature_mismatch");
  }
}

} // namespace authforge
