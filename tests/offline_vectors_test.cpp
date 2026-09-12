// Conformance test for offline `.authforge` license files.
//
// Runs every case in offline_license_vectors.json through the SDK verifier and
// exercises the client-level LoginFromFile / VerifyLicenseFile / GetHwid
// surface. Built with -DAUTHFORGE_BUILD_TESTS=ON and run through ctest.
//
// The SDK keeps its JSON reader private; including the implementation file
// here gives the test access to it for reading the vector fixture without
// adding a JSON dependency.
#include "../authforge_offline.cpp"

#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#ifndef AUTHFORGE_SDK_VERSION
#error "AUTHFORGE_SDK_VERSION must be defined from CMake PROJECT_VERSION"
#endif

namespace authforge {

// Befriended by AuthForgeClient (see authforge_sdk.h) so the test can drive
// the private heartbeat entry point and read its state.
struct OfflineVectorsTestAccess {
  static void StartHeartbeatOnce(AuthForgeClient &client) { client.StartHeartbeatOnce(); }
  static bool HeartbeatStarted(const AuthForgeClient &client) {
    std::lock_guard<std::mutex> guard(client.lock_);
    return client.heartbeatStarted_;
  }
};

} // namespace authforge

namespace {

int g_failures = 0;

void Check(bool condition, const std::string &message) {
  if (!condition) {
    ++g_failures;
    std::cerr << "FAIL: " << message << "\n";
  }
}

std::string ReadFile(const std::string &path) {
  std::ifstream in(path, std::ios::in | std::ios::binary);
  if (!in) {
    throw std::runtime_error("cannot open " + path);
  }
  std::ostringstream buffer;
  buffer << in.rdbuf();
  return buffer.str();
}

std::string Str(const authforge::JsonNode *node) {
  return node != nullptr && node->kind == authforge::JsonNode::Kind::String ? node->stringValue : std::string();
}

struct Case {
  std::string name;
  std::string appId;
  std::string publicKey;
  std::string hwid;
  std::string now;
  std::string file;
  std::string expect;
  std::string payloadBase64;
  std::string signatureBase64;
};

const Case &Find(const std::vector<Case> &cases, const std::string &name) {
  for (const auto &c : cases) {
    if (c.name == name) return c;
  }
  throw std::runtime_error("case not found: " + name);
}

struct TestClient {
  std::vector<std::pair<std::string, std::string>> failures;
  std::unique_ptr<authforge::AuthForgeClient> client;

  TestClient(const Case &good,
             const std::string &appId,
             const std::string &publicKey,
             const std::string &hwid,
             authforge::OnlineHeartbeat onlineHeartbeat = authforge::OnlineHeartbeat::Off) {
    auto *sink = &failures;
    client = std::make_unique<authforge::AuthForgeClient>(
        appId.empty() ? good.appId : appId,
        "",
        publicKey.empty() ? good.publicKey : publicKey,
        onlineHeartbeat,
        900,
        // Any network call would hit a closed port and fail loudly.
        "http://127.0.0.1:9",
        [sink](const std::string &reason, const std::exception *exc) {
          sink->emplace_back(reason, exc != nullptr ? exc->what() : "");
        },
        15,
        0,
        hwid.empty() ? good.hwid : hwid);
  }
};

} // namespace

int main(int argc, char **argv) {
  if (argc < 2) {
    std::cerr << "usage: offline_vectors_test <offline_license_vectors.json>\n";
    return 2;
  }
  // Deliberately no sodium_init() here: the vector loop below runs before any
  // AuthForgeClient exists, proving the free VerifyLicenseFile initialises
  // libsodium on its own.

  const std::string json = ReadFile(argv[1]);
  authforge::JsonNode root = authforge::JsonReader(json).ParseDocument();
  Check(root.Get("version") != nullptr && root.Get("version")->numberValue == 1, "vectors version is 1");

  std::vector<Case> cases;
  const authforge::JsonNode *caseArray = root.Get("cases");
  Check(caseArray != nullptr && caseArray->array.size() >= 15, "at least 15 vector cases");
  for (const auto &node : caseArray->array) {
    Case c;
    c.name = Str(node.Get("name"));
    c.appId = Str(node.Get("appId"));
    c.publicKey = Str(node.Get("publicKey"));
    c.hwid = Str(node.Get("hwid"));
    c.now = Str(node.Get("now"));
    c.file = Str(node.Get("file"));
    c.expect = Str(node.Get("expect"));
    c.payloadBase64 = Str(node.Get("payloadBase64"));
    c.signatureBase64 = Str(node.Get("signatureBase64"));
    cases.push_back(c);
  }
  const std::string wrongPublicKey = Str(root.Get("keys")->Get("wrongPublicKey"));

  // 1. Every vector case verifies to the expected result.
  for (const auto &c : cases) {
    const auto now = authforge::ParseIso8601Ms(c.now);
    Check(now.has_value(), c.name + ": now parses");
    const auto result = authforge::VerifyLicenseFile(c.file, c.appId, {c.publicKey}, c.hwid, now.value_or(1));
    const std::string got = result.ok ? "ok" : result.error;
    Check(got == c.expect, c.name + ": expected " + c.expect + ", got " + got);
    if (result.ok && !c.payloadBase64.empty()) {
      Check(result.license.payloadBase64 == c.payloadBase64, c.name + ": canonical payload string");
      Check(result.license.signatureBase64 == c.signatureBase64, c.name + ": canonical signature string");
    }
  }

  // 2. Parser recovers the canonical signed string and headers.
  const Case &good = Find(cases, "good_bound");
  {
    const auto parsed = authforge::ParseLicenseFile(good.file);
    Check(parsed.has_value(), "good file parses");
    if (parsed) {
      Check(parsed->payloadBase64 == good.payloadBase64, "parsed payload matches");
      Check(parsed->signatureBase64 == good.signatureBase64, "parsed signature matches");
      bool sawVersion = false;
      for (const auto &h : parsed->headers) {
        if (h.first == "Version" && h.second == "1") sawVersion = true;
      }
      Check(sawVersion, "Version header present");
    }
    Check(!authforge::ParseLicenseFile("nope").has_value(), "garbage does not parse");
  }

  // 3. Good file exposes entitlements.
  {
    const auto result = authforge::VerifyLicenseFile(good.file, good.appId, {good.publicKey}, good.hwid,
                                                     *authforge::ParseIso8601Ms(good.now));
    Check(result.ok, "good_bound ok");
    Check(result.license.licenseKey == "TEST-KEY0-0000-0000", "license key");
    Check(result.license.keyId == "kid-test-0001", "key id");
    Check(result.license.hwidPolicy.mode == "bound" && result.license.hwidPolicy.hwids.size() == 2, "hwid policy");
    Check(result.license.label.has_value() && *result.license.label == "Vector license", "label");
    Check(result.license.expiresAt.has_value() && *result.license.expiresAt == "2027-01-01T00:00:00.000Z", "expiresAt");
    Check(result.license.licenseExpirationKnown && result.license.licenseExpiresAt.empty(), "licenseExpiresAt null");
    Check(result.license.licenseVariablesJson.find("\"tier\":\"pro\"") != std::string::npos, "license variables json");
    Check(result.license.appVariablesJson.find("\"theme\":\"dark\"") != std::string::npos, "app variables json");
  }

  // 4. Client LoginFromFile: offline, no heartbeat, state populated.
  // Client-level checks run against the wall clock: use the lifetime vector
  // (expiresAt null) so they never turn into "expired" in 2027.
  const Case &lifetime = Find(cases, "good_lifetime");
  {
    TestClient t(lifetime, "", "", "");
    Check(t.client->GetHwid() == good.hwid, "GetHwid returns override");
    Check(t.client->GetSessionKind() == authforge::SessionKind::None, "no session kind before login");
    Check(t.client->LoginFromFile(lifetime.file), "LoginFromFile succeeds");
    Check(t.client->IsAuthenticated(), "authenticated after LoginFromFile");
    Check(t.client->GetSessionKind() == authforge::SessionKind::Offline, "session kind is Offline");
    const auto offline = t.client->GetOfflineLicense();
    Check(offline.has_value() && offline->jti == "00000000-0000-4000-8000-000000000003", "GetOfflineLicense jti");
    const auto vars = t.client->GetLicenseVariablesJson();
    Check(vars.has_value() && vars->find("\"tier\":\"pro\"") != std::string::npos, "license variables populated");
    const auto session = t.client->GetSessionDataJson();
    Check(session.has_value() && session->find("TEST-KEY0-0000-0000") != std::string::npos, "session data populated");
    Check(t.failures.empty(), "no onFailure calls on success");
    t.client->Logout();
    Check(!t.client->IsAuthenticated(), "logout clears auth");
    Check(t.client->GetSessionKind() == authforge::SessionKind::None, "logout clears session kind");
    Check(!t.client->GetOfflineLicense().has_value(), "logout clears offline license");
    bool loginThrew = false;
    try {
      t.client->Login("XXXX-XXXX-XXXX-XXXX");
    } catch (const std::invalid_argument &ex) {
      loginThrew = std::string(ex.what()).find("app_secret is required") != std::string::npos;
    }
    Check(loginThrew, "Login requires app secret on an offline-only client");
  }

  // 4b. Offline SelfBan is a local error and never reaches the network. The
  // client points at a closed port, so any HTTP attempt would surface as a
  // transport error rather than the offline_session code.
  {
    TestClient t(lifetime, "", "", "");
    Check(t.client->LoginFromFile(lifetime.file), "LoginFromFile before SelfBan");
    Check(!t.client->SelfBan(), "SelfBan returns false on an offline session");
    Check(t.failures.size() == 1 && t.failures[0].first == "selfban_failed" && t.failures[0].second == "offline_session",
          "SelfBan reports onFailure(selfban_failed, offline_session)");
    Check(t.client->IsAuthenticated(), "offline session survives the local SelfBan failure");
  }

  // 4c. The heartbeat entry point is a no-op for offline sessions even when
  // online check-ins are enabled.
  {
    TestClient t(lifetime, "", "", "", authforge::OnlineHeartbeat::On);
    Check(t.client->LoginFromFile(lifetime.file), "LoginFromFile with OnlineHeartbeat::On");
    Check(!authforge::OfflineVectorsTestAccess::HeartbeatStarted(*t.client), "no heartbeat after LoginFromFile");
    authforge::OfflineVectorsTestAccess::StartHeartbeatOnce(*t.client);
    Check(!authforge::OfflineVectorsTestAccess::HeartbeatStarted(*t.client), "StartHeartbeatOnce is a no-op offline");
    Check(t.failures.empty(), "no onFailure calls from heartbeat paths");
    Check(t.client->IsAuthenticated(), "still authenticated offline");
  }

  // 5. Rejections surface through onFailure with the cross-SDK code.
  struct Reject {
    const char *label;
    std::string appId;
    std::string publicKey;
    std::string hwid;
    std::string file;
    const char *code;
  };
  const std::vector<Reject> rejects = {
      {"tampered", "", "", "", Find(cases, "bad_signature_tampered_body").file, "bad_signature"},
      {"wrong key", "", wrongPublicKey, "", lifetime.file, "bad_signature"},
      {"expired", "", "", "", Find(cases, "expired").file, "expired"},
      {"hwid mismatch", "", "", "otherhwid", lifetime.file, "hwid_mismatch"},
      {"wrong app", "other-app", "", "", lifetime.file, "wrong_app"},
      {"unsupported version", "", "", "", Find(cases, "unsupported_version").file, "unsupported_version"},
  };
  for (const auto &r : rejects) {
    TestClient t(lifetime, r.appId, r.publicKey, r.hwid);
    Check(!t.client->LoginFromFile(r.file), std::string(r.label) + ": LoginFromFile returns false");
    Check(!t.client->IsAuthenticated(), std::string(r.label) + ": not authenticated");
    Check(t.failures.size() == 1 && t.failures[0].first == "offline_login_failed" && t.failures[0].second == r.code,
          std::string(r.label) + ": onFailure(offline_login_failed, " + r.code + ")");
  }

  // 6. Reads from disk; VerifyLicenseFile is side-effect free; unreadable path never exits.
  {
    TestClient t(lifetime, "", "", "");
    const std::string path = std::string(argv[0]) + ".license.authforge";
    {
      std::ofstream out(path, std::ios::out | std::ios::binary);
      out << lifetime.file;
    }
    const auto checked = t.client->VerifyLicenseFile(path, 0);
    Check(checked.ok, "VerifyLicenseFile(path) ok");
    Check(!t.client->IsAuthenticated(), "VerifyLicenseFile does not authenticate");
    Check(t.client->LoginFromFile(path), "LoginFromFile(path) ok");
    Check(t.client->IsAuthenticated(), "authenticated after LoginFromFile(path)");
    std::remove(path.c_str());
    Check(!t.client->LoginFromFile(path + ".missing"), "missing file returns false");
    Check(t.failures.size() == 1 && t.failures[0].first == "offline_login_failed", "missing file reports offline_login_failed");
  }

  {
    Check(std::string(kActivationRequestSdkTag) == std::string("cpp/") + AUTHFORGE_SDK_VERSION,
          "kActivationRequestSdkTag matches CMake project version");
    std::string requestPath(argv[1]);
    const auto slash = requestPath.find_last_of("/\\");
    requestPath = (slash == std::string::npos ? std::string() : requestPath.substr(0, slash + 1)) +
                  "activation_request_vectors.json";
    const std::string requestJson = ReadFile(requestPath);
    authforge::JsonNode requestRoot = authforge::JsonReader(requestJson).ParseDocument();
    const authforge::JsonNode *requestCases = requestRoot.Get("cases");
    Check(requestCases != nullptr && !requestCases->array.empty(), "activation request vectors present");
    const std::string dummyKey = "0wRcYWn44wk9tHOisXgso1wbtUqpFdy0IeMk4HXDiNc=";
    for (const auto &node : requestCases->array) {
      const authforge::JsonNode *inputs = node.Get("inputs");
      if (inputs == nullptr || inputs->kind != authforge::JsonNode::Kind::Object) {
        continue;
      }
      const std::string name = Str(node.Get("name"));
      const std::string want = Str(node.Get("file"));
      const std::string appId = Str(inputs->Get("appId"));
      const std::string hwid = Str(inputs->Get("hwid"));
      const std::string createdAt = Str(inputs->Get("createdAt"));
      const std::string machineName = Str(inputs->Get("machineName"));
      const std::string os = Str(inputs->Get("os"));
      const std::string sdk = Str(inputs->Get("sdk"));
      const std::string licenseKey = Str(inputs->Get("licenseKey"));
      authforge::AuthForgeClient client(appId, "", dummyKey, authforge::OnlineHeartbeat::Off, 900, "http://127.0.0.1:9",
                                       nullptr, 15, 0, hwid);
      authforge::ActivationRequestOptions opts;
      opts.createdAt = createdAt;
      opts.omitOs = os.empty();
      opts.omitSdk = sdk.empty();
      opts.includeMachineName = !machineName.empty();
      opts.machineName = machineName;
      opts.os = os;
      opts.sdk = sdk;
      opts.licenseKey = licenseKey;
      const std::string got = client.CreateActivationRequest(opts);
      Check(got == want, name + ": CreateActivationRequest matches vector");
      Check(authforge::FormatActivationRequest(appId, hwid, createdAt, machineName, os, sdk, licenseKey) == want,
            name + ": FormatActivationRequest matches vector");
    }
  }

  if (g_failures != 0) {
    std::cerr << g_failures << " check(s) failed\n";
    return 1;
  }
  std::cout << "offline license file conformance: all checks passed (" << cases.size() << " vector cases)\n";
  return 0;
}
