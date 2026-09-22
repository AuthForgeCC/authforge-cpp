// Heartbeat failure contract test.
//
// Drives the private HeartbeatTick / heartbeat thread through a fake transport
// and a recording sleep: every definitive code clears the session and stops
// check-ins, everything else is transient and keeps the session, and the
// onFailure callback can call Logout()/IsAuthenticated() or destroy the
// client without deadlocking. Built with -DAUTHFORGE_BUILD_TESTS=ON and run
// through ctest.
//
// Including the implementation file gives the test the SDK's private JSON
// reader for the vector fixture (see offline_vectors_test.cpp).
#include "../authforge_offline.cpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <functional>
#include <future>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace authforge {

// Befriended by AuthForgeClient (see authforge_sdk.h).
struct HeartbeatTestAccess {
  using Response = AuthForgeClient::HttpResponse;
  using Transport = std::function<Response(const std::string &, const std::string &, long)>;

  static void SetTransport(AuthForgeClient &client, Transport transport) { client.transport_ = std::move(transport); }
  static void SetSleep(AuthForgeClient &client, std::function<void(std::chrono::seconds)> sleep) {
    client.sleep_ = std::move(sleep);
  }
  static void SetNonce(AuthForgeClient &client, const std::string &nonce) {
    client.nonce_ = [nonce]() { return nonce; };
  }
  static void SetInterval(AuthForgeClient &client, int seconds) { client.heartbeatInterval_ = seconds; }
  static void SeedSession(AuthForgeClient &client,
                          const std::string &sessionToken,
                          long long expiresIn,
                          const std::string &rawPayloadB64 = "",
                          const std::string &signature = "") {
    std::lock_guard<std::mutex> guard(client.lock_);
    ++client.sessionGeneration_;
    client.authenticated_ = true;
    client.sessionKind_ = SessionKind::Online;
    client.sessionToken_ = sessionToken;
    client.sessionExpiresIn_ = expiresIn;
    client.rawPayloadB64_ = rawPayloadB64;
    client.signature_ = signature;
  }
  static bool Tick(AuthForgeClient &client) { return client.HeartbeatTick(); }
  static void Start(AuthForgeClient &client) { client.StartHeartbeatOnce(); }
  static std::string SessionToken(const AuthForgeClient &client) {
    std::lock_guard<std::mutex> guard(client.lock_);
    return client.sessionToken_;
  }
  static std::optional<long long> SessionExpiresIn(const AuthForgeClient &client) {
    std::lock_guard<std::mutex> guard(client.lock_);
    return client.sessionExpiresIn_;
  }
};

} // namespace authforge

namespace {

using authforge::AuthForgeClient;
using authforge::AuthForgeError;
using Access = authforge::HeartbeatTestAccess;
using Response = Access::Response;

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

struct Vector {
  std::string payload;
  std::string signature;
};

Vector FindVector(const authforge::JsonNode &root, const std::string &id) {
  const authforge::JsonNode *cases = root.Get("cases");
  if (cases != nullptr) {
    for (const auto &node : cases->array) {
      if (Str(node.Get("id")) == id) {
        return {Str(node.Get("payload")), Str(node.Get("signature"))};
      }
    }
  }
  throw std::runtime_error("vector not found: " + id);
}

Response Http(long status, const std::string &body) {
  Response response;
  response.transportOk = true;
  response.status = status;
  response.body = body;
  return response;
}

Response Failed(long status, const std::string &code) {
  return Http(status, "{\"status\":\"failed\",\"error\":\"" + code + "\"}");
}

Response Signed(const Vector &vector) {
  return Http(200, "{\"status\":\"ok\",\"payload\":\"" + vector.payload + "\",\"signature\":\"" + vector.signature +
                       "\",\"keyId\":\"kid-test\"}");
}

Response TransportDown(bool timedOut) {
  Response response;
  response.transportOk = false;
  response.timedOut = timedOut;
  response.transportError = timedOut ? "Timeout was reached" : "Couldn't connect to server";
  return response;
}

struct FakeServer {
  std::mutex mutex;
  std::vector<Response> script;
  std::vector<std::string> urls;
  std::function<void()> onRequest;

  int Requests() {
    std::lock_guard<std::mutex> guard(mutex);
    return static_cast<int>(urls.size());
  }
};

struct Record {
  std::string reason;
  std::string what;
  std::string code;
  bool typed = false;
  bool transient = false;
};

struct Recorder {
  std::mutex mutex;
  std::vector<Record> records;
  std::vector<int> sleeps;
  std::function<void()> hook;

  std::vector<Record> Records() {
    std::lock_guard<std::mutex> guard(mutex);
    return records;
  }
};

constexpr const char *kPublicKey = "0wRcYWn44wk9tHOisXgso1wbtUqpFdy0IeMk4HXDiNc=";
constexpr const char *kHeartbeatNonce = "nonce-heartbeat-001";

long long Now() { return static_cast<long long>(std::time(nullptr)); }

struct Harness {
  std::shared_ptr<FakeServer> server = std::make_shared<FakeServer>();
  std::shared_ptr<Recorder> recorder = std::make_shared<Recorder>();
  std::unique_ptr<AuthForgeClient> client;

  explicit Harness(authforge::OnlineHeartbeat mode = authforge::OnlineHeartbeat::On) {
    client.reset(Create(mode, server, recorder));
  }

  static AuthForgeClient *Create(authforge::OnlineHeartbeat mode,
                                 const std::shared_ptr<FakeServer> &server,
                                 const std::shared_ptr<Recorder> &recorder) {
    auto *created = new AuthForgeClient(
        "app-test",
        "secret-test",
        kPublicKey,
        mode,
        900,
        "http://127.0.0.1:9",
        [recorder](const std::string &reason, const std::exception *exc) {
          Record record;
          record.reason = reason;
          if (exc != nullptr) {
            record.what = exc->what();
          }
          if (const auto *error = dynamic_cast<const AuthForgeError *>(exc)) {
            record.typed = true;
            record.code = error->code();
            record.transient = error->isTransient();
          }
          std::function<void()> hook;
          {
            std::lock_guard<std::mutex> guard(recorder->mutex);
            recorder->records.push_back(record);
            hook = recorder->hook;
          }
          if (hook) {
            hook();
          }
        },
        15,
        0,
        "hwid-test");
    Access::SetTransport(*created, [server](const std::string &url, const std::string &, long) {
      std::function<void()> onRequest;
      Response response;
      {
        std::lock_guard<std::mutex> guard(server->mutex);
        server->urls.push_back(url);
        const std::size_t index = (std::min)(server->urls.size(), server->script.size()) - 1;
        response = server->script.at(index);
        onRequest = server->onRequest;
      }
      if (onRequest) {
        onRequest();
      }
      return response;
    });
    Access::SetSleep(*created, [recorder](std::chrono::seconds delay) {
      std::lock_guard<std::mutex> guard(recorder->mutex);
      recorder->sleeps.push_back(static_cast<int>(delay.count()));
    });
    Access::SetNonce(*created, kHeartbeatNonce);
    return created;
  }

  void Script(std::vector<Response> responses) {
    std::lock_guard<std::mutex> guard(server->mutex);
    server->script = std::move(responses);
  }

  void Seed(long long expiresIn = 0) {
    Access::SeedSession(*client, "session.seed.token", expiresIn == 0 ? Now() + 3600 : expiresIn);
  }

  std::vector<int> Sleeps() {
    std::lock_guard<std::mutex> guard(recorder->mutex);
    return recorder->sleeps;
  }
};

std::string Join(const std::vector<int> &values) {
  std::string out;
  for (const int value : values) {
    out += (out.empty() ? "" : ",") + std::to_string(value);
  }
  return "[" + out + "]";
}

struct Expectation {
  std::string code;
  bool fatal = false;
  int requests = 1;
  std::vector<int> sleeps;
  std::string whatPrefix;
};

void ExpectTick(const std::string &label, std::vector<Response> script, const Expectation &want) {
  Harness h;
  h.Script(std::move(script));
  h.Seed();
  const bool keepRunning = Access::Tick(*h.client);
  const auto records = h.recorder->Records();
  Check(keepRunning == !want.fatal, label + ": tick returns " + (want.fatal ? "false" : "true"));
  Check(records.size() == 1, label + ": onFailure called once (got " + std::to_string(records.size()) + ")");
  if (!records.empty()) {
    const Record &r = records.front();
    Check(r.reason == "heartbeat_failed", label + ": reason heartbeat_failed");
    Check(r.typed, label + ": exception is AuthForgeError");
    Check(r.code == want.code, label + ": code " + want.code + " (got " + r.code + ")");
    Check(r.transient == !want.fatal, label + ": transient flag");
    if (want.whatPrefix.empty()) {
      Check(r.what == want.code, label + ": what() == code (got " + r.what + ")");
    } else {
      Check(r.what.rfind(want.whatPrefix, 0) == 0, label + ": what() starts with " + want.whatPrefix + " (got " + r.what + ")");
    }
  }
  Check(h.client->IsAuthenticated() == !want.fatal,
        label + ": IsAuthenticated " + (want.fatal ? "false" : "true"));
  if (want.fatal) {
    Check(h.client->GetSessionKind() == authforge::SessionKind::None, label + ": session kind cleared");
  }
  Check(h.server->Requests() == want.requests,
        label + ": " + std::to_string(want.requests) + " request(s) (got " + std::to_string(h.server->Requests()) + ")");
  Check(h.Sleeps() == want.sleeps, label + ": sleeps " + Join(want.sleeps) + " (got " + Join(h.Sleeps()) + ")");
}

template <typename Fn>
bool FinishesWithin(Fn fn, std::chrono::seconds timeout, const std::string &label) {
  auto future = std::async(std::launch::async, std::move(fn));
  if (future.wait_for(timeout) != std::future_status::ready) {
    std::cerr << "FAIL: " << label << ": did not finish within " << timeout.count() << "s (deadlock?)\n";
    std::_Exit(1);
  }
  future.get();
  return true;
}

template <typename Pred>
bool WaitUntil(Pred pred, std::chrono::milliseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    if (pred()) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return pred();
}

} // namespace

int main(int argc, char **argv) {
  if (argc < 2) {
    std::cerr << "usage: heartbeat_test <test_vectors.json>\n";
    return 2;
  }
  const std::string json = ReadFile(argv[1]);
  const authforge::JsonNode root = authforge::JsonReader(json).ParseDocument();
  const Vector heartbeatSuccess = FindVector(root, "heartbeat_success");
  const Vector validateSuccess = FindVector(root, "validate_success");
  const Vector tampered = FindVector(root, "tampered_payload");

  // 1. Classification helper.
  {
    for (const char *code : {"revoked", "expired", "hwid_mismatch", "blocked", "session_expired",
                             "malformed_request", "app_disabled", "invalid_app", "signature_mismatch"}) {
      Check(!authforge::IsTransientErrorCode(code), std::string(code) + " is definitive");
      Check(AuthForgeError(code).isFatal(), std::string(code) + " AuthForgeError isFatal");
    }
    for (const char *code : {"http_error_403", "http_error_500", "invalid_json_response", "response_not_json_object",
                             "network_error", "timeout", "rate_limited", "system_error", "no_credits",
                             "demo_quota_exceeded", "app_burn_cap_reached", "bad_request", "invalid_key",
                             "replay_detected", "revoke_requires_session", "unexpected_response", "unknown_error",
                             "missing_session_token", "nonce_mismatch", "brand_new_code"}) {
      Check(authforge::IsTransientErrorCode(code), std::string(code) + " is transient");
      Check(AuthForgeError(code).isTransient(), std::string(code) + " AuthForgeError isTransient");
    }
    const AuthForgeError withMessage("network_error", "url_error: boom");
    Check(withMessage.code() == "network_error" && std::string(withMessage.what()) == "url_error: boom",
          "AuthForgeError keeps code and message");
  }

  // 2. Definitive codes, as non-2xx and as a 200 failed body.
  const std::vector<std::pair<std::string, long>> definitive = {
      {"revoked", 410}, {"expired", 410}, {"hwid_mismatch", 403}, {"blocked", 403},
      {"app_disabled", 403}, {"session_expired", 401}, {"invalid_app", 401}, {"malformed_request", 400},
  };
  for (const auto &entry : definitive) {
    ExpectTick(entry.first + " (" + std::to_string(entry.second) + ")", {Failed(entry.second, entry.first)},
               {entry.first, true, 1, {}, ""});
    ExpectTick(entry.first + " (200)", {Failed(200, entry.first)}, {entry.first, true, 1, {}, ""});
  }

  // 3. A tampered success response is definitive.
  ExpectTick("signature_mismatch", {Signed({heartbeatSuccess.payload, tampered.signature})},
             {"signature_mismatch", true, 1, {}, ""});

  // 4. Transient server codes keep the session.
  ExpectTick("rate_limited", {Failed(429, "rate_limited")}, {"rate_limited", false, 3, {2, 5}, ""});
  ExpectTick("rate_limited (200)", {Failed(200, "rate_limited")}, {"rate_limited", false, 3, {2, 5}, ""});
  ExpectTick("system_error", {Failed(500, "system_error")}, {"system_error", false, 1, {}, ""});
  ExpectTick("server_error", {Failed(500, "server_error")}, {"server_error", false, 1, {}, ""});
  for (const char *code : {"no_credits", "demo_quota_exceeded", "app_burn_cap_reached"}) {
    ExpectTick(std::string(code) + " (429)", {Failed(429, code)}, {code, false, 1, {}, ""});
  }
  ExpectTick("bad_request", {Failed(400, "bad_request")}, {"bad_request", false, 1, {}, ""});
  ExpectTick("invalid_key", {Failed(401, "invalid_key")}, {"invalid_key", false, 1, {}, ""});
  ExpectTick("unknown code passthrough", {Failed(403, "Brand_New_Code")}, {"brand_new_code", false, 1, {}, ""});
  ExpectTick("rate limit then revoked", {Failed(429, "rate_limited"), Failed(403, "revoked")},
             {"revoked", true, 2, {2}, ""});

  // 5. Non-JSON and non-object bodies.
  ExpectTick("non-JSON 403", {Http(403, "<html>Forbidden</html>")}, {"http_error_403", false, 1, {}, ""});
  ExpectTick("non-JSON 500", {Http(500, "Internal Server Error")}, {"http_error_500", false, 1, {}, ""});
  ExpectTick("non-JSON 502", {Http(502, "<html>Bad Gateway</html>")}, {"http_error_502", false, 1, {}, ""});
  ExpectTick("empty 503", {Http(503, "")}, {"http_error_503", false, 1, {}, ""});
  ExpectTick("empty 200", {Http(200, "")}, {"invalid_json_response", false, 1, {}, ""});
  ExpectTick("non-object JSON 200", {Http(200, "[\"revoked\"]")}, {"response_not_json_object", false, 1, {}, ""});
  ExpectTick("non-object JSON 403", {Http(403, "[\"revoked\"]")}, {"http_error_403", false, 1, {}, ""});

  // 6. Malformed failure bodies are unexpected_response, never a verdict.
  for (const long status : {200L, 403L}) {
    const std::string suffix = " (" + std::to_string(status) + ")";
    ExpectTick("error without status" + suffix, {Http(status, "{\"error\":\"revoked\"}")},
               {"unexpected_response", false, 1, {}, "unexpected_response"});
    ExpectTick("status is the code" + suffix, {Http(status, "{\"status\":\"revoked\"}")},
               {"unexpected_response", false, 1, {}, "unexpected_response"});
    ExpectTick("failed without error" + suffix, {Http(status, "{\"status\":\"failed\"}")},
               {"unexpected_response", false, 1, {}, "unexpected_response"});
  }
  ExpectTick("429 without error code is retried", {Http(429, "{\"status\":\"failed\"}")},
             {"unexpected_response", false, 3, {2, 5}, "unexpected_response"});

  // 7. Transport failures: one retry, one callback.
  ExpectTick("network error", {TransportDown(false)}, {"network_error", false, 2, {2}, "url_error: "});
  ExpectTick("timeout", {TransportDown(true)}, {"timeout", false, 2, {2}, "url_error: "});

  // 8. TTL promotion: a transient failure past the signed TTL is session_expired.
  {
    Harness h;
    h.Script({Http(502, "Bad Gateway")});
    h.Seed(Now() - 5);
    Check(!Access::Tick(*h.client), "ttl promotion: tick returns false");
    const auto records = h.recorder->Records();
    Check(records.size() == 1 && records[0].code == "session_expired" && !records[0].transient,
          "ttl promotion: session_expired");
    Check(!h.client->IsAuthenticated(), "ttl promotion: logged out");
  }

  // 9. Success after a transient failure refreshes the session.
  {
    Harness h;
    h.Script({Http(503, "Service Unavailable"), Signed(heartbeatSuccess)});
    h.Seed();
    Check(Access::Tick(*h.client), "transient then success: first tick keeps running");
    Check(h.client->IsAuthenticated(), "transient then success: still authenticated");
    Check(Access::Tick(*h.client), "transient then success: second tick ok");
    Check(h.recorder->Records().size() == 1, "transient then success: one callback");
    Check(Access::SessionToken(*h.client) == "session.heartbeat.token", "heartbeat_success refreshes session token");
    const auto expiresIn = Access::SessionExpiresIn(*h.client);
    Check(expiresIn.has_value() && *expiresIn == 1900000300, "heartbeat_success refreshes expiresIn");
  }

  // 10. Grace period (no online check-ins).
  {
    Harness h(authforge::OnlineHeartbeat::Off);
    Access::SeedSession(*h.client, "session.validate.token", Now() + 3600, validateSuccess.payload,
                        validateSuccess.signature);
    Check(Access::Tick(*h.client), "grace period: valid session keeps running");
    Check(h.recorder->Records().empty(), "grace period: no callback while valid");
    Check(h.server->Requests() == 0, "grace period: no network");

    Access::SeedSession(*h.client, "session.validate.token", Now() - 1, validateSuccess.payload,
                        validateSuccess.signature);
    Check(!Access::Tick(*h.client), "grace expiry: tick returns false");
    const auto records = h.recorder->Records();
    Check(records.size() == 1 && records[0].code == "session_expired" && records[0].what == "session_expired" &&
              !records[0].transient,
          "grace expiry: session_expired is definitive");
    Check(!h.client->IsAuthenticated(), "grace expiry: logged out");
  }
  {
    Harness h(authforge::OnlineHeartbeat::Off);
    Access::SeedSession(*h.client, "session.validate.token", Now() + 3600, validateSuccess.payload,
                        heartbeatSuccess.signature);
    Check(!Access::Tick(*h.client), "grace period tampered signature: tick returns false");
    const auto records = h.recorder->Records();
    Check(records.size() == 1 && records[0].code == "signature_mismatch", "grace period: signature_mismatch");
  }

  // 11. Login and ValidateLicense get clean codes for non-2xx JSON bodies.
  {
    Harness h;
    h.Script({Failed(401, "invalid_key")});
    Check(!h.client->Login("KEY-0000"), "login invalid_key: returns false");
    const auto records = h.recorder->Records();
    Check(records.size() == 1 && records[0].reason == "login_failed", "login invalid_key: login_failed");
    Check(!records.empty() && records[0].what == "invalid_key" && records[0].code == "invalid_key",
          "login invalid_key: what() == invalid_key");
    Check(h.server->Requests() == 1, "login invalid_key: not retried");
    Check(!h.client->IsAuthenticated(), "login invalid_key: not authenticated");

    h.Script({Failed(403, "revoked")});
    Check(h.client->ValidateLicense("KEY-0000").errorCode == "revoked", "ValidateLicense 403 revoked -> revoked");
    h.Script({Http(500, "<html>oops</html>")});
    Check(h.client->ValidateLicense("KEY-0000").errorCode == "http_error_500", "ValidateLicense non-JSON 500");
  }
  {
    Harness h;
    Access::SetNonce(*h.client, "nonce-validate-001");
    h.Script({Signed(validateSuccess)});
    Check(h.client->Login("KEY-0000"), "login success via fake transport");
    Check(h.client->IsAuthenticated(), "login success: authenticated");
    Check(h.recorder->Records().empty(), "login success: no callback");
  }

  // 12. The callback may call Logout() and IsAuthenticated() without deadlock.
  for (const bool fatal : {false, true}) {
    const std::string label = fatal ? "fatal callback" : "transient callback";
    Harness h;
    h.Script({fatal ? Failed(403, "revoked") : Http(500, "oops")});
    h.Seed();
    auto sawAuthenticated = std::make_shared<std::optional<bool>>();
    AuthForgeClient *client = h.client.get();
    h.recorder->hook = [client, sawAuthenticated]() {
      *sawAuthenticated = client->IsAuthenticated();
      client->Logout();
      (void)client->IsAuthenticated();
    };
    bool tickResult = true;
    FinishesWithin([&]() { tickResult = Access::Tick(*h.client); }, std::chrono::seconds(10), label);
    Check(sawAuthenticated->has_value(), label + ": hook ran");
    Check(sawAuthenticated->value_or(!fatal) == !fatal,
          label + ": IsAuthenticated inside callback is " + (fatal ? "false" : "true"));
    Check(!h.client->IsAuthenticated(), label + ": logged out after callback Logout");
    Check(tickResult == !fatal, label + ": tick result");
  }

  // 13. Real heartbeat thread: the callback destroys the client.
  for (const bool fatal : {false, true}) {
    const std::string label = fatal ? "destroy in fatal callback" : "destroy in transient callback";
    auto server = std::make_shared<FakeServer>();
    auto recorder = std::make_shared<Recorder>();
    server->script = {fatal ? Failed(403, "revoked") : Http(502, "Bad Gateway")};
    auto holder = std::make_shared<std::atomic<AuthForgeClient *>>(
        Harness::Create(authforge::OnlineHeartbeat::On, server, recorder));
    auto done = std::make_shared<std::promise<void>>();
    auto doneFuture = done->get_future();
    recorder->hook = [holder, done]() {
      AuthForgeClient *client = holder->exchange(nullptr);
      if (client != nullptr) {
        delete client;
        done->set_value();
      }
    };
    AuthForgeClient *client = holder->load();
    Access::SetInterval(*client, 1);
    Access::SeedSession(*client, "session.seed.token", Now() + 3600);
    Access::Start(*client);
    const bool finished = doneFuture.wait_for(std::chrono::seconds(15)) == std::future_status::ready;
    Check(finished, label + ": callback ran and deleted the client");
    if (!finished) {
      std::cerr << "FAIL: " << label << ": heartbeat thread never reported\n";
      std::_Exit(1);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    Check(recorder->Records().size() == 1, label + ": exactly one callback");
    Check(server->Requests() == 1, label + ": no further check-ins after destruction");
  }

  // 13b. Real heartbeat thread: Login() from the fatal callback restarts
  // check-ins on a new thread (the old one detaches itself).
  {
    const std::string label = "login from fatal callback";
    Harness h;
    Access::SetNonce(*h.client, "nonce-validate-001");
    Access::SetInterval(*h.client, 1);
    h.Script({Failed(403, "revoked"), Signed(validateSuccess)});
    auto loggedIn = std::make_shared<std::promise<bool>>();
    auto loggedInFuture = loggedIn->get_future();
    AuthForgeClient *client = h.client.get();
    h.recorder->hook = [client, loggedIn]() {
      const bool ok = client->Login("KEY-0000");
      loggedIn->set_value(ok);
    };
    h.Seed();
    Access::Start(*h.client);
    const bool finished = loggedInFuture.wait_for(std::chrono::seconds(15)) == std::future_status::ready;
    Check(finished && loggedInFuture.get(), label + ": Login inside callback succeeds");
    if (!finished) {
      std::cerr << "FAIL: " << label << ": callback never ran\n";
      std::_Exit(1);
    }
    Check(WaitUntil([&]() { return h.server->Requests() >= 3; }, std::chrono::milliseconds(5000)),
          label + ": new heartbeat thread checks in");
    Check(h.client->IsAuthenticated(), label + ": authenticated after re-login");
    Check(h.recorder->Records().size() == 1, label + ": one callback");
    FinishesWithin([&]() { h.client.reset(); }, std::chrono::seconds(5), label + ": destructor");
  }

  // 14. Logout during an in-flight heartbeat; the late response can't
  // resurrect the session (success) or report a stale failure (revoked).
  for (const bool lateSuccess : {true, false}) {
    const std::string label = lateSuccess ? "logout in flight (late success)" : "logout in flight (late revoked)";
    Harness h;
    h.Script({lateSuccess ? Signed(heartbeatSuccess) : Failed(403, "revoked")});
    auto entered = std::make_shared<std::promise<void>>();
    auto enteredFuture = entered->get_future();
    auto release = std::make_shared<std::promise<void>>();
    std::shared_future<void> releaseFuture = release->get_future().share();
    auto returned = std::make_shared<std::atomic<bool>>(false);
    h.server->onRequest = [entered, releaseFuture, returned]() {
      entered->set_value();
      releaseFuture.wait();
      returned->store(true);
    };
    Access::SetInterval(*h.client, 1);
    h.Seed();
    Access::Start(*h.client);
    const bool inFlight = enteredFuture.wait_for(std::chrono::seconds(15)) == std::future_status::ready;
    Check(inFlight, label + ": heartbeat request started");
    if (!inFlight) {
      std::cerr << "FAIL: " << label << ": heartbeat never started\n";
      std::_Exit(1);
    }
    FinishesWithin([&]() { h.client->Logout(); }, std::chrono::seconds(5), label + ": Logout");
    Check(!h.client->IsAuthenticated(), label + ": logged out while in flight");
    release->set_value();
    Check(WaitUntil([&]() { return returned->load(); }, std::chrono::milliseconds(5000)), label + ": response returned");
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    Check(!h.client->IsAuthenticated(), label + ": still logged out after late response");
    Check(Access::SessionToken(*h.client).empty(), label + ": session token stays cleared");
    Check(!h.client->GetSessionDataJson().has_value(), label + ": session data stays cleared");
    Check(h.recorder->Records().empty(), label + ": no callback for the stale response");

    // Re-login restarts the thread (joining the old one) and check-ins
    // resume for the new session.
    {
      std::lock_guard<std::mutex> guard(h.server->mutex);
      h.server->onRequest = nullptr;
    }
    h.Script({Http(500, "oops")});
    h.Seed();
    FinishesWithin([&]() { Access::Start(*h.client); }, std::chrono::seconds(5), label + ": restart");
    Check(WaitUntil([&]() { return !h.recorder->Records().empty(); }, std::chrono::milliseconds(5000)),
          label + ": restarted thread checks in");
    Check(h.client->IsAuthenticated(), label + ": restarted session survives transient failure");
  }

  // 15. Destroying a client with a running heartbeat thread joins promptly.
  {
    Harness h;
    Access::SetInterval(*h.client, 900);
    h.Seed();
    Access::Start(*h.client);
    FinishesWithin([&]() { h.client.reset(); }, std::chrono::seconds(5), "destructor interrupts the interval wait");
  }

  if (g_failures != 0) {
    std::cerr << g_failures << " check(s) failed\n";
    return 1;
  }
  std::cout << "heartbeat contract: all checks passed\n";
  return 0;
}
