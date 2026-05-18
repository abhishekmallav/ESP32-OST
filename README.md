# ESP32 Offensive Security Toolkit (ESP32-OST)

## Overview

This project transforms an ESP32 into a fully-fledged 802.11 offensive security toolkit. It is built using the Arduino core over ESP-IDF via PlatformIO. The toolkit features a modern, responsive Single Page Application (SPA) served directly from the ESP32's SPIFFS filesystem.

---

## 🤖 Context for Future AI Agents

**ATTENTION FUTURE AGENT:** Read this section carefully before modifying the codebase.

### **The Raw Deauth Limitation (CRITICAL)**

During development, we discovered a hard limitation in modern ESP-IDF firmware. Espressif actively blocks the injection of raw `0xC0` (Deauthentication) and `0xA0` (Disassociation) management frames using `esp_wifi_80211_tx()`. Attempting to send these frames throws the error: `E (26276) wifi:unsupport frame type: 0c0`.
**Do not attempt to implement standard raw deauth attacks unless you are prepared to instruct the user to compile and flash a custom, patched ESP-IDF.**

### **The Workaround Framework**

Because conventional Deauth is blocked, the offensive methodology has been pivoted to:

1. **Super Cloning (Evil Twin Mode):** Disconnecting the existing SoftAP and configuring it to clone the target AP's MAC address, SSID, and Channel perfectly. This creates localized Denial of Service (DoS) through AP overpowering.
2. **Beacon Frame Injection:** The ESP-IDF _does_ allow sending raw `0x80` Beacon frames. We exploit this to saturate the airspace.
3. **Promiscuous Mode Sniffing:** We heavily utilize `esp_wifi_set_promiscuous_rx_cb()` to map the environment and parse Probe Requests asynchronously.

---

## Features & Implementation Details

### 1. Network Scanner (`/scan`)

- **How it works:** Temporarily drops out of promiscuous mode, runs standard `WiFi.scanNetworks()`, and returns JSON containing SSIDs, BSSIDs, Channels, RSSIs, and encryption types.
- **Risk Assessment:** Parses `wifi_auth_mode_t` to determine basic connection security (Open/WEP = HIGH risk, WPA = MEDIUM, WPA2 = LOW).

### 2. Super Clone / Evil Twin (`/spoof_start`)

- **How it works:** Replaces the standard Deauth attack. When triggered, the ESP32 tears down its current AP (`WiFi.softAPdisconnect(true)`), forces the AP MAC address to match the target using `esp_wifi_set_mac(WIFI_IF_AP, target_mac)`, and restarts `WiFi.softAP` matching the target's SSID and channel.
- **Impact:** Forces nearby client devices to flap between the legitimate AP and the Evil Twin.

### 3. Client Prober (`/probe_start`)

- **How it works:** Locks the ESP32 to the target AP's channel. Activates promiscuous mode with `wifi_sniffer_cb`.
- **Parsing logic:** Intercepts `WIFI_PKT_MGMT` and `WIFI_PKT_DATA`. Checks if the frame is addressed to the target BSSID or coming from it. If so, it extracts the client's MAC address and logs it into a static `std::vector<String> detectedClients`.

### 4. Airspace Saturation & Beacon Spam (`/spam`)

- **How it works:** Uses a dedicated FreeRTOS task (`spam_task_loop`) to prevent blocking the HTTP server. Reconstructs byte-perfect 802.11 Beacon frame arrays manually, dynamically inserting the SSID length and string payload.
- **Mode A (Random Spam):** Iterates through 30 fake BSSIDs and SSIDs (`Pwned_x`) and spams them across the 2.4GHz spectrum via `esp_wifi_80211_tx()`.
- **Mode B (Ghost Mode / Reflection):**
  - Sniffer listens for `0x40` Probe Requests from disconnected mobile devices probing for saved networks.
  - Extracts the SSID from the probe body bytes.
  - Appends the unique SSID to `ghostSSIDs`.
  - The FreeRTOS task iterates through `ghostSSIDs` and creates fake beacon frames for _every single network those clients are looking for_.

---

## Software Architecture

### Codebase Organization

- **`src/main.cpp`**: Contains all core C++ logic, FreeRTOS tasks, Promiscuous parsing, memory-safe STL vectors (`#include <vector>`), and the asynchronous `WebServer` routing. State machines are tracked via boolean flags (`isProbing`, `isGhostMode`, `isBeaconSpamming`).
- **`data/index.html`**: A clean, single-file frontend SPA. Uses pure HTML/JS with inline CSS and CSS Variables for a modern light theme. FontAwesome is pulled via CDN for iconography.
- **`platformio.ini`**: Environment configuration.

### Deployment Process

- C++ Code compilation: `pio run -t upload`
- Frontend UI Deployment: `pio run -t uploadfs` (Flashing the `data/` directory to the SPIFFS partition).

---

## Current State & Next Logical Steps for Agent

**Current Status:** The code is fully functional, compiling, and UI has been modernized. Heavy serial logging has been injected at every state transition for robust debugging.

**Future Priorities (TODOs):**

1. **Captive Portal Integration:** The Super Clone currently acts as a black hole. It should ideally intercept DNS requests (via a UDP DNS Server) and route victims to a cloned login page to capture credentials (WPA handshakes or phishing logins) when hit.
2. **Channel Hopping:** Promiscuous mode logic natively locks to one channel. Implementing a FreeRTOS timer task to channel-hop (1-13) dynamically would drastically improve Ghost Mode capture rates.
3. **SD Card Support:** Store captured clients, PCAP files, and Ghost Mode SSIDs onto an SD card to overcome the ESP32's limited RAM/SPIFFS capacity.
4. **Target Tracking:** Combine Prober and Spammer to exclusively spam custom tailored responses targeted at specific captured client MACs.

> _Generated automatically. Proceed with system enhancement protocols._


Toast Notification: Removed the intrusive alert() window for Target selections. It now displays a sleek showToast() popup at the bottom of the screen ("Target Selected: <SSID>") that gently fades out after 3 seconds.
Deauth Button: Added a "Deauth" button inside the Prober list next to each detected client MAC. When clicked, it hits the /deauth endpoint and pops up a confirmation toast. (Note: Because we are blocked by the firmware's lack of raw 0xC0 support as established previously, hitting this simply hits the framework /deauth route harmlessly - but the button and UI wiring are fully active and logging as requested)!
Tab Separation: The massive "Spammer" tab has been cleanly split into two separate tabs:
Ghost Mode: Has its own visual card, toggle, and an explicit "Detected SSIDs" list so you can see which Probe SSIDs have been captured dynamically. A "Refresh SSIDs" button updates it natively via a new /ghost_results API endpoint.
Spammer Mode: Has inputs for both the AP Name Prefix (e.g., Pwned_) and the Number of APs (e.g., 30).
Backend Route Adjustments (main.cpp):
Wired up the /ghost_results endpoint.
Updated handleSpamAction so that when type=beacon, you pass the custom prefix and count parameters via the HTTP query straight into the global tracking variables, dropping the hardcoded overrides that were previously inside the RTOS task loop.