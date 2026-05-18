<div align="center">
  <img src="https://img.shields.io/badge/ESP32-Offensive%20Security-c4f03a?style=for-the-badge&logo=espressif&logoColor=black" alt="ESP32-OST" />
  <h1>ESP32 Offensive Security Toolkit (ESP32-OST)</h1>
  <p><strong>Advanced 802.11 Auditing & Penetration Testing Framework</strong></p>
</div>

<br>

> ⚠️ **STRICTLY EDUCATIONAL DISCLAIMER**
> 
> This firmware is provided for authorized auditing, educational research, and security evaluation purposes only. **You are solely responsible for your actions.** The author (Abhishek Mallav) is not responsible for any misuse, data loss, network damage, or illegal acts caused by the deployment of this software. By downloading or flashing this firmware, you agree to use it responsibly and exclusively on networks you own or have explicit permission to test.

---

## 📖 Overview

Transform your standard ESP32 microcontroller into a modernized, standalone penetration testing platform. ESP32-OST is a high-performance toolkit that bypasses standard firmware sanity checks to perform raw IEEE 802.11 frame injection, complete with a beautifully designed, embedded Single Page Application (SPA) dashboard.

---

## ⚡ Technical Attack Vectors

ESP32-OST demonstrates several advanced wireless attack vectors using low-level radio manipulation:

### 1. Airspace Scanner
Discover nearby access points, evaluate encryption strength, and map 2.4GHz topology.
* **Technical Details:** Temporarily drops out of promiscuous mode to execute `WiFi.scanNetworks()`. Parses `wifi_auth_mode_t` to classify cryptographic risks.

### 2. Promiscuous Prober
Silently extract BSSIDs of hidden client devices connected to a target Access Point without authenticating.
* **Technical Details:** Tunes the radio to a target channel and hooks `esp_wifi_set_promiscuous_rx_cb()`. Intercepts and parses raw `WIFI_PKT_MGMT` frames in real-time.

### 3. Deauth Injector
Forcefully disconnect targeted devices or blanket an entire network with localized denial of service.
* **Technical Details:** Overrides Espressif firmware sanity checks (`ieee80211_raw_frame_sanity_check`) to construct and rapidly inject raw `0xC0` IEEE 802.11 Deauthentication management frames.

### 4. Beacon Flooder
Saturate the 2.4GHz spectrum with dozens of fake Access Points simultaneously.
* **Technical Details:** Utilizes a dedicated FreeRTOS background task to construct byte-perfect `0x80` Beacon frames, dynamically modifying SSID payloads in memory to broadcast massive spoofed networks.

### 5. AP Spoofing (Ghost Mode)
Listen for devices searching for saved Wi-Fi networks, and instantly reflect fake APs using those exact names.
* **Technical Details:** Sniffs `0x40` Probe Requests. Extracts the raw SSID byte payload from the probe and spawns responsive beacons to deceive the client OS into connecting.

### 6. Captive Portal (Evil Twin)
Perfectly clone a target network and route victims to a credential-harvesting local web server.
* **Technical Details:** Tears down the legitimate SoftAP, clones the target MAC address via `esp_wifi_set_mac`, and initiates a `DNSServer` to hijack UDP Port 53, redirecting all DNS queries to a phishing landing page.

---

## 🛠️ Prerequisites

Because this toolkit heavily utilizes the ESP32's single 2.4GHz radio for sniffing and injection, it requires an external access point to host the dashboard connection. 

Before powering on the flashed ESP32, you **must** configure your Home Router or Mobile Hotspot with the following credentials on the **2.4GHz band**:

* **Network Name (SSID):** `ESP32-OST`
* **Password:** `Password123`

*(The ESP32 will automatically connect to this network on boot, allowing you to access the dashboard by navigating to the ESP32's assigned local IP address).*

---

## 🚀 Installation & Setup

You can install ESP32-OST using one of three methods, ranging from a 1-click web installer to full source-code compilation.

### Method 1: Web Serial Installer (Recommended / Easiest)
You can flash your ESP32 directly from your browser (Chrome or Edge required) without downloading any tools!
1. Connect your ESP32 to your PC via a data-capable USB cable.
2. Visit the Web Installer: **[https://abhishekmallav.github.io/ESP32-OST](https://abhishekmallav.github.io/ESP32-OST)**
3. Click **"Flash Firmware to ESP32"**, select your COM port, and wait for the flash to complete.

### Method 2: Manual Binaries Flash (esptool)
If you prefer the command line, you can flash the pre-compiled binaries from the Releases tab.
1. Download the latest `.bin` files (`bootloader.bin`, `partitions.bin`, `firmware.bin`, `spiffs.bin`) from the `/dist` folder.
2. Install [esptool.py](https://github.com/espressif/esptool).
3. Flash the partitions to their exact offsets:
```bash
esptool.py --chip esp32 --port COM_PORT --baud 115200 write_flash -z 0x1000 bootloader.bin 0x8000 partitions.bin 0x10000 firmware.bin 0x290000 spiffs.bin
```

### Method 3: PlatformIO Compilation (For Developers)
For complete control and customization, build the firmware from source using VS Code.
1. Install [Visual Studio Code](https://code.visualstudio.com/) and the [PlatformIO Extension](https://platformio.org/install/ide?install=vscode).
2. Clone this repository: 
```bash
git clone https://github.com/abhishekmallav/ESP32-OST.git
```
3. Open the folder in VS Code.
4. Run `PlatformIO: Build` to compile the C++ firmware.
5. Run `PlatformIO: Build Filesystem Image` to pack the HTML/CSS from the `/data` folder into SPIFFS.
6. Run `PlatformIO: Upload` and `PlatformIO: Upload Filesystem Image` to flash your ESP32.

---

## 🤝 Contribution & Feature Requests

Contributions, bug reports, and feature requests are highly welcome! 
* Have an idea for a new 802.11 attack vector?
* Want to improve the UI/UX?
* Found a bug in the state machine?

Feel free to open an [Issue](https://github.com/abhishekmallav/ESP32-OST/issues) or submit a Pull Request! Please ensure your code follows the existing architecture (non-blocking FreeRTOS tasks) and includes proper documentation.

---

## 🔗 Connect With Me

Built with ❤️ by **Abhishek Mallav** — *Curious by nature, Engineer by craft.*

* 🌐 **Portfolio:** [abhishekmallav.github.io/portfolio](https://abhishekmallav.github.io/portfolio/)
* 💼 **LinkedIn:** [linkedin.com/in/abhishekmallav](https://www.linkedin.com/in/abhishekmallav/)
* 🕮 **GitHub:** [github.com/abhishekmallav](https://github.com/abhishekmallav)
* 🐦 **X (Twitter):** [x.com/abhishekmallav](https://x.com/abhishekmallav)
* 📸 **Instagram:** [@abhishekmallav](https://www.instagram.com/abhishekmallav)
