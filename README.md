# ESP32 Offensive Security Toolkit (ESP32-OST)

A complete, standalone 802.11 offensive security toolkit designed specifically for the ESP32. ESP32-OST hosts its own lightweight web dashboard directly from the device, meaning no external home network or router is required to operate it.

> **Disclaimer:** This project is intended for educational purposes and authorized auditing only. Do not use this tool on networks you do not own or have explicit permission to test.

## Features

- **Network Scanner:** Discover nearby Access Points, viewing their BSSID, channel, RSSI, and security risk (Open, WEP, WPA, WPA2).
- **Prober (Client Sniffer):** Locks onto a specific Access Point and sniffs raw Wi-Fi packets to detect hidden client devices connected to it.
- **Deauther:** Injects raw `0xC0` Deauthentication frames to targeted clients or broadcasts them to all clients on an AP, forcefully disconnecting them.
- **Beacon Spammer:** Floods the 2.4GHz spectrum with up to dozens of fake Access Points (SSIDs) simultaneously.
- **Ghost Mode (Probe Reflection):** Sniffs the air for floating "Probe Requests" (devices looking for their saved Wi-Fi networks) and instantly creates fake APs using those exact names.
- **Evil Twin (Captive Portal):** Tears down a legitimate network, broadcasts a perfect clone (same SSID, MAC, and Channel), and runs a rogue DNS server to trap clients in a fake login portal to harvest credentials.

## Installation & Flashing

This project is built using the PlatformIO ecosystem on VS Code. To flash it onto your own ESP32, follow these steps:

### Prerequisites
1. **Hardware:** An ESP32 development board (e.g., ESP32 DOIT DevKit V1) and a micro-USB/USB-C data cable.
2. **Software:** [Visual Studio Code](https://code.visualstudio.com/) with the [PlatformIO IDE extension](https://platformio.org/install/ide?install=vscode) installed.

### Flashing the Firmware and UI

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/abhishekmallav/ESP32-OST.git
   ```
2. **Open the Project:** Open the cloned `ESP32-OST` folder inside VS Code.
3. **Connect the ESP32:** Plug your ESP32 into your computer via USB.
4. **Compile and Flash the Code:** Click the PlatformIO **Upload** button (the right-pointing arrow in the bottom blue toolbar) or run:
   ```bash
   pio run -t upload
   ```
5. **Upload the Web UI (SPIFFS):** The HTML/CSS/JS frontend is stored in the ESP32's flash memory. You MUST upload it for the dashboard to work. Click the PlatformIO icon on the left sidebar, navigate to `Project Tasks -> env:esp32doit-devkit-v1 -> Platform -> Upload Filesystem Image`, or run:
   ```bash
   pio run -t uploadfs
   ```

## Usage

1. **Power the ESP32:** Plug the flashed ESP32 into any USB power source (computer, wall block, or portable power bank).
2. **Connect to the Network:** On your phone or laptop, scan for Wi-Fi networks and connect to the ESP32's standalone network:
   - **SSID:** `ESP32-OST`
   - **Password:** `Password123`
3. **Access the Dashboard:** Open a web browser and navigate to the default gateway:
   - **URL:** `http://192.168.4.1`

*(Note: During certain attacks like Probing or Deauth, the `ESP32-OST` network will temporarily drop out as the ESP32 shifts its radio channel to execute the attack. The network will automatically return when the 10-30 second attack timer concludes).*

## License

This project is licensed under the MIT License. See the [LICENSE.txt](LICENSE.txt) file for details.