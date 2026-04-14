// Probe Request Sniffer for Heltec WiFi LoRa 32 V3 (ESP32-S3)
// - WiFi promiscuous mode, 2.4 GHz channel hopper
// - Filters for 802.11 probe requests
// - Parses MAC, SSID, RSSI, channel, sequence number, and capability IEs
// - Stable device fingerprint (hash of capability IEs, excluding SSID) so
//   MAC-randomized probes from the same device collapse into one "device"
// - Live OLED stats: probes, unique MACs, unique fingerprints, top SSID
// - Streams each probe as one JSON line over USB-CDC so a phone/laptop
//   can tee the output to a file for later analysis.
//
// Tools menu:
//   Board: "WiFi LoRa 32(V3)"
//   USB CDC On Boot: Enabled
//   Upload Speed: 921600
//
// Requires library: "Heltec ESP32 Dev-boards" (installed via Boards Manager
// above) which provides the Heltec/SSD1306 OLED driver used below.

#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "HT_SSD1306Wire.h"

// ---------- OLED ----------
// Heltec V3 pins: SDA=17, SCL=18, RST=21
static SSD1306Wire display(0x3c, 500000, SDA_OLED, SCL_OLED,
                           GEOMETRY_128_64, RST_OLED);

// ---------- Config ----------
static const uint8_t CHANNELS[] = {1, 6, 11, 2, 7, 3, 8, 4, 9, 5, 10, 12, 13};
static const uint8_t N_CHANNELS = sizeof(CHANNELS) / sizeof(CHANNELS[0]);
static const uint32_t HOP_INTERVAL_MS = 350;
static const uint32_t DISPLAY_INTERVAL_MS = 1000;
static const uint16_t MAX_UNIQUE_TRACKED = 512;

// ---------- Stats ----------
static volatile uint32_t g_probe_count = 0;
static volatile uint32_t g_unique_macs = 0;
static volatile uint32_t g_unique_fps = 0;
static char g_last_ssid[33] = {0};
static uint8_t g_current_channel = 1;

// Tiny open-addressing sets (fixed-size, no heap churn) to count unique
// MACs and fingerprints without blowing RAM.
struct HashSet {
    uint64_t slots[MAX_UNIQUE_TRACKED];
    uint16_t count;
};
static HashSet g_macs  = {{0}, 0};
static HashSet g_fps   = {{0}, 0};

static bool set_insert(HashSet* s, uint64_t key) {
    if (key == 0) key = 1;  // 0 reserved as empty
    uint16_t h = (uint16_t)((key ^ (key >> 32)) % MAX_UNIQUE_TRACKED);
    for (uint16_t i = 0; i < MAX_UNIQUE_TRACKED; i++) {
        uint16_t idx = (h + i) % MAX_UNIQUE_TRACKED;
        if (s->slots[idx] == 0) {
            if (s->count >= MAX_UNIQUE_TRACKED - 1) return false;
            s->slots[idx] = key;
            s->count++;
            return true;
        }
        if (s->slots[idx] == key) return false;
    }
    return false;
}

// FNV-1a 64-bit for the fingerprint hash.
static inline uint64_t fnv1a_init() { return 0xcbf29ce484222325ULL; }
static inline uint64_t fnv1a_step(uint64_t h, uint8_t b) {
    return (h ^ b) * 0x100000001b3ULL;
}

// Capability IEs we fingerprint over. Excludes SSID (0) and vendor-random
// stuff. Same set as the Python side so fingerprints match across tools.
static bool is_fp_ie(uint8_t id) {
    return id == 1 || id == 45 || id == 50 || id == 127 || id == 191 || id == 221;
}

static void hex_append(char* out, const uint8_t* data, size_t len) {
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        *out++ = H[data[i] >> 4];
        *out++ = H[data[i] & 0x0f];
    }
    *out = 0;
}

// ---------- Sniffer callback ----------
// 802.11 frame type 0 subtype 4 = probe request.
static void sniffer_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;

    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    const uint8_t* payload = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    if (len < 24) return;

    uint8_t fc0 = payload[0];
    uint8_t ftype = (fc0 >> 2) & 0x3;
    uint8_t fsubtype = (fc0 >> 4) & 0xf;
    if (ftype != 0 || fsubtype != 4) return;  // not a probe request

    const uint8_t* src = payload + 10;  // addr2
    uint64_t mac_key = 0;
    for (int i = 0; i < 6; i++) mac_key = (mac_key << 8) | src[i];

    // Walk IEs starting at byte 24.
    const uint8_t* ies = payload + 24;
    int ies_len = len - 24;
    if (ies_len < 0) return;

    char ssid[33] = {0};
    uint64_t fp = fnv1a_init();
    bool got_fp_bytes = false;

    int p = 0;
    while (p + 2 <= ies_len) {
        uint8_t id = ies[p];
        uint8_t ilen = ies[p + 1];
        if (p + 2 + ilen > ies_len) break;
        const uint8_t* idata = ies + p + 2;

        if (id == 0 && ilen <= 32 && ssid[0] == 0) {
            memcpy(ssid, idata, ilen);
            ssid[ilen] = 0;
        }

        if (is_fp_ie(id)) {
            fp = fnv1a_step(fp, id);
            fp = fnv1a_step(fp, ilen);
            for (int i = 0; i < ilen; i++) fp = fnv1a_step(fp, idata[i]);
            got_fp_bytes = true;
        }

        p += 2 + ilen;
    }

    if (!got_fp_bytes) fp = mac_key;  // fallback so unique fp count is sane

    bool mac_random = (src[0] & 0x02) != 0;
    int8_t rssi = pkt->rx_ctrl.rssi;
    uint8_t ch = pkt->rx_ctrl.channel;
    uint16_t seq_ctrl = (payload[22]) | (payload[23] << 8);
    uint16_t seq = seq_ctrl >> 4;

    g_probe_count++;
    set_insert(&g_macs, mac_key);
    set_insert(&g_fps,  fp);
    g_unique_macs = g_macs.count;
    g_unique_fps  = g_fps.count;
    if (ssid[0]) strncpy(g_last_ssid, ssid, sizeof(g_last_ssid) - 1);

    // JSON line over USB-CDC. Kept compact to survive slow serial.
    char mac_s[18];
    snprintf(mac_s, sizeof(mac_s), "%02x:%02x:%02x:%02x:%02x:%02x",
             src[0], src[1], src[2], src[3], src[4], src[5]);
    char fp_s[17];
    snprintf(fp_s, sizeof(fp_s), "%016llx", (unsigned long long)fp);

    // Escape SSID minimally (quotes + backslashes). Good enough for
    // downstream Python which parses line by line.
    char ssid_escaped[80];
    size_t k = 0;
    for (size_t i = 0; ssid[i] && k < sizeof(ssid_escaped) - 2; i++) {
        char c = ssid[i];
        if (c == '"' || c == '\\') {
            if (k < sizeof(ssid_escaped) - 3) ssid_escaped[k++] = '\\';
        }
        if (c < 0x20) c = '?';
        ssid_escaped[k++] = c;
    }
    ssid_escaped[k] = 0;

    Serial.printf(
        "{\"t\":%lu,\"mac\":\"%s\",\"rand\":%d,\"ssid\":\"%s\","
        "\"rssi\":%d,\"ch\":%u,\"seq\":%u,\"fp\":\"%s\"}\n",
        (unsigned long)millis(), mac_s, mac_random ? 1 : 0,
        ssid_escaped, rssi, ch, seq, fp_s);
}

// ---------- Setup / loop ----------
static uint32_t g_last_hop = 0;
static uint32_t g_last_display = 0;
static uint8_t g_hop_idx = 0;

static void start_promiscuous() {
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_start();

    wifi_promiscuous_filter_t filt = {.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT};
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(&sniffer_cb);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(CHANNELS[0], WIFI_SECOND_CHAN_NONE);
}

static void draw_status() {
    display.clear();
    display.setTextAlignment(TEXT_ALIGN_LEFT);
    display.setFont(ArialMT_Plain_10);

    display.drawString(0, 0, "PROBE SNIFFER");
    char line[40];
    snprintf(line, sizeof(line), "ch:%u  seen:%lu",
             g_current_channel, (unsigned long)g_probe_count);
    display.drawString(0, 12, line);
    snprintf(line, sizeof(line), "macs:%lu  fps:%lu",
             (unsigned long)g_unique_macs, (unsigned long)g_unique_fps);
    display.drawString(0, 24, line);

    display.drawString(0, 38, "last SSID:");
    const char* s = g_last_ssid[0] ? g_last_ssid : "<none>";
    char buf[22];
    strncpy(buf, s, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;
    display.drawString(0, 50, buf);

    display.display();
}

void setup() {
    Serial.begin(115200);
    delay(200);

    // Heltec V3 board power (VEXT) — needed for OLED on this revision.
    pinMode(Vext, OUTPUT);
    digitalWrite(Vext, LOW);
    delay(50);

    display.init();
    display.setFont(ArialMT_Plain_10);
    display.clear();
    display.drawString(0, 0, "booting...");
    display.display();

    start_promiscuous();

    Serial.println("# probesniff: started");
    Serial.println("# fields: t(ms since boot), mac, rand, ssid, rssi, ch, seq, fp");
}

void loop() {
    uint32_t now = millis();

    if (now - g_last_hop >= HOP_INTERVAL_MS) {
        g_hop_idx = (g_hop_idx + 1) % N_CHANNELS;
        g_current_channel = CHANNELS[g_hop_idx];
        esp_wifi_set_channel(g_current_channel, WIFI_SECOND_CHAN_NONE);
        g_last_hop = now;
    }

    if (now - g_last_display >= DISPLAY_INTERVAL_MS) {
        draw_status();
        g_last_display = now;
    }

    delay(5);
}
