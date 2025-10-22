// SPDX-License-Identifier: MIT
// ESP32-P4 ↔ TROPIC01 (no vendor SDK)
// L2 (LEN=1, CRC16 0x8005 init 0x0000, MSB-first math, LSB-first on wire)
// + Secure Channel (X25519/HKDF-SHA256/AES-GCM)
//
// Flow parity with Petr Kracik’s Python reference:
// - GET_INFO(CHIPID, X.509) → STPUB → SC handshake
// - TRNG (RANDOM_VALUE)
// - ECC(P-256) KEY_GENERATE / KEY_READ / ECDSA_SIGN (+ mbedTLS verify)
// - Added L2: GET_LOG, ENCRYPTED_SESSION_ABORT, SLEEP_REQ, STARTUP_REQ
// - Added L3: PING, SERIAL_CODE_GET, R/I_CONFIG_READ, MEMDATA R/W/ERASE,
//             ECC_KEY_STORE, EDDSA_SIGN, MAC_AND_DESTROY,
//             MCOUNTER INIT/UPDATE/GET
//
// NOTE: For a few command IDs the repo uses constants you are not
//       have defined in C yet. They are marked TODO_* below. They will be filled in.

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <inttypes.h>

#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "driver/spi_master.h"
#include "driver/gpio.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_rom_sys.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

// mbedTLS
#include "mbedtls/md.h"
#include "mbedtls/gcm.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/error.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecdsa.h"

// X25519 (via curve25519 helpers from ed25519 lib)
#include "ed25519.h"

// Declare ed25519_verify if not in header
extern int ed25519_verify(const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key);

/* ─────────── Board pins / SPI ─────────── */
#define PIN_NUM_MOSI   28
#define PIN_NUM_MISO   29
#define PIN_NUM_CLK    30
#define PIN_NUM_CS     31

#define SPI_HOST_USED  SPI2_HOST
#define SPI_CLOCK_HZ   1000000
#define SPI_MODE       0

/* ─────────── Timing / sizes / log ─────────── */
#define TAG "TROPIC_DEMO"

#define MAX_POLL_RETRIES    120
#define POLL_DELAY_MS       10
#define L1_MAX              512
#define ENC_CHUNK_MAX       128

/* ─────────── Protocol constants ─────────── */
#define REQ_ID_GET_RESPONSE           0xAA

// L2 REQ IDs
#define REQ_ID_GET_INFO_REQ           0x01
#define REQ_ID_SC_HANDSHAKE           0x02
#define REQ_ID_ENCRYPTED_CMD_REQ      0x04
#define REQ_ID_ENCRYPTED_SESSION_ABT  0x08
#define REQ_ID_GET_LOG_REQ            0xA2
#define REQ_ID_SLEEP_REQ              0x20
#define REQ_ID_STARTUP_REQ            0xB3

// L2 status
#define STATUS_REQ_OK                 0x01
#define STATUS_RES_OK                 0x02
#define STATUS_REQ_CONT               0x03
#define STATUS_RES_CONT               0x04
#define STATUS_BUSY                   0xFF

// CHIP_STATUS
#define CHIP_STATUS_NOT_READY         0x00
#define CHIP_STATUS_READY             0x01
#define CHIP_STATUS_BUSY_BIT          0x02
#define CHIP_STATUS_ALARM_BIT         0x80

// GET_INFO objects/chunks
#define GET_INFO_OBJECT_X509_CERT     0x00
#define GET_INFO_OBJECT_CHIPID        0x01
#define GET_INFO_OBJECT_RISCV_FW_VER  0x02  // optional: for parity with Python properties
#define GET_INFO_OBJECT_SPECT_FW_VER  0x03  // optional
#define GET_INFO_OBJECT_FW_BANK       0x04  // optional

#define GET_INFO_DATA_CHUNK_0_127     0x00
#define GET_INFO_DATA_CHUNK_128_255   0x01
#define GET_INFO_DATA_CHUNK_256_383   0x02
#define GET_INFO_DATA_CHUNK_384_511   0x03

// L3 Command IDs (known)
#define CMD_ID_RANDOM_VALUE           0x50
#define CMD_ID_ECC_KEY_GENERATE       0x60
#define CMD_ID_ECC_KEY_STORE          0x61
#define CMD_ID_ECC_KEY_READ           0x62
#define CMD_ID_ECC_KEY_ERASE          0x63
#define CMD_ID_ECDSA_SIGN             0x70
#define CMD_ID_EDDSA_SIGN             0x71

// L3 Command IDs (TODO: fill per spec)
#ifndef CMD_ID_PING
#define CMD_ID_PING                   0x40 /* TODO: verify */
#endif
#ifndef CMD_ID_SERIAL_CODE_GET
#define CMD_ID_SERIAL_CODE_GET        0x41 /* TODO: verify */
#endif
#ifndef CMD_ID_R_CFG_READ
#define CMD_ID_R_CFG_READ             0x42 /* TODO: verify */
#endif
#ifndef CMD_ID_I_CFG_READ
#define CMD_ID_I_CFG_READ             0x43 /* TODO: verify */
#endif
#ifndef CMD_ID_R_MEMDATA_READ
#define CMD_ID_R_MEMDATA_READ         0x44 /* TODO: verify */
#endif
#ifndef CMD_ID_R_MEMDATA_WRITE
#define CMD_ID_R_MEMDATA_WRITE        0x45 /* TODO: verify */
#endif
#ifndef CMD_ID_R_MEMDATA_ERASE
#define CMD_ID_R_MEMDATA_ERASE        0x46 /* TODO: verify */
#endif
#ifndef CMD_ID_MCOUNTER_INIT
#define CMD_ID_MCOUNTER_INIT          0x47 /* TODO: verify */
#endif
#ifndef CMD_ID_MCOUNTER_UPDATE
#define CMD_ID_MCOUNTER_UPDATE        0x48 /* TODO: verify */
#endif
#ifndef CMD_ID_MCOUNTER_GET
#define CMD_ID_MCOUNTER_GET           0x49 /* TODO: verify */
#endif
#ifndef CMD_ID_MAC_AND_DESTROY
#define CMD_ID_MAC_AND_DESTROY        0x4A /* TODO: verify */
#endif

#define CMD_RESULT_OK                 0xC3

// ECC curves
#define ECC_CURVE_P256                0x01
#define ECC_CURVE_ED25519             0x02

// Limits / sizes
#define COMMAND_SIZE_LEN              2
#define MEM_ADDRESS_SIZE              2
#define CFG_ADDRESS_SIZE              2
#define MEM_DATA_MAX_SIZE             444
#define MCOUNTER_MAX                  0xFFFF
#define MAC_AND_DESTROY_MAX           0xFFFF

// Sleep / startup IDs (from Python names)
#define SLEEP_MODE_SLEEP              0x00
#define SLEEP_MODE_DEEP_SLEEP         0x01
#define STARTUP_REBOOT                0x00
#define STARTUP_MAINTENANCE_REBOOT    0x01

/* ─────────── Handshake constants ─────────── */
static const uint8_t PROTOCOL_NAME[32] = {
  'N','o','i','s','e','_','K','K','1','_','2','5','5','1','9','_',
  'A','E','S','G','C','M','_','S','H','A','2','5','6', 0x00,0x00,0x00
};

/* ─────────── Pairing keys (select via -DSELECT_PKEY_SLOT) ─────────── */
#ifndef SELECT_PKEY_SLOT
#define SELECT_PKEY_SLOT 0
#endif
static const uint8_t PKEY_INDEX = SELECT_PKEY_SLOT;

#if SELECT_PKEY_SLOT==1
static const uint8_t SH_PRIV[32] = { 0x58,0xc4,0x81,0x88,0xf8,0xb1,0xcb,0xd4,0x19,0x00,0x2e,0x9c,0x8d,0xf8,0xce,0xea,
  0xf3,0xa9,0x11,0xde,0xb6,0x6b,0xc8,0x87,0xae,0xe7,0x88,0x10,0xfb,0x48,0xb6,0x74 };
static const uint8_t SH_PUB[32]  = { 0xe1,0xdc,0xf9,0xc3,0x46,0xbc,0xf2,0xe7,0x8b,0xa8,0xf0,0x27,0xd8,0x0a,0x8a,0x33,
  0xcc,0xf3,0xe9,0xdf,0x6b,0xdf,0x65,0xa2,0xc1,0xae,0xc4,0xd9,0x21,0xe1,0x8d,0x51 };
#elif SELECT_PKEY_SLOT==2
static const uint8_t SH_PRIV[32] = { 0x00,0x40,0x5e,0x19,0x46,0x75,0xab,0xe1,0x5f,0x0b,0x57,0xf2,0x5b,0x12,0x86,0x62,
  0xab,0xb0,0xe9,0xc6,0xa7,0xc3,0xca,0xdf,0x1c,0xb1,0xd2,0xb7,0xf8,0xcf,0x35,0x47 };
static const uint8_t SH_PUB[32]  = { 0x66,0xb9,0x92,0x5a,0x85,0x66,0xe8,0x09,0x5c,0x56,0x80,0xfb,0x22,0xd4,0xb8,0x4b,
  0xf8,0xe3,0x12,0xb2,0x7c,0x4b,0xac,0xce,0x26,0x3c,0x78,0x39,0x6d,0x4c,0x16,0x6c };
#elif SELECT_PKEY_SLOT==3
static const uint8_t SH_PRIV[32] = { 0xb0,0x90,0x9f,0xe1,0xf3,0x1f,0xa1,0x21,0x75,0xef,0x45,0xb1,0x42,0xde,0x0e,0xdd,
  0xa1,0xf4,0x51,0x01,0x40,0xc2,0xe5,0x2c,0xf4,0x68,0xac,0x96,0xa1,0x0e,0xcb,0x46 };
static const uint8_t SH_PUB[32]  = { 0x22,0x57,0xa8,0x2f,0x85,0x8f,0x13,0x32,0xfa,0x0f,0xf6,0x0c,0x76,0x29,0x42,0x70,
  0xa9,0x58,0x9d,0xfd,0x47,0xa5,0x23,0x78,0x18,0x4d,0x2d,0x38,0xf0,0xa7,0xc4,0x01 };
#else
static const uint8_t SH_PRIV[32] = { 0xd0,0x99,0x92,0xb1,0xf1,0x7a,0xbc,0x4d,0xb9,0x37,0x17,0x68,0xa2,0x7d,0xa0,0x5b,
  0x18,0xfa,0xb8,0x56,0x13,0xa7,0x84,0x2c,0xa6,0x4c,0x79,0x10,0xf2,0x2e,0x71,0x6b };
static const uint8_t SH_PUB[32]  = { 0xe7,0xf7,0x35,0xba,0x19,0xa3,0x3f,0xd6,0x73,0x23,0xab,0x37,0x26,0x2d,0xe5,0x36,
  0x08,0xca,0x57,0x85,0x76,0x53,0x43,0x52,0xe1,0x8f,0x64,0xe6,0x13,0xd3,0x8d,0x54 };
#endif

/* ─────────── SPI helpers ─────────── */
static spi_device_handle_t g_spi = NULL;

static inline void udelay(uint32_t us) { esp_rom_delay_us(us); }
static inline void cs_low(void)  { gpio_set_level(PIN_NUM_CS, 0); udelay(2); }
static inline void cs_high(void) { gpio_set_level(PIN_NUM_CS, 1); udelay(2); }

static void dump_hex(const char *label, const uint8_t *p, size_t n) {
    ESP_LOGI(TAG, "%s (%zu bytes)", label, n);
    ESP_LOG_BUFFER_HEXDUMP(TAG, p, n, ESP_LOG_INFO);
}

static esp_err_t spi_rw(const uint8_t *tx, uint8_t *rx, size_t n) {
    uint8_t *z = NULL;
    if (!tx) { 
        z = (uint8_t*)heap_caps_calloc(1, n ? n : 1, MALLOC_CAP_8BIT);
        if (!z) return ESP_ERR_NO_MEM;
        tx = z; 
    }
    spi_transaction_t t = { .length = n * 8, .tx_buffer = tx, .rx_buffer = rx };
    esp_err_t r = spi_device_transmit(g_spi, &t);
    if (z) free(z);
    return r;
}
static inline esp_err_t spi_read_bytes(uint8_t *rx, size_t n) { return spi_rw(NULL, rx, n); }
static inline esp_err_t spi_write_bytes(const uint8_t *tx, size_t n) { return spi_rw(tx, NULL, n); }

/* ─────────── CRC16 (poly 0x8005) ─────────── */
static uint16_t crc16_8005(const uint8_t *data, size_t len) {
    uint16_t crc = 0x0000;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int b = 0; b < 8; b++) {
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x8005) : (uint16_t)(crc << 1);
        }
    }
    return crc;
}

/* ─────────── READY polling ─────────── */
static bool tropic_wait_ready(void) {
    ESP_LOGI(TAG, "Waiting for CHIP_STATUS[READY]...");
    for (int i = 0; i < MAX_POLL_RETRIES; i++) {
        uint8_t tx = REQ_ID_GET_RESPONSE, chip = 0;
        cs_low();
        (void)spi_rw(&tx, &chip, 1);
        cs_high();
        if (chip == CHIP_STATUS_READY) {
            ESP_LOGI(TAG, "Ready (CHIP_STATUS=0x%02X)", chip);
            return true;
        }
        vTaskDelay(pdMS_TO_TICKS(POLL_DELAY_MS));
    }
    ESP_LOGW(TAG, "Timeout waiting for READY.");
    return false;
}

/* ─────────── L2 send helpers ─────────── */
static int l2_send_simple(uint8_t req_id, const uint8_t *data, uint8_t len) {
    if (len > 252) return -10;
    uint8_t frame[1 + 1 + 252 + 2] = {0};
    size_t used = 0;
    frame[used++] = req_id;
    frame[used++] = len;
    if (len) { memcpy(&frame[used], data, len); used += len; }
    uint16_t c = crc16_8005(frame, used);
    frame[used++] = (uint8_t)(c & 0xFF);
    frame[used++] = (uint8_t)(c >> 8);

    cs_low();
    esp_err_t ret = spi_write_bytes(frame, used);
    cs_high();
    return (ret == ESP_OK) ? 0 : -11;
}

static inline int l2_send_get_info(uint8_t object_id, uint8_t chunk_idx) {
    uint8_t req[2] = { object_id, chunk_idx };
    return l2_send_simple(REQ_ID_GET_INFO_REQ, req, sizeof(req));
}

static int l2_send_handshake_len(const uint8_t ehpub[32], uint8_t pkey_index) {
    uint8_t payload[33];
    memcpy(payload, ehpub, 32);
    payload[32] = pkey_index;

    int rc = l2_send_simple(REQ_ID_SC_HANDSHAKE, payload, sizeof(payload));
    if (rc == 0) {
        uint8_t frame[1 + 1 + 33 + 2];
        size_t off = 0;
        frame[off++] = REQ_ID_SC_HANDSHAKE;
        frame[off++] = 33;
        memcpy(&frame[off], payload, 33); off += 33;
        uint16_t c = crc16_8005(frame, off);
        frame[off++] = (uint8_t)(c & 0xFF);
        frame[off++] = (uint8_t)(c >> 8);
        dump_hex("HSK TX", frame, off);
    }
    return rc;
}

static int l2_send_enc_chunk(const uint8_t *chunk, uint8_t chunk_len) {
    uint8_t buf[1 + 1 + ENC_CHUNK_MAX + 2];
    buf[0] = REQ_ID_ENCRYPTED_CMD_REQ;
    buf[1] = chunk_len;
    memcpy(&buf[2], chunk, chunk_len);
    uint16_t crc = crc16_8005(buf, 2 + chunk_len);
    buf[2 + chunk_len]     = (uint8_t)(crc & 0xFF);
    buf[2 + chunk_len + 1] = (uint8_t)(crc >> 8);

    cs_low();
    esp_err_t r = spi_write_bytes(buf, 2 + chunk_len + 2);
    cs_high();
    return (r == ESP_OK) ? 0 : -11;
}

/* ─────────── L2 receive path ─────────── */
static int l2_read_response(uint8_t *out_payload, size_t out_max,
                            uint8_t *out_status, uint8_t *out_chip_status)
{
    if (!out_payload || out_max == 0) return -1;

    for (int tries = 0; tries < MAX_POLL_RETRIES; tries++) {
        uint8_t poll = REQ_ID_GET_RESPONSE, chip = 0;

        cs_low();
        if (spi_rw(&poll, &chip, 1) != ESP_OK) { cs_high(); return -2; }
        if (out_chip_status) *out_chip_status = chip;

        if (chip == CHIP_STATUS_NOT_READY || (chip & CHIP_STATUS_BUSY_BIT)) {
            cs_high();
            vTaskDelay(pdMS_TO_TICKS(POLL_DELAY_MS));
            continue;
        }
        if (chip & CHIP_STATUS_ALARM_BIT) { cs_high(); return -30; }

        uint8_t hdr[2] = {0};
        if (spi_read_bytes(hdr, 2) != ESP_OK) { cs_high(); return -2; }
        uint8_t st  = hdr[0];
        uint8_t len = hdr[1];

        if (st == STATUS_BUSY) { cs_high(); vTaskDelay(pdMS_TO_TICKS(POLL_DELAY_MS)); continue; }

        if (st == STATUS_REQ_OK && len == 0) {
            cs_high();
            if (out_status) *out_status = st;
            ESP_LOGI(TAG, "RX st=0x%02X len=%u (ack, no CRC)", st, len);
            return 0;
        }

        if (out_status) *out_status = st;
        if (len > out_max) { cs_high(); return -4; }

        if (len) {
            if (spi_read_bytes(out_payload, len) != ESP_OK) { cs_high(); return -2; }
        }

        uint8_t crcb[2] = {0};
        if (spi_read_bytes(crcb, 2) != ESP_OK) { cs_high(); return -2; }
        cs_high();

        size_t crc_len = (size_t)(2 + len);
        uint8_t *crcbuf = (uint8_t*)heap_caps_malloc(crc_len, MALLOC_CAP_8BIT);
        if (!crcbuf) return -50;
        crcbuf[0] = st;
        crcbuf[1] = len;
        if (len) memcpy(&crcbuf[2], out_payload, len);
        uint16_t calc = crc16_8005(crcbuf, crc_len);
        free(crcbuf);

        uint16_t wire = (uint16_t)crcb[0] | ((uint16_t)crcb[1] << 8);
        if (calc != wire) {
            ESP_LOGE(TAG, "CRC mismatch: calc=0x%04X wire=0x%04X", calc, wire);
            return -5;
        }

        if (st == STATUS_RES_CONT) {
            int n2 = l2_read_response(out_payload + len, out_max - len, &st, NULL);
            if (n2 < 0) return n2;
            return len + n2;
        }

        ESP_LOGI(TAG, "RX st=0x%02X len=%u", st, len);
        dump_hex("RX payload", out_payload, len);
        return (int)len;
    }
    return -6;
}

/* ─────────── L2 utilities matching Python ─────────── */
static int l2_get_info_req(uint8_t object_id, uint8_t chunk_idx, uint8_t *buf, size_t buflen) {
    int s = l2_send_get_info(object_id, chunk_idx);
    if (s < 0) return s;

    for (int i = 0; i < MAX_POLL_RETRIES; i++) {
        uint8_t st = 0, cs = 0;
        int len = l2_read_response(buf, buflen, &st, &cs);
        if (len < 0) return len;
        if (len == 0) { vTaskDelay(pdMS_TO_TICKS(POLL_DELAY_MS)); continue; }
        return len;
    }
    return -3;
}

static int l2_handshake_resp(uint8_t pkey_index, const uint8_t ehpub[32],
                             uint8_t tsehpub[32], uint8_t tsauth[16]) {
    int rc = l2_send_handshake_len(ehpub, pkey_index);
    if (rc) return rc;

    for (int i = 0; i < MAX_POLL_RETRIES; i++) {
        uint8_t st=0, cs=0; uint8_t tmp[64]={0};
        int n = l2_read_response(tmp, sizeof(tmp), &st, &cs);
        if (n < 0) return n;
        if (n == 0) { vTaskDelay(pdMS_TO_TICKS(POLL_DELAY_MS)); continue; }
        if (n < 48) return -22;
        memcpy(tsehpub, tmp, 32);
        memcpy(tsauth,  tmp+32, 16);
        return 0;
    }
    return -23;
}

static int l2_get_log(char **out_text) {
    if (!out_text) return -1;
    size_t cap = 256, len = 0;
    char *acc = (char*)heap_caps_malloc(cap, MALLOC_CAP_8BIT);
    if (!acc) return -2;

    for (;;) {
        int s = l2_send_simple(REQ_ID_GET_LOG_REQ, NULL, 0);
        if (s) { free(acc); return s; }

        uint8_t st=0, cs=0; uint8_t chunk[256]={0};
        int n = l2_read_response(chunk, sizeof(chunk), &st, &cs);
        if (n < 0) { free(acc); return n; }
        if (n == 0) break; // no more

        if (len + (size_t)n + 1 > cap) {
            cap = (len + n + 1) * 2;
            char *tmp = (char*)heap_caps_realloc(acc, cap, MALLOC_CAP_8BIT);
            if (!tmp) { free(acc); return -3; }
            acc = tmp;
        }
        memcpy(acc + len, chunk, n);
        len += (size_t)n;
    }
    acc[len] = '\0';
    *out_text = acc;
    return 0;
}

#if 0
static int l2_encrypted_session_abort(void) {
    int s = l2_send_simple(REQ_ID_ENCRYPTED_SESSION_ABT, NULL, 0);
    if (s) return s;
    uint8_t st=0, cs=0; uint8_t dummy[8]={0};
    int n = l2_read_response(dummy, sizeof(dummy), &st, &cs);
    return (n >= 0) ? 0 : n;
}

static int l2_sleep_req(uint8_t sleep_mode) {
    if (sleep_mode != SLEEP_MODE_SLEEP && sleep_mode != SLEEP_MODE_DEEP_SLEEP) return -1;
    uint8_t b = sleep_mode;
    int s = l2_send_simple(REQ_ID_SLEEP_REQ, &b, 1);
    if (s) return s;
    uint8_t st=0, cs=0; uint8_t dummy[8]={0};
    int n = l2_read_response(dummy, sizeof(dummy), &st, &cs);
    return (n >= 0) ? 0 : n;
}

static int l2_startup_req(uint8_t startup_id) {
    if (startup_id != STARTUP_REBOOT && startup_id != STARTUP_MAINTENANCE_REBOOT) return -1;
    uint8_t b = startup_id;
    int s = l2_send_simple(REQ_ID_STARTUP_REQ, &b, 1);
    if (s) return s;
    uint8_t st=0, cs=0; uint8_t dummy[8]={0};
    int n = l2_read_response(dummy, sizeof(dummy), &st, &cs);
    return (n >= 0) ? 0 : n;
}
#endif

/* ─────────── mbedTLS helpers / X25519 / HKDF / GCM ─────────── */
typedef struct { mbedtls_entropy_context entropy; mbedtls_ctr_drbg_context ctr; int inited; } rng_t;

static int rng_init(rng_t *r) {
    const char *pers = "tropic_rng";
    mbedtls_entropy_init(&r->entropy);
    mbedtls_ctr_drbg_init(&r->ctr);
    int ret = mbedtls_ctr_drbg_seed(&r->ctr, mbedtls_entropy_func, &r->entropy,
                                    (const unsigned char*)pers, strlen(pers));
    if (ret == 0) {
        uint8_t extra[64];
        for (size_t i = 0; i < sizeof(extra); i += 4) {
            uint32_t v = esp_random();
            memcpy(&extra[i], &v, 4);
        }
        mbedtls_ctr_drbg_update(&r->ctr, extra, sizeof(extra));
    }
    r->inited = (ret == 0);
    return ret;
}
static void rng_free(rng_t *r){ if(!r->inited)return; mbedtls_ctr_drbg_free(&r->ctr); mbedtls_entropy_free(&r->entropy); r->inited=0; }

static int x25519_keygen(rng_t *rng, uint8_t out_priv[32], uint8_t out_pub[32]) {
    mbedtls_ecp_group grp; mbedtls_ecp_group_init(&grp);
    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (ret) { mbedtls_ecp_group_free(&grp); return ret; }
    mbedtls_mpi d; mbedtls_ecp_point Q; mbedtls_mpi_init(&d); mbedtls_ecp_point_init(&Q);

    ret = mbedtls_ecp_gen_keypair(&grp, &d, &Q, mbedtls_ctr_drbg_random, &rng->ctr);
    if (ret == 0) {
        ret = mbedtls_mpi_write_binary_le(&d, out_priv, 32);
        if (ret == 0) ret = mbedtls_mpi_write_binary_le(&Q.MBEDTLS_PRIVATE(X), out_pub, 32);
    }

    mbedtls_mpi_free(&d); mbedtls_ecp_point_free(&Q); mbedtls_ecp_group_free(&grp);
    return ret;
}

static void x25519_scalarmult(uint8_t *shared, const uint8_t *priv, const uint8_t *pub) {
    curve25519_scalarmult(shared, priv, pub);
}

#if 0
static void x25519_public_from_private(uint8_t *pub, const uint8_t *priv) {
    curve25519_scalarmult_basepoint(pub, priv);
}
#endif

static int sha256_once(const uint8_t *data, size_t len, uint8_t out[32]) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t ctx; mbedtls_md_init(&ctx);
    int ret = mbedtls_md_setup(&ctx, md, 0);
    if (ret==0) {
        mbedtls_md_starts(&ctx);
        mbedtls_md_update(&ctx, data, len);
        mbedtls_md_finish(&ctx, out);
    }
    mbedtls_md_free(&ctx);
    return ret;
}

static int hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *data, size_t data_len,
                       uint8_t out[32]) {
    int ret=0; const mbedtls_md_info_t *md=mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t ctx; mbedtls_md_init(&ctx);
    if((ret=mbedtls_md_setup(&ctx,md,1))!=0) goto end;
    if((ret=mbedtls_md_hmac_starts(&ctx,key,key_len))!=0) goto end;
    if((ret=mbedtls_md_hmac_update(&ctx,data,data_len))!=0) goto end;
    if((ret=mbedtls_md_hmac_finish(&ctx,out))!=0) goto end;
end: mbedtls_md_free(&ctx); return ret;
}

static int hkdf_extract_expand(const uint8_t *salt, size_t salt_len,
                               const uint8_t *ikm, size_t ikm_len,
                               uint8_t *out, size_t out_len) {
    uint8_t prk[32];
    int ret=hmac_sha256(salt,salt_len,ikm?ikm:(const uint8_t*)"",ikm_len,prk);
    if(ret) return ret;
    uint8_t T[32]; size_t Tlen=0, pos=0; uint8_t cnt=1;
    while(pos<out_len){
        uint8_t buf[32+1];
        memcpy(buf,T,Tlen);
        buf[Tlen]=cnt;
        ret=hmac_sha256(prk,sizeof(prk),buf,Tlen+1,T);
        if(ret) return ret;
        size_t copy=(out_len-pos>32)?32:(out_len-pos);
        memcpy(out+pos,T,copy);
        pos+=copy; Tlen=32; cnt++;
    }
    return 0;
}

/* ─────────── AES-GCM ─────────── */
static int gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *pt, size_t pt_len,
                       uint8_t *ct, uint8_t tag[16]) {
    mbedtls_gcm_context g; mbedtls_gcm_init(&g);
    int ret=mbedtls_gcm_setkey(&g,MBEDTLS_CIPHER_ID_AES,key,256);
    uint8_t din=0,dout=0; const uint8_t *in=pt_len?pt:&din; uint8_t *out=pt_len?ct:&dout;
    if(ret==0) ret=mbedtls_gcm_crypt_and_tag(&g,MBEDTLS_GCM_ENCRYPT,pt_len,nonce,12,aad,aad_len,in,out,16,tag);
    mbedtls_gcm_free(&g); return ret;
}
static int gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ct, size_t ct_len,
                       const uint8_t tag[16], uint8_t *pt) {
    mbedtls_gcm_context g; mbedtls_gcm_init(&g);
    int ret=mbedtls_gcm_setkey(&g,MBEDTLS_CIPHER_ID_AES,key,256);
    if(ret==0) ret=mbedtls_gcm_auth_decrypt(&g,ct_len,nonce,12,aad,aad_len,tag,16,ct,pt);
    mbedtls_gcm_free(&g); return ret;
}

/* ─────────── SC state ─────────── */
typedef struct {
    uint8_t kcmd[32];
    uint8_t kres[32];
    uint32_t counter;
    int established;
} sc_t;

static void nonce12_from_counter_le(uint32_t ctr, uint8_t nonce[12]) {
    memset(nonce, 0, 12);
    nonce[0]=(uint8_t)(ctr&0xFF);
    nonce[1]=(uint8_t)((ctr>>8)&0xFF);
    nonce[2]=(uint8_t)((ctr>>16)&0xFF);
    nonce[3]=(uint8_t)((ctr>>24)&0xFF);
}

/* Transcript hash (matches Python) */
static int build_handshake_hash(const uint8_t shpub[32], const uint8_t stpub[32],
                                const uint8_t ehpub[32], uint8_t pkey_index,
                                const uint8_t tsehpub[32],
                                uint8_t out_hash[32]) {
    uint8_t h[32], buf[64];

    if (sha256_once(PROTOCOL_NAME, 32, h) != 0) return -1;
    memcpy(buf,h,32); memcpy(buf+32,shpub,32);
    if (sha256_once(buf, 64, h) != 0) return -1;
    memcpy(buf,h,32); memcpy(buf+32,stpub,32);
    if (sha256_once(buf, 64, h) != 0) return -1;
    memcpy(buf,h,32); memcpy(buf+32,ehpub,32);
    if (sha256_once(buf, 64, h) != 0) return -1;
    uint8_t pi[33]; memcpy(pi,h,32); pi[32]=pkey_index;
    if (sha256_once(pi, 33, h) != 0) return -1;
    memcpy(buf,h,32); memcpy(buf+32,tsehpub,32);
    if (sha256_once(buf, 64, h) != 0) return -1;
    memcpy(out_hash,h,32);
    return 0;
}

/* ─────────── L2 secure channel flows ─────────── */
static int sc_start(uint8_t pkey_index,
                    const uint8_t shpriv[32], const uint8_t shpub[32],
                    const uint8_t stpub[32], sc_t *sc) {
    rng_t rng; if (rng_init(&rng) != 0) return -1;

    uint8_t ehpriv[32], ehpub[32];
    if (x25519_keygen(&rng, ehpriv, ehpub) != 0) { rng_free(&rng); return -2; }
    dump_hex("EHPUB", ehpub, 32);

    uint8_t tsehpub[32], tsauth[16];
    int hs = l2_handshake_resp(pkey_index, ehpub, tsehpub, tsauth);
    if (hs != 0) { rng_free(&rng); return -3; }

    uint8_t h[32];
    if (build_handshake_hash(shpub, stpub, ehpub, pkey_index, tsehpub, h) != 0) { rng_free(&rng); return -4; }

    uint8_t ss_eh_tseh[32], ss_sh_tseh[32], ss_eh_st[32];
    x25519_scalarmult(ss_eh_tseh, ehpriv, tsehpub);
    x25519_scalarmult(ss_sh_tseh, shpriv, tsehpub);
    x25519_scalarmult(ss_eh_st,   ehpriv, stpub);

    uint8_t ck1[32];     if (hkdf_extract_expand(PROTOCOL_NAME, 32, ss_eh_tseh, 32, ck1, 32))     { rng_free(&rng); return -8; }
    uint8_t ck2[32];     if (hkdf_extract_expand(ck1, 32, ss_sh_tseh, 32, ck2, 32))               { rng_free(&rng); return -9; }
    uint8_t out64[64];   if (hkdf_extract_expand(ck2, 32, ss_eh_st, 32, out64, 64))               { rng_free(&rng); return -10; }
    uint8_t ck_cmdres[32], kauth[32];
    memcpy(ck_cmdres, out64, 32);
    memcpy(kauth,     out64 + 32, 32);

    uint8_t keys64[64]; if (hkdf_extract_expand(ck_cmdres, 32, NULL, 0, keys64, 64))              { rng_free(&rng); return -11; }
    memcpy(sc->kcmd, keys64, 32);
    memcpy(sc->kres, keys64 + 32, 32);

    uint8_t znonce[12] = {0}, tag[16];
    if (gcm_encrypt(kauth, znonce, h, 32, NULL, 0, NULL, tag) != 0) { rng_free(&rng); return -12; }
    if (memcmp(tag, tsauth, 16) != 0) { rng_free(&rng); return -13; }

    sc->counter = 0;
    sc->established = 1;
    rng_free(&rng);
    return 0;
}

/* ─────────── Encrypted command exec ─────────── */
static int l2_encrypted_exec(sc_t *sc, const uint8_t *pt, uint16_t pt_len,
                             uint8_t **out_pt, uint16_t *out_len) {
    if (!sc || !sc->established) return -1;

    uint8_t nonce[12];
    nonce12_from_counter_le(sc->counter, nonce);

    uint8_t *ct = (uint8_t*)heap_caps_malloc(pt_len ? pt_len : 1, MALLOC_CAP_8BIT);
    if (!ct) return -2;
    uint8_t tag[16];
    if (gcm_encrypt(sc->kcmd, nonce, NULL, 0, pt, pt_len, ct, tag) != 0) { free(ct); return -3; }

    // build L3 blob: [len_le16][ct...][tag16]
    size_t blob_len = 2 + pt_len + 16;
    uint8_t *blob = (uint8_t*)heap_caps_malloc(blob_len, MALLOC_CAP_8BIT);
    if (!blob) { free(ct); return -4; }
    blob[0] = (uint8_t)(pt_len & 0xFF);
    blob[1] = (uint8_t)((pt_len >> 8) & 0xFF);
    memcpy(blob + 2, ct, pt_len);
    memcpy(blob + 2 + pt_len, tag, 16);

    // stream in 128B chunks and collect the final response
    uint8_t *prefetch = NULL; int prefetch_len = 0;
    size_t off = 0;
    while (off < blob_len) {
        uint8_t piece = (uint8_t)((blob_len - off) > ENC_CHUNK_MAX ? ENC_CHUNK_MAX : (blob_len - off));
        int s = l2_send_enc_chunk(blob + off, piece);
        if (s < 0) { free(ct); free(blob); if (prefetch) free(prefetch); return -5; }

        for (;;) {
            uint8_t st = 0, cs = 0;
            uint8_t tmp[256] = {0};
            int r = l2_read_response(tmp, sizeof(tmp), &st, &cs);
            if (r < 0) { free(ct); free(blob); if (prefetch) free(prefetch); return -6; }
            if (r == 0) {
                // no payload yet (ack/noCRC), proceed sending next chunk
                break;
            } else {
                prefetch = (uint8_t*)heap_caps_malloc(r, MALLOC_CAP_8BIT);
                if (!prefetch) { free(ct); free(blob); return -7; }
                memcpy(prefetch, tmp, r);
                prefetch_len = r;
                break;
            }
        }
        off += piece;
    }

    uint8_t *rbuf = NULL; int rlen = 0;
    if (prefetch) {
        rbuf = prefetch; rlen = prefetch_len;
    } else {
        rbuf = (uint8_t*)heap_caps_malloc(L1_MAX, MALLOC_CAP_8BIT);
        if (!rbuf) { free(ct); free(blob); return -8; }
        for (;;) {
            uint8_t st = 0, cs = 0;
            rlen = l2_read_response(rbuf, L1_MAX, &st, &cs);
            if (rlen < 0) { free(ct); free(blob); free(rbuf); return -9; }
            if (rlen == 0) { vTaskDelay(pdMS_TO_TICKS(10)); continue; }
            break;
        }
    }

    if (rlen < 2 + 16) { free(ct); free(blob); if (!prefetch) free(rbuf); return -10; }
    uint16_t resp_ct_len = (uint16_t)rbuf[0] | ((uint16_t)rbuf[1] << 8);
    if (2 + resp_ct_len + 16 != (size_t)rlen) { free(ct); free(blob); if (!prefetch) free(rbuf); return -11; }

    const uint8_t *resp_ct  = &rbuf[2];
    const uint8_t *resp_tag = &rbuf[2 + resp_ct_len];

    dump_hex("Encrypted CT", resp_ct, resp_ct_len);
    dump_hex("Encrypted TAG", resp_tag, 16);

    uint8_t *pt_out = (uint8_t*)heap_caps_malloc(resp_ct_len ? resp_ct_len : 1, MALLOC_CAP_8BIT);
    if (!pt_out) { free(ct); free(blob); if (!prefetch) free(rbuf); return -12; }
    if (gcm_decrypt(sc->kres, nonce, NULL, 0, resp_ct, resp_ct_len, resp_tag, pt_out) != 0) {
        ESP_LOGE(TAG, "GCM decrypt failed (tag mismatch) ctr=%" PRIu32, (uint32_t)sc->counter);
        free(ct); free(blob); if (!prefetch) free(rbuf); free(pt_out); return -13;
    }

    sc->counter += 1;

    *out_pt = pt_out;
    *out_len = resp_ct_len;

    free(ct); free(blob); if (!prefetch) free(rbuf);
    dump_hex("Decrypted PT", pt_out, resp_ct_len);
    return 0;
}

/* ─────────── GET_INFO helpers ─────────── */
static int get_info_chipid(uint8_t *buf, size_t buflen) {
    return l2_get_info_req(GET_INFO_OBJECT_CHIPID, GET_INFO_DATA_CHUNK_0_127, buf, buflen);
}
static int get_info_x509_all(uint8_t *dst, size_t dstlen) {
    size_t off = 0;
    for (uint8_t ch = 0; ch < 4; ch++) {
        if (off >= dstlen) return -1;
        int n = l2_get_info_req(GET_INFO_OBJECT_X509_CERT, ch, dst + off, dstlen - off);
        if (n < 0) return n;
        off += (size_t)n;
    }
    return (int)off;
}
static int find_x25519_pub_in_cert(const uint8_t *cert, size_t cert_len, uint8_t out_pub[32]) {
    for (size_t i = 0; i + 5 + 32 <= cert_len; i++) {
        if (i >= 1 && cert[i-1] == 0x2B && cert[i] == 0x65 && cert[i+1] == 0x6E) {
            if (cert[i+2] == 0x03 && cert[i+3] == 0x21 && cert[i+4] == 0x00) {
                memcpy(out_pub, &cert[i+5], 32);
                return 0;
            }
        }
        if (cert[i] == 0x65 && cert[i+1] == 0x6e && cert[i+2] == 0x03 && cert[i+3] == 0x21) {
            memcpy(out_pub, &cert[i+5], 32);
            return 0;
        }
    }
    return -1;
}

/* ─────────── L3 (parity with Python) ─────────── */

// Common decoder: require leading C3 OK
static int l3_expect_ok(uint8_t *resp, uint16_t rlen) {
    return (rlen >= 1 && resp[0] == CMD_RESULT_OK) ? 0 : -1;
}

#if 0
// PING: [CMD, data...] → echo
static int l3_ping(sc_t *sc, const uint8_t *data, size_t len, uint8_t **out, uint16_t *out_len) {
    if (len > 240) return -1;
    uint8_t pt[1 + 240]; pt[0] = CMD_ID_PING;
    memcpy(&pt[1], data, len);
    uint8_t *resp=NULL; uint16_t rlen=0;
    int rc = l2_encrypted_exec(sc, pt, (uint16_t)(1+len), &resp, &rlen);
    if (rc) return rc;
    if (l3_expect_ok(resp, rlen)) { free(resp); return -2; }
    // Python returns all payload (no extra length here)
    *out_len = rlen - 1;
    *out = (uint8_t*)heap_caps_malloc(*out_len ? *out_len : 1, MALLOC_CAP_8BIT);
    if(!*out){ free(resp); return -3; }
    memcpy(*out, resp+1, *out_len);
    free(resp);
    return 0;
}

// SERIAL_CODE_GET: [CMD] → C3 | payload...
static int l3_get_serial_code(sc_t *sc, uint8_t **out, uint16_t *out_len) {
    uint8_t pt[1] = { CMD_ID_SERIAL_CODE_GET };
    uint8_t *resp=NULL; uint16_t rlen=0;
    int rc = l2_encrypted_exec(sc, pt, sizeof(pt), &resp, &rlen);
    if (rc) return rc;
    if (l3_expect_ok(resp, rlen)) { free(resp); return -2; }
    *out_len = rlen - 1;
    *out = (uint8_t*)heap_caps_malloc(*out_len ? *out_len : 1, MALLOC_CAP_8BIT);
    if(!*out){ free(resp); return -3; }
    memcpy(*out, resp+1, *out_len);
    free(resp);
    return 0;
}

// R/I CONFIG READ: [CMD, addr_le16] → C3 | (maybe 0x00 0x00 0x00) | data...
static int l3_cfg_read(sc_t *sc, uint8_t cmd, uint16_t addr, uint8_t **out, uint16_t *out_len) {
    uint8_t pt[1 + CFG_ADDRESS_SIZE];
    pt[0] = cmd;
    pt[1] = (uint8_t)(addr & 0xFF);
    pt[2] = (uint8_t)((addr >> 8) & 0xFF);
    uint8_t *resp=NULL; uint16_t rlen=0;
    int rc = l2_encrypted_exec(sc, pt, sizeof(pt), &resp, &rlen);
    if (rc) return rc;
    if (l3_expect_ok(resp, rlen)) { free(resp); return -2; }
    uint16_t pos = 1;
    if (rlen >= 4 && resp[1]==0 && resp[2]==0 && resp[3]==0) pos = 4;
    *out_len = rlen - pos;
    *out = (uint8_t*)heap_caps_malloc(*out_len ? *out_len : 1, MALLOC_CAP_8BIT);
    if(!*out){ free(resp); return -3; }
    memcpy(*out, resp + pos, *out_len);
    free(resp);
    return 0;
}
static inline int l3_r_config_read(sc_t *sc, uint16_t addr, uint8_t **out, uint16_t *out_len) {
    return l3_cfg_read(sc, CMD_ID_R_CFG_READ, addr, out, out_len);
}
static inline int l3_i_config_read(sc_t *sc, uint16_t addr, uint8_t **out, uint16_t *out_len) {
    return l3_cfg_read(sc, CMD_ID_I_CFG_READ, addr, out, out_len);
}

// MEMDATA READ: [CMD, slot_le16] → C3 | (maybe zeros) | data...
static int l3_mem_data_read(sc_t *sc, uint16_t slot, uint8_t **out, uint16_t *out_len) {
    uint8_t pt[1 + MEM_ADDRESS_SIZE];
    pt[0] = CMD_ID_R_MEMDATA_READ;
    pt[1] = (uint8_t)(slot & 0xFF);
    pt[2] = (uint8_t)((slot >> 8) & 0xFF);
    uint8_t *resp=NULL; uint16_t rlen=0;
    int rc = l2_encrypted_exec(sc, pt, sizeof(pt), &resp, &rlen);
    if (rc) return rc;
    if (l3_expect_ok(resp, rlen)) { free(resp); return -2; }
    uint16_t pos = 1;
    if (rlen >= 4 && resp[1]==0 && resp[2]==0 && resp[3]==0) pos = 4;
    *out_len = rlen - pos;
    *out = (uint8_t*)heap_caps_malloc(*out_len ? *out_len : 1, MALLOC_CAP_8BIT);
    if(!*out){ free(resp); return -3; }
    memcpy(*out, resp + pos, *out_len);
    free(resp);
    return 0;
}

// MEMDATA WRITE: [CMD, slot_le16, 'M', data...] → C3
static int l3_mem_data_write(sc_t *sc, uint16_t slot, const uint8_t *data, size_t len) {
    if (len > MEM_DATA_MAX_SIZE) return -1;
    uint8_t *pt = (uint8_t*)heap_caps_malloc(1 + MEM_ADDRESS_SIZE + 1 + len, MALLOC_CAP_8BIT);
    if (!pt) return -2;
    size_t off=0;
    pt[off++] = CMD_ID_R_MEMDATA_WRITE;
    pt[off++] = (uint8_t)(slot & 0xFF);
    pt[off++] = (uint8_t)((slot >> 8) & 0xFF);
    pt[off++] = 'M'; // padding dummy byte
    memcpy(&pt[off], data, len); off += len;

    uint8_t *resp=NULL; uint16_t rlen=0;
    int rc = l2_encrypted_exec(sc, pt, (uint16_t)off, &resp, &rlen);
    free(pt);
    if (rc) return rc;
    int ok = l3_expect_ok(resp, rlen) ? -3 : 0;
    free(resp);
    return ok;
}

// MEMDATA ERASE: [CMD, slot_le16] → C3
static int l3_mem_data_erase(sc_t *sc, uint16_t slot) {
    uint8_t pt[1 + MEM_ADDRESS_SIZE];
    pt[0] = CMD_ID_R_MEMDATA_ERASE;
    pt[1] = (uint8_t)(slot & 0xFF);
    pt[2] = (uint8_t)((slot >> 8) & 0xFF);
    uint8_t *resp=NULL; uint16_t rlen=0;
    int rc = l2_encrypted_exec(sc, pt, sizeof(pt), &resp, &rlen);
    if (rc) return rc;
    int ok = l3_expect_ok(resp, rlen) ? -2 : 0;
    free(resp);
    return ok;
}
#endif

/* ECC (generate/read/store/erase/sign) — P256 & Ed25519 */
static int l3_ecc_key_generate(sc_t *sc, uint16_t slot, uint8_t curve) {
    uint8_t pt[1 + MEM_ADDRESS_SIZE + 1];
    pt[0] = CMD_ID_ECC_KEY_GENERATE;
    pt[1] = (uint8_t)(slot & 0xFF);
    pt[2] = (uint8_t)((slot >> 8) & 0xFF);
    pt[3] = curve;

    uint8_t *resp = NULL; uint16_t rlen = 0;
    int rc = l2_encrypted_exec(sc, pt, sizeof(pt), &resp, &rlen);
    if (rc != 0) return rc;
    int ok = l3_expect_ok(resp, rlen) ? -2 : 0;
    free(resp);
    return ok;
}
static int l3_ecc_key_read(sc_t *sc, uint16_t slot,
                           uint8_t *out_curve, uint8_t *out_origin,
                           uint8_t *out_pub, size_t *out_pub_len) {
    uint8_t pt[1 + MEM_ADDRESS_SIZE];
    pt[0] = CMD_ID_ECC_KEY_READ;
    pt[1] = (uint8_t)(slot & 0xFF);
    pt[2] = (uint8_t)((slot >> 8) & 0xFF);

    uint8_t *resp = NULL; uint16_t rlen = 0;
    int rc = l2_encrypted_exec(sc, pt, sizeof(pt), &resp, &rlen);
    if (rc != 0) return rc;
    if (rlen < 1 || resp[0] != CMD_RESULT_OK) { free(resp); return -2; }
    if (rlen < 16) { free(resp); return -3; }

    if (out_curve)  *out_curve  = resp[1];
    if (out_origin) *out_origin = resp[2];

    size_t pos = 1 + 15; // C3 + (curve, origin, 13 reserved)
    if (pos > rlen) { free(resp); return -4; }

    size_t plen = (size_t)rlen - pos;
    if (out_pub && out_pub_len) {
        memcpy(out_pub, &resp[pos], plen);
        *out_pub_len = plen;
    }
    free(resp);
    return 0;
}

#if 0
static int l3_ecc_key_store(sc_t *sc, uint16_t slot, uint8_t curve, const uint8_t *priv32) {
    // [0x61, slot_le16, curve, 12×0x00, priv32]
    uint8_t pt[1 + MEM_ADDRESS_SIZE + 1 + 12 + 32];
    size_t off=0;
    pt[off++] = CMD_ID_ECC_KEY_STORE;
    pt[off++] = (uint8_t)(slot & 0xFF);
    pt[off++] = (uint8_t)((slot >> 8) & 0xFF);
    pt[off++] = curve;
    memset(&pt[off], 0x00, 12); off += 12;
    memcpy(&pt[off], priv32, 32); off += 32;

    uint8_t *resp=NULL; uint16_t rlen=0;
    int rc = l2_encrypted_exec(sc, pt, (uint16_t)off, &resp, &rlen);
    if (rc) return rc;
    int ok = l3_expect_ok(resp, rlen) ? -2 : 0;
    free(resp);
    return ok;
}
#endif

static int l3_ecc_key_erase(sc_t *sc, uint16_t slot) {
    uint8_t pt[1 + MEM_ADDRESS_SIZE];
    pt[0] = CMD_ID_ECC_KEY_ERASE;
    pt[1] = (uint8_t)(slot & 0xFF);
    pt[2] = (uint8_t)((slot >> 8) & 0xFF);

    uint8_t *resp = NULL; uint16_t rlen = 0;
    int rc = l2_encrypted_exec(sc, pt, sizeof(pt), &resp, &rlen);
    if (rc != 0) return rc;
    int ok = l3_expect_ok(resp, rlen) ? -2 : 0;
    free(resp);
    return ok;
}

// ECDSA (P-256)
static int l3_ecdsa_sign(sc_t *sc, uint16_t slot, const uint8_t hash32[32],
                         uint8_t r[32], uint8_t s[32]) {
    uint8_t pt[1 + MEM_ADDRESS_SIZE + 13 + 32];
    pt[0] = CMD_ID_ECDSA_SIGN;
    pt[1] = (uint8_t)(slot & 0xFF);
    pt[2] = (uint8_t)((slot >> 8) & 0xFF);
    memset(&pt[3], 0x00, 13);
    memcpy(&pt[3 + 13], hash32, 32);

    uint8_t *resp = NULL; uint16_t rlen = 0;
    int rc = l2_encrypted_exec(sc, pt, sizeof(pt), &resp, &rlen);
    if (rc != 0) return rc;
    if (rlen < 1 || resp[0] != CMD_RESULT_OK) { free(resp); return -2; }

    size_t pos = 1 + 15; // skip OK + 15 reserved
    if (rlen < pos + 64) { free(resp); return -3; }

    memcpy(r, &resp[pos], 32);
    memcpy(s, &resp[pos + 32], 32);
    free(resp);
    return 0;
}

// Ed25519 (EdDSA) message-sign
static int l3_eddsa_sign(sc_t *sc, uint16_t slot, const uint8_t *msg, size_t msg_len,
                         uint8_t R[32], uint8_t S[32]) {
    if (msg_len > 240) return -1; // keep single frame in this demo
    uint8_t *pt = (uint8_t*)heap_caps_malloc(1 + MEM_ADDRESS_SIZE + 13 + msg_len, MALLOC_CAP_8BIT);
    if (!pt) return -2;
    size_t off=0;
    pt[off++] = CMD_ID_EDDSA_SIGN;
    pt[off++] = (uint8_t)(slot & 0xFF);
    pt[off++] = (uint8_t)((slot >> 8) & 0xFF);
    memset(&pt[off], 0x00, 13); off += 13;
    memcpy(&pt[off], msg, msg_len); off += msg_len;

    uint8_t *resp=NULL; uint16_t rlen=0;
    int rc = l2_encrypted_exec(sc, pt, (uint16_t)off, &resp, &rlen);
    free(pt);
    if (rc) return rc;
    if (rlen < 1 || resp[0] != CMD_RESULT_OK) { free(resp); return -3; }

    size_t pos = 1 + 15;
    if (rlen < pos + 64) { free(resp); return -4; }
    memcpy(R, &resp[pos], 32);
    memcpy(S, &resp[pos+32], 32);
    free(resp);
    return 0;
}

#if 0
/* Monotonic counters */
static int l3_mcounter_init(sc_t *sc, uint16_t index, uint32_t value) {
    uint8_t pt[1 + 2 + 1 + 4]; // cmd + index_le16 + 'A' + value_le32
    pt[0] = CMD_ID_MCOUNTER_INIT;
    pt[1] = (uint8_t)(index & 0xFF);
    pt[2] = (uint8_t)((index >> 8) & 0xFF);
    pt[3] = 'A';
    pt[4] = (uint8_t)(value & 0xFF);
    pt[5] = (uint8_t)((value >> 8) & 0xFF);
    pt[6] = (uint8_t)((value >> 16) & 0xFF);
    pt[7] = (uint8_t)((value >> 24) & 0xFF);
    uint8_t *resp=NULL; uint16_t rlen=0;
    int rc = l2_encrypted_exec(sc, pt, sizeof(pt), &resp, &rlen);
    if (rc) return rc;
    int ok = l3_expect_ok(resp, rlen) ? -2 : 0;
    free(resp);
    return ok;
}
static int l3_mcounter_update(sc_t *sc, uint16_t index) {
    uint8_t pt[1 + 2];
    pt[0] = CMD_ID_MCOUNTER_UPDATE;
    pt[1] = (uint8_t)(index & 0xFF);
    pt[2] = (uint8_t)((index >> 8) & 0xFF);
    uint8_t *resp=NULL; uint16_t rlen=0;
    int rc = l2_encrypted_exec(sc, pt, sizeof(pt), &resp, &rlen);
    if (rc) return rc;
    int ok = l3_expect_ok(resp, rlen) ? -2 : 0;
    free(resp);
    return ok;
}
static int l3_mcounter_get(sc_t *sc, uint16_t index, uint32_t *value) {
    if (!value) return -1;
    uint8_t pt[1 + 2];
    pt[0] = CMD_ID_MCOUNTER_GET;
    pt[1] = (uint8_t)(index & 0xFF);
    pt[2] = (uint8_t)((index >> 8) & 0xFF);
    uint8_t *resp=NULL; uint16_t rlen=0;
    int rc = l2_encrypted_exec(sc, pt, sizeof(pt), &resp, &rlen);
    if (rc) return rc;
    if (l3_expect_ok(resp, rlen)) { free(resp); return -2; }
    uint16_t pos = 1;
    if (rlen < pos + 4) { free(resp); return -3; }
    *value = (uint32_t)resp[pos] | ((uint32_t)resp[pos+1]<<8) |
             ((uint32_t)resp[pos+2]<<16) | ((uint32_t)resp[pos+3]<<24);
    free(resp);
    return 0;
}

// MAC_AND_DESTROY: [CMD, slot_le16, 'M', data...] → C3 | (maybe zeros) | mac...
static int l3_mac_and_destroy(sc_t *sc, uint16_t slot, const uint8_t *data, size_t len,
                              uint8_t **out, uint16_t *out_len) {
    uint8_t *pt = (uint8_t*)heap_caps_malloc(1 + MEM_ADDRESS_SIZE + 1 + len, MALLOC_CAP_8BIT);
    if (!pt) return -2;
    size_t off=0;
    pt[off++] = CMD_ID_MAC_AND_DESTROY;
    pt[off++] = (uint8_t)(slot & 0xFF);
    pt[off++] = (uint8_t)((slot >> 8) & 0xFF);
    pt[off++] = 'M';
    memcpy(&pt[off], data, len); off += len;

    uint8_t *resp=NULL; uint16_t rlen=0;
    int rc = l2_encrypted_exec(sc, pt, (uint16_t)off, &resp, &rlen);
    free(pt);
    if (rc) return rc;
    if (l3_expect_ok(resp, rlen)) { free(resp); return -3; }
    uint16_t pos = 1;
    if (rlen >= 4 && resp[1]==0 && resp[2]==0 && resp[3]==0) pos = 4;
    *out_len = rlen - pos;
    *out = (uint8_t*)heap_caps_malloc(*out_len ? *out_len : 1, MALLOC_CAP_8BIT);
    if(!*out){ free(resp); return -4; }
    memcpy(*out, resp+pos, *out_len);
    free(resp);
    return 0;
}
#endif

/* ─────────── Local ECDSA verify (P-256) ─────────── */
static int verify_p256_signature(const uint8_t *pub, size_t publen,
                                 const uint8_t hash32[32],
                                 const uint8_t r[32], const uint8_t s[32]) {
    int ret = 0;
    uint8_t xy[64];

    if (publen == 65 && pub[0] == 0x04) {
        memcpy(xy, pub + 1, 64);
    } else if (publen == 64) {
        memcpy(xy, pub, 64);
    } else {
        return -0x7F00; // unsupported pub format
    }

    mbedtls_ecp_group grp;  mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point Q;    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi R;          mbedtls_mpi S; mbedtls_mpi_init(&R); mbedtls_mpi_init(&S);

    MBEDTLS_MPI_CHK( mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary(&Q.MBEDTLS_PRIVATE(X), &xy[0],  32) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary(&Q.MBEDTLS_PRIVATE(Y), &xy[32], 32) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset(&Q.MBEDTLS_PRIVATE(Z), 1) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary(&R, r, 32) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary(&S, s, 32) );

    MBEDTLS_MPI_CHK( mbedtls_ecdsa_verify(&grp, hash32, 32, &Q, &R, &S) );

cleanup:
    mbedtls_mpi_free(&R); mbedtls_mpi_free(&S);
    mbedtls_ecp_point_free(&Q); mbedtls_ecp_group_free(&grp);
    return ret; // 0 == valid
}

/* ─────────── Local Ed25519 verify ─────────── */
static int verify_ed25519_signature(const uint8_t pub[32],
                                    const uint8_t *msg, size_t msg_len,
                                    const uint8_t R[32], const uint8_t S[32]) {
    uint8_t sig[64];
    memcpy(sig, R, 32);
    memcpy(sig + 32, S, 32);
    // Assuming ed25519.h provides ed25519_verify (standard API: returns 0 on success)
    // If using a different library (e.g., tweetnacl), adjust: crypto_sign_verify_detached(sig, 64, msg, msg_len, pub)
    return ed25519_verify(sig, msg, msg_len, pub);
}

/* ─────────── Demo task ─────────── */
static int get_stpub_from_x509(uint8_t stpub_out[32]) {
    // X.509 (4 × 128B chunks)
    uint8_t *blob = (uint8_t*)heap_caps_calloc(1, 4*128, MALLOC_CAP_8BIT);
    if (!blob) return -1;
    int total = get_info_x509_all(blob, 4*128);
    if (total < 10) { free(blob); return -2; }

    uint16_t cert_len = (uint16_t)blob[2] << 8 | (uint16_t)blob[3];
    if ((size_t)(10 + cert_len) > (size_t)total)
        cert_len = (total > 10) ? (total - 10) : 0;
    const uint8_t *cert = blob + 10;
    ESP_LOGI(TAG, "X509 length=%u bytes", cert_len);
    int rc = find_x25519_pub_in_cert(cert, cert_len, stpub_out);
    free(blob);
    return rc;
}

static int ensure_empty_then_generate(sc_t *sc, uint16_t slot, uint8_t curve) {
    uint8_t curve_out=0, origin=0, pub[96]; size_t publen=0;
    int rc_read = l3_ecc_key_read(sc, slot, &curve_out, &origin, pub, &publen);
    if (rc_read == 0 && (origin != 0 || publen > 0)) {
        ESP_LOGW(TAG, "Slot %u occupied (origin=%u, publen=%u) → erasing...", slot, origin, (unsigned)publen);
        int rc_erase = l3_ecc_key_erase(sc, slot);
        if (rc_erase != 0) {
            ESP_LOGE(TAG, "Erase failed rc=%d", rc_erase);
            return rc_erase ? rc_erase : -1;
        }
        vTaskDelay(pdMS_TO_TICKS(5));
    }
    return l3_ecc_key_generate(sc, slot, curve);
}

static int l3_get_random(sc_t *sc, uint8_t nbytes, uint8_t **out, uint16_t *out_len) {
    uint8_t pt[2] = { CMD_ID_RANDOM_VALUE, nbytes };
    dump_hex("Plain L3 command", pt, sizeof(pt));
    uint8_t *resp = NULL; uint16_t rlen = 0;
    int rc = l2_encrypted_exec(sc, pt, sizeof(pt), &resp, &rlen);
    if (rc != 0) return rc;
    if (rlen < 1 || resp[0] != CMD_RESULT_OK) { free(resp); return -2; }

    uint16_t pos = 1;
    if (rlen >= 4 && resp[1]==0 && resp[2]==0 && resp[3]==0) pos = 4;

    *out_len = (uint16_t)(rlen - pos);
    *out = (uint8_t*)heap_caps_malloc(*out_len ? *out_len : 1, MALLOC_CAP_8BIT);
    if(!*out){ free(resp); return -3; }
    memcpy(*out, resp + pos, *out_len);
    free(resp);
    return 0;
}

static void tropic_demo_task(void *arg)
{
    ESP_LOGI(TAG, "===============================================");
    ESP_LOGI(TAG, "TROPIC01 L2 + SC + TRNG + ECC (P-256 ECDSA + Ed25519 EdDSA)");
    ESP_LOGI(TAG, "Using pairing slot %u", (unsigned)PKEY_INDEX);
    ESP_LOGI(TAG, "===============================================");

    // CS pin
    gpio_config_t io_conf = { .pin_bit_mask=(1ULL<<PIN_NUM_CS), .mode=GPIO_MODE_OUTPUT,
                              .pull_up_en=GPIO_PULLUP_DISABLE, .pull_down_en=GPIO_PULLDOWN_DISABLE,
                              .intr_type=GPIO_INTR_DISABLE };
    gpio_config(&io_conf);
    cs_high();

    // SPI init
    spi_bus_config_t buscfg = { .mosi_io_num=PIN_NUM_MOSI, .miso_io_num=PIN_NUM_MISO, .sclk_io_num=PIN_NUM_CLK,
                                .quadwp_io_num=-1, .quadhd_io_num=-1, .max_transfer_sz=512 };
    spi_device_interface_config_t devcfg = { .clock_speed_hz=SPI_CLOCK_HZ, .mode=SPI_MODE,
                                             .spics_io_num=-1, .queue_size=1, .flags=0 };
    spi_bus_free(SPI_HOST_USED);
    ESP_ERROR_CHECK(spi_bus_initialize(SPI_HOST_USED, &buscfg, SPI_DMA_CH_AUTO));
    ESP_ERROR_CHECK(spi_bus_add_device(SPI_HOST_USED, &devcfg, &g_spi));
    ESP_LOGI(TAG, "SPI ready (host=%d, mode=%d, %d Hz)", SPI_HOST_USED, SPI_MODE, SPI_CLOCK_HZ);

    if (!tropic_wait_ready()) goto cleanup;

    // CHIPID
    uint8_t chipid[128] = {0};
    int len = get_info_chipid(chipid, sizeof(chipid));
    if (len > 0) { dump_hex("CHIPID", chipid, (size_t)len); } else { goto cleanup; }

    // X.509 → STPUB
    uint8_t stpub[32];
    if (get_stpub_from_x509(stpub) != 0) goto cleanup;
    dump_hex("STPUB (X25519)", stpub, 32);

    // Secure Channel
    sc_t sc = {0};
    int rc = sc_start(PKEY_INDEX, SH_PRIV, SH_PUB, stpub, &sc);
    if (rc != 0) { ESP_LOGE(TAG, "Secure Channel handshake failed rc=%d", rc); goto cleanup; }
    ESP_LOGI(TAG, "Secure Channel established.");

    ESP_LOGI(TAG, "Re-checking READY after SC...");
    if (!tropic_wait_ready()) goto cleanup;
    vTaskDelay(pdMS_TO_TICKS(10));

    // TRNG: 32 bytes
    uint8_t *rnd = NULL; uint16_t rnd_len = 0;
    if (l3_get_random(&sc, 32, &rnd, &rnd_len) == 0) {
        dump_hex("TROPIC01 TRNG", rnd, rnd_len);
        free(rnd);
    }

    // ── ECC demo (P-256 ECDSA): slot 0
    const uint16_t slot_p256 = 0;
    ESP_LOGI(TAG, "Ensuring slot %u is empty, then generating P-256 key ...", slot_p256);
    rc = ensure_empty_then_generate(&sc, slot_p256, ECC_CURVE_P256);
    if (rc != 0) { ESP_LOGE(TAG, "ECC_KEY_GENERATE failed rc=%d", rc); goto cleanup; }

    // Read back pubkey
    uint8_t curve=0, origin=0; uint8_t pub[96]; size_t publen=0;
    rc = l3_ecc_key_read(&sc, slot_p256, &curve, &origin, pub, &publen);
    if (rc != 0) { ESP_LOGE(TAG, "ECC_KEY_READ failed rc=%d", rc); goto cleanup; }
    ESP_LOGI(TAG, "ECC_KEY_READ: curve=0x%02X (1=P256,2=Ed25519), origin=%u, publen=%u",
             curve, origin, (unsigned)publen);
    dump_hex("Public key (raw from device)", pub, publen);

    // Build a message hash
    const char *msg_p256 = "hello-tropic01-ecdsa";
    uint8_t hash32[32]; sha256_once((const uint8_t*)msg_p256, strlen(msg_p256), hash32);
    dump_hex("SHA-256(msg)", hash32, 32);

    // Ask TROPIC01 to sign
    uint8_t R[32], S[32];
    rc = l3_ecdsa_sign(&sc, slot_p256, hash32, R, S);
    if (rc != 0) { ESP_LOGE(TAG, "ECDSA_SIGN failed rc=%d", rc); goto cleanup; }
    dump_hex("ECDSA r", R, 32);
    dump_hex("ECDSA s", S, 32);

    // Verify (mbedTLS)
    rc = verify_p256_signature(pub, publen, hash32, R, S);
    if (rc == 0) ESP_LOGI(TAG, "ECDSA signature verified OK (mbedTLS, P-256).");
    else         ESP_LOGE(TAG, "ECDSA verification FAILED (rc=%d).", rc);

    // ── ECC demo (Ed25519 EdDSA): slot 1
    const uint16_t slot_ed25519 = 1;
    ESP_LOGI(TAG, "Ensuring slot %u is empty, then generating Ed25519 key ...", slot_ed25519);
    rc = ensure_empty_then_generate(&sc, slot_ed25519, ECC_CURVE_ED25519);
    if (rc != 0) { ESP_LOGE(TAG, "ECC_KEY_GENERATE failed rc=%d", rc); goto cleanup; }

    // Read back pubkey (for Ed25519, expect 32 bytes raw)
    memset(pub, 0, sizeof(pub)); publen = 0;
    rc = l3_ecc_key_read(&sc, slot_ed25519, &curve, &origin, pub, &publen);
    if (rc != 0) { ESP_LOGE(TAG, "ECC_KEY_READ failed rc=%d", rc); goto cleanup; }
    ESP_LOGI(TAG, "ECC_KEY_READ: curve=0x%02X (1=P256,2=Ed25519), origin=%u, publen=%u",
             curve, origin, (unsigned)publen);
    dump_hex("Public key (raw from device)", pub, publen);

    // Message to sign (EdDSA signs the message directly, no hash)
    const char *msg_ed25519 = "hello-tropic01-eddsa";
    dump_hex("Message", (const uint8_t*)msg_ed25519, strlen(msg_ed25519));

    // Ask TROPIC01 to sign
    rc = l3_eddsa_sign(&sc, slot_ed25519, (const uint8_t*)msg_ed25519, strlen(msg_ed25519), R, S);
    if (rc != 0) { ESP_LOGE(TAG, "EDDSA_SIGN failed rc=%d", rc); goto cleanup; }
    dump_hex("EdDSA R", R, 32);
    dump_hex("EdDSA S", S, 32);

    // Verify (ed25519 lib)
    rc = verify_ed25519_signature(pub, (const uint8_t*)msg_ed25519, strlen(msg_ed25519), R, S);
    if (rc == 0) ESP_LOGI(TAG, "EdDSA signature verified OK (ed25519 lib).");
    else         ESP_LOGE(TAG, "EdDSA verification FAILED (rc=%d).", rc);

    // Optional: demonstrate GET_LOG
    char *logtxt = NULL;
    if (l2_get_log(&logtxt) == 0 && logtxt) {
        ESP_LOGI(TAG, "DEVICE LOG:\n%s", logtxt);
        free(logtxt);
    }

    // Optional: abort SC and reboot to maintenance (parity with Python)
    // (Uncomment if desired)
    // l2_encrypted_session_abort();
    // l2_startup_req(STARTUP_MAINTENANCE_REBOOT);

cleanup:
    if (g_spi) { spi_bus_remove_device(g_spi); g_spi = NULL; }
    spi_bus_free(SPI_HOST_USED);
    gpio_set_pull_mode(PIN_NUM_MOSI, GPIO_PULLUP_ONLY);
    gpio_set_pull_mode(PIN_NUM_MISO, GPIO_PULLUP_ONLY);
    gpio_set_pull_mode(PIN_NUM_CLK,  GPIO_PULLUP_ONLY);
    ESP_LOGI(TAG, "Done.");
    vTaskDelete(NULL);
}

void app_main(void)
{
    const int STACK = 24 * 1024; // bumped for extra features
    xTaskCreatePinnedToCore(tropic_demo_task, "tropic_demo", STACK, NULL, 5, NULL, 0);
}
