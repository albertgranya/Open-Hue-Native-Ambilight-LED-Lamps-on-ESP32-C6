// zbsniffer.h — Sniffer IEEE 802.15.4 / Zigbee per a ESP32-C6 amb ESPHome (esp-idf), sense pila Zigbee.
//
// Usa el driver de radio cru de l'IDF (components/ieee802154, CONFIG_IEEE802154_ENABLED) en mode PROMISCU:
// rep TOTES les trames del canal (beacons, comandes MAC, ACKs, dades Zigbee) i les treu pel log de serie, una
// linia per trama, amb la capcalera MAC, la capcalera NWK Zigbee (sempre en clar) i, si la trama no va xifrada a
// nivell NWK, la capcalera APS (p. ex. el Transport Key d'un pont Hue: comanda APS xifrada amb la key-transport
// key derivada de la TC link key).
//
// DESXIFRAT (2026-09-29): amb la clau de xarxa carregada (set_key_hex; el cactus la imprimeix amb
// `log_network_key: true` en unir-se) les trames NWK xifrades es desxifren (AES-CCM*, mbedtls) i es decodifiquen
// NWK CMD / APS / ZDO / ZCL: descriptors (Node/Simple/Active EP), lectures d'atributs amb el seu estat, reports,
// Default Response, Mgmt_Leave... Aixi es veu l'entrevista del pont Hue a un dispositiu nou. El nonce fa servir
// la IEEE de l'aux header, que en una trama retransmesa es la del RELE (Zigbee xifra salt a salt).
//
// EVENTS: les coses importants (finestra d'unio oberta/tancada per PAN, Association Request/Response, Device
// Announce, Mgmt_Leave, NWK Leave, estats ZCL d'error) surten a mes en una linia WARN ">>> ..." facil de filtrar.
//
// Contracte del driver (esp_ieee802154.h): esp_ieee802154_receive_done() es crida en context d'ISR amb
//   frame[0] = Len, frame[1..Len] = MHR + payload; els 2 ultims bytes (on aniria el FCS) son RSSI i LQI.
// Per aixo la ISR nomes copia la trama a un anell (SPSC, sense locks) i crida receive_handle_done(); la
// decodificacio i el log es fan des del loop d'ESPHome (drain()).

#pragma once

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include "esp_attr.h"
#include "esp_ieee802154.h"
#include "esp_timer.h"
#include "esphome/core/log.h"
#include "mbedtls/ccm.h"

namespace zbsniff {

static const char *const TAG = "zbsniff";

// ── Anell de trames omplert des de la ISR ──
static const int RING_SIZE = 256;     // trames en cua: ~1,3 s d un canal saturat (~200 trames/s) sense perdre res
static const int FRAME_MAX = 128;     // PSDU maxim 127 + byte de longitud

struct Slot {
  uint8_t len;                        // bytes utils de data[] (MHR + payload, sense RSSI/LQI)
  uint8_t data[FRAME_MAX];
  int8_t rssi;
  uint8_t lqi;
  uint8_t channel;
  uint64_t ts_us;
};

inline Slot g_ring[RING_SIZE];
inline volatile uint32_t g_head = 0;   // escriu la ISR
inline volatile uint32_t g_tail = 0;   // llegeix el loop
inline volatile uint32_t g_dropped = 0;
inline volatile uint32_t g_received = 0;

struct Stats {
  uint32_t logged = 0, beacon = 0, data = 0, ack = 0, cmd = 0, other = 0, nwk_secured = 0, aps_cmd = 0;
  uint32_t decrypted = 0, mic_fail = 0;
  uint32_t last_received = 0, last_dropped = 0;
  bool running = false;
  uint8_t channel = 11;
  bool hex = true;
  uint64_t t0_us = 0;
  // estat de la trama que s'esta decodificant (el fa servir drain())
  double cur_t = 0;
  std::string plain_hex;              // payload NWK desxifrat (substitueix el hex xifrat al volcat)
  std::string events;                 // events d'aquesta trama (linia ">>>")
};
inline Stats st;

// ── Utilitats ──
inline std::string hex_bytes(const uint8_t *d, int n) {
  std::string s;
  char b[4];
  for (int i = 0; i < n; i++) {
    snprintf(b, sizeof b, "%02X", d[i]);
    s += b;
    if (i + 1 < n) s += ' ';
  }
  return s;
}
/// Adreca IEEE de 8 bytes tal com viatja (LSB primer) -> "AA:BB:...:HH" (MSB primer, com la mostren els ponts).
inline std::string ieee_str(const uint8_t *p) {
  char b[32];
  snprintf(b, sizeof b, "%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X", p[7], p[6], p[5], p[4], p[3], p[2], p[1], p[0]);
  return b;
}
inline uint16_t u16(const uint8_t *p) { return (uint16_t) (p[0] | (p[1] << 8)); }
inline uint32_t u32(const uint8_t *p) { return (uint32_t) p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24); }
inline std::string fmt(const char *f, ...) {
  char b[192];
  va_list ap;
  va_start(ap, f);
  vsnprintf(b, sizeof b, f, ap);
  va_end(ap);
  return b;
}
inline void note_event(const std::string &e) {
  if (!st.events.empty()) st.events += " | ";
  st.events += e;
}

// ── Clau de xarxa i desxifrat NWK (AES-CCM*) ──
inline uint8_t g_nwk_key[16];
inline bool g_have_key = false;
inline mbedtls_ccm_context g_ccm;
inline bool g_ccm_init = false;

/// Carrega la clau de xarxa des de text hex (32 digits; espais, ':' i '-' s'ignoren). Buit = sense desxifrat.
/// Al log nomes surt una empremta de 16 bits, mai la clau.
inline bool set_key_hex(const std::string &txt) {
  uint8_t k[16] = {0};
  int count = 0;
  for (char c : txt) {
    int v = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
    if (v < 0) continue;
    if (count < 32) {
      if (count % 2 == 0) k[count / 2] = (uint8_t) (v << 4);
      else k[count / 2] |= (uint8_t) v;
    }
    count++;
  }
  g_have_key = false;
  if (count == 0) {
    ESP_LOGI(TAG, "Sense clau de xarxa: les trames NWK xifrades es mostren en hex (entra-la amb l'accio set_nwk_key)");
    return false;
  }
  if (count != 32) {
    ESP_LOGE(TAG, "Clau de xarxa invalida: %d digits hex (en calen 32)", count);
    return false;
  }
  if (!g_ccm_init) { mbedtls_ccm_init(&g_ccm); g_ccm_init = true; }
  if (mbedtls_ccm_setkey(&g_ccm, MBEDTLS_CIPHER_ID_AES, k, 128) != 0) {
    ESP_LOGE(TAG, "mbedtls_ccm_setkey ha fallat");
    return false;
  }
  memcpy(g_nwk_key, k, 16);
  uint16_t fp = 0x1D0F;
  for (uint8_t b : k) fp = (uint16_t) ((fp << 5) ^ (fp >> 11) ^ b);
  g_have_key = true;
  ESP_LOGI(TAG, "Clau de xarxa carregada (empremta 0x%04X): es desxifren les trames NWK", fp);
  return true;
}

/// Desxifra el payload d'una trama NWK segura. p/n = trama NWK sencera; aux = offset del security control;
/// pl = offset del payload xifrat. Zigbee envia el camp de nivell a 0: el nivell real es 5 (ENC-MIC-32) i s'ha de
/// posar tant al nonce com a l'AAD. Nonce = IEEE font de l'aux header + frame counter (tal com viatgen) + security
/// control. AAD = capcalera NWK + aux header. Retorna la longitud en clar, o -1 si el MIC no quadra.
inline int nwk_decrypt(const uint8_t *p, int n, int aux, int pl, uint8_t *out) {
  uint8_t sc = p[aux];
  int level = sc & 0x07;
  if (level == 0) level = 5;
  static const int mic_tab[8] = {0, 4, 8, 16, 0, 4, 8, 16};
  int mic = mic_tab[level];
  if (level < 5 || !(sc & 0x20)) return -1;   // sense xifrat o sense extended nonce: no es pot
  int ct = n - pl - mic;
  if (ct < 0 || pl > FRAME_MAX) return -1;
  uint8_t sc_real = (uint8_t) ((sc & ~0x07) | level);
  uint8_t nonce[13];
  memcpy(nonce, p + aux + 5, 8);
  memcpy(nonce + 8, p + aux + 1, 4);
  nonce[12] = sc_real;
  uint8_t aad[FRAME_MAX];
  memcpy(aad, p, pl);
  aad[aux] = sc_real;
  int r = mbedtls_ccm_auth_decrypt(&g_ccm, (size_t) ct, nonce, 13, aad, (size_t) pl, p + pl, out, p + pl + ct, (size_t) mic);
  return r == 0 ? ct : -1;
}

// ── Noms ──
inline const char *zcl_status(uint8_t s) {
  switch (s) {
    case 0x00: return "SUCCESS";
    case 0x01: return "FAILURE";
    case 0x7E: return "NOT_AUTHORIZED";
    case 0x80: return "MALFORMED_COMMAND";
    case 0x81: return "UNSUP_CLUSTER_COMMAND";
    case 0x82: return "UNSUP_GENERAL_COMMAND";
    case 0x83: return "UNSUP_MANUF_CLUSTER_COMMAND";
    case 0x84: return "UNSUP_MANUF_GENERAL_COMMAND";
    case 0x85: return "INVALID_FIELD";
    case 0x86: return "UNSUPPORTED_ATTRIBUTE";
    case 0x87: return "INVALID_VALUE";
    case 0x88: return "READ_ONLY";
    case 0x89: return "INSUFFICIENT_SPACE";
    case 0x8B: return "NOT_FOUND";
    case 0x8C: return "UNREPORTABLE_ATTRIBUTE";
    case 0x8D: return "INVALID_DATA_TYPE";
    case 0xC3: return "UNSUPPORTED_CLUSTER";
  }
  return "?";
}
inline const char *zdo_status(uint8_t s) {
  switch (s) {
    case 0x00: return "SUCCESS";
    case 0x80: return "INV_REQUESTTYPE";
    case 0x81: return "DEVICE_NOT_FOUND";
    case 0x82: return "INVALID_EP";
    case 0x83: return "NOT_ACTIVE";
    case 0x84: return "NOT_SUPPORTED";
    case 0x85: return "TIMEOUT";
    case 0x86: return "NO_MATCH";
    case 0x88: return "NO_ENTRY";
    case 0x89: return "NO_DESCRIPTOR";
    case 0x8C: return "TABLE_FULL";
    case 0x8D: return "NOT_AUTHORIZED";
  }
  return "?";
}
inline std::string cluster_name(uint16_t c) {
  switch (c) {
    case 0x0000: return "Basic";
    case 0x0001: return "PowerCfg";
    case 0x0003: return "Identify";
    case 0x0004: return "Groups";
    case 0x0005: return "Scenes";
    case 0x0006: return "OnOff";
    case 0x0008: return "Level";
    case 0x0019: return "OTA";
    case 0x0021: return "GreenPower";
    case 0x0300: return "Color";
    case 0x0B05: return "Diagnostics";
    case 0x1000: return "Touchlink";
  }
  if (c >= 0xFC00) return fmt("Manuf0x%04X", c);
  return fmt("0x%04X", c);
}
inline const char *zdo_name(uint16_t c) {
  switch (c) {
    case 0x0000: return "NWK_addr_req";
    case 0x0001: return "IEEE_addr_req";
    case 0x0002: return "Node_Desc_req";
    case 0x0003: return "Power_Desc_req";
    case 0x0004: return "Simple_Desc_req";
    case 0x0005: return "Active_EP_req";
    case 0x0006: return "Match_Desc_req";
    case 0x0013: return "Device_annce";
    case 0x0021: return "Bind_req";
    case 0x0022: return "Unbind_req";
    case 0x0031: return "Mgmt_Lqi_req";
    case 0x0032: return "Mgmt_Rtg_req";
    case 0x0033: return "Mgmt_Bind_req";
    case 0x0034: return "Mgmt_Leave_req";
    case 0x0036: return "Mgmt_Permit_Joining_req";
    case 0x0038: return "Mgmt_NWK_Update_req";
    case 0x8000: return "NWK_addr_rsp";
    case 0x8001: return "IEEE_addr_rsp";
    case 0x8002: return "Node_Desc_rsp";
    case 0x8003: return "Power_Desc_rsp";
    case 0x8004: return "Simple_Desc_rsp";
    case 0x8005: return "Active_EP_rsp";
    case 0x8006: return "Match_Desc_rsp";
    case 0x8021: return "Bind_rsp";
    case 0x8022: return "Unbind_rsp";
    case 0x8031: return "Mgmt_Lqi_rsp";
    case 0x8032: return "Mgmt_Rtg_rsp";
    case 0x8033: return "Mgmt_Bind_rsp";
    case 0x8034: return "Mgmt_Leave_rsp";
    case 0x8036: return "Mgmt_Permit_Joining_rsp";
    case 0x8038: return "Mgmt_NWK_Update_notify";
  }
  return "ZDO?";
}
inline std::string attr_name(uint16_t cluster, uint16_t a) {
  if (cluster == 0x0000) {
    switch (a) {
      case 0x0000: return "ZCLVersion";
      case 0x0001: return "AppVersion";
      case 0x0002: return "StackVersion";
      case 0x0003: return "HWVersion";
      case 0x0004: return "ManufacturerName";
      case 0x0005: return "ModelId";
      case 0x0006: return "DateCode";
      case 0x0007: return "PowerSource";
      case 0x0008: return "GenericDeviceClass";
      case 0x0009: return "GenericDeviceType";
      case 0x000A: return "ProductCode";
      case 0x000B: return "ProductURL";
      case 0x4000: return "SWBuildID";
    }
  } else if (cluster == 0x0006) {
    switch (a) {
      case 0x0000: return "OnOff";
      case 0x4000: return "GlobalSceneControl";
      case 0x4001: return "OnTime";
      case 0x4002: return "OffWaitTime";
      case 0x4003: return "StartUpOnOff";
    }
  } else if (cluster == 0x0008) {
    switch (a) {
      case 0x0000: return "CurrentLevel";
      case 0x0011: return "OnLevel";
      case 0x000F: return "Options";
      case 0x4000: return "StartUpCurrentLevel";
    }
  } else if (cluster == 0x0300) {
    switch (a) {
      case 0x0000: return "CurrentHue";
      case 0x0001: return "CurrentSaturation";
      case 0x0003: return "CurrentX";
      case 0x0004: return "CurrentY";
      case 0x0007: return "ColorTemperature";
      case 0x0008: return "ColorMode";
      case 0x000F: return "Options";
      case 0x4001: return "EnhancedColorMode";
      case 0x400A: return "ColorCapabilities";
      case 0x400B: return "ColorTempMin";
      case 0x400C: return "ColorTempMax";
      case 0x4010: return "StartUpColorTemp";
    }
  }
  return fmt("0x%04X", a);
}
inline const char *global_cmd_name(uint8_t c) {
  switch (c) {
    case 0x00: return "ReadAttr";
    case 0x01: return "ReadAttrRsp";
    case 0x02: return "WriteAttr";
    case 0x03: return "WriteAttrUndivided";
    case 0x04: return "WriteAttrRsp";
    case 0x05: return "WriteAttrNoRsp";
    case 0x06: return "ConfigReporting";
    case 0x07: return "ConfigReportingRsp";
    case 0x08: return "ReadReportingCfg";
    case 0x09: return "ReadReportingCfgRsp";
    case 0x0A: return "ReportAttr";
    case 0x0B: return "DefaultRsp";
    case 0x0C: return "DiscoverAttr";
    case 0x0D: return "DiscoverAttrRsp";
    case 0x11: return "DiscoverCmdsRx";
    case 0x12: return "DiscoverCmdsRxRsp";
    case 0x13: return "DiscoverCmdsGen";
    case 0x14: return "DiscoverCmdsGenRsp";
    case 0x15: return "DiscoverAttrExt";
    case 0x16: return "DiscoverAttrExtRsp";
  }
  return "Global?";
}

/// Valor d'un atribut ZCL segons el seu tipus. used = bytes consumits, o -1 si el tipus no se sap mesurar.
inline std::string zcl_value(uint8_t type, const uint8_t *d, int n, int &used) {
  int size = -1;
  switch (type) {
    case 0x10: case 0x08: case 0x18: case 0x20: case 0x28: case 0x30: size = 1; break;
    case 0x09: case 0x19: case 0x21: case 0x29: case 0x31: case 0x38: case 0xE8: case 0xE9: size = 2; break;
    case 0x0A: case 0x1A: case 0x22: case 0x2A: size = 3; break;
    case 0x0B: case 0x1B: case 0x23: case 0x2B: case 0x39: case 0xE0: case 0xE1: case 0xE2: case 0xEA: size = 4; break;
    case 0x24: case 0x2C: size = 5; break;
    case 0x25: case 0x2D: size = 6; break;
    case 0x26: case 0x2E: size = 7; break;
    case 0x27: case 0x2F: case 0x3A: case 0xF0: size = 8; break;
    case 0xF1: size = 16; break;
    case 0x41: case 0x42:
      if (n < 1) { used = -1; return "?"; }
      if (d[0] == 0xFF) { used = 1; return "(invalid)"; }
      size = 1 + d[0];
      break;
    case 0x43: case 0x44:
      if (n < 2) { used = -1; return "?"; }
      size = 2 + u16(d);
      break;
    default: used = -1; return fmt("type0x%02X", type);
  }
  if (size > n) { used = -1; return "(truncat)"; }
  used = size;
  if (type == 0x42 || type == 0x44) {
    int off = type == 0x42 ? 1 : 2;
    return "\"" + std::string((const char *) d + off, size - off) + "\"";
  }
  if (type == 0x41 || type == 0x43) return "[" + hex_bytes(d + (type == 0x41 ? 1 : 2), size - (type == 0x41 ? 1 : 2)) + "]";
  if (type == 0x10) return d[0] ? "true" : "false";
  if (type == 0xF0) return ieee_str(d);
  if (size <= 4) {
    uint32_t v = 0;
    for (int i = size - 1; i >= 0; i--) v = (v << 8) | d[i];
    if (type >= 0x28 && type <= 0x2B) {   // amb signe
      int32_t sv = (int32_t) (v << (32 - 8 * size)) >> (32 - 8 * size);
      return fmt("%ld", (long) sv);
    }
    return fmt("%lu(0x%0*lX)", (unsigned long) v, size * 2, (unsigned long) v);
  }
  return hex_bytes(d, size);
}

// ── Decodificador ZDO (profile 0x0000) ──
inline std::string decode_zdo(uint16_t cluster, const uint8_t *p, int n) {
  if (n < 1) return " ZDO:(buit)";
  const uint8_t *d = p + 1;
  int dn = n - 1;
  std::string s = fmt(" ZDO:%s tsn=%u", zdo_name(cluster), p[0]);
  bool rsp = cluster & 0x8000;
  if (rsp && dn >= 1) s += fmt(" status=%s", zdo_status(d[0]));
  switch (cluster) {
    case 0x0000:
      if (dn >= 8) s += " ieee=" + ieee_str(d);
      break;
    case 0x0001: case 0x0002: case 0x0003: case 0x0005:
      if (dn >= 2) s += fmt(" addr=0x%04X", u16(d));
      break;
    case 0x0004:
      if (dn >= 3) s += fmt(" addr=0x%04X ep=%u", u16(d), d[2]);
      break;
    case 0x0006:
      if (dn >= 4) s += fmt(" addr=0x%04X profile=0x%04X", u16(d), u16(d + 2));
      break;
    case 0x0013:
      if (dn >= 11) {
        s += fmt(" nwk=0x%04X ieee=", u16(d)) + ieee_str(d + 2) + fmt(" cap=0x%02X", d[10]);
        note_event(fmt("Device_annce nwk=0x%04X ieee=", u16(d)) + ieee_str(d + 2));
      }
      break;
    case 0x0021: case 0x0022:
      if (dn >= 12) {
        s += " src=" + ieee_str(d) + fmt(" ep=%u cluster=%s", d[8], cluster_name(u16(d + 9)).c_str());
        if (d[11] == 0x03 && dn >= 21) s += " dst=" + ieee_str(d + 12) + fmt(" ep=%u", d[20]);
        else if (d[11] == 0x01 && dn >= 14) s += fmt(" group=0x%04X", u16(d + 12));
      }
      break;
    case 0x0034:
      if (dn >= 9) {
        s += " ieee=" + ieee_str(d) + fmt(" flags=0x%02X%s%s", d[8], (d[8] & 0x80) ? " REJOIN" : "", (d[8] & 0x40) ? " REMOVE-CHILDREN" : "");
        note_event("Mgmt_Leave_req (el pont fa fora) ieee=" + ieee_str(d) + fmt(" rejoin=%u", (d[8] & 0x80) ? 1 : 0));
      }
      break;
    case 0x0036:
      if (dn >= 1) {
        s += fmt(" duration=%us", d[0]);
        note_event(fmt("Mgmt_Permit_Joining_req %us", d[0]));
      }
      break;
    case 0x8000: case 0x8001:
      if (dn >= 11) s += " ieee=" + ieee_str(d + 1) + fmt(" nwk=0x%04X", u16(d + 9));
      break;
    case 0x8002:
      if (dn >= 16) {
        const uint8_t *nd = d + 3;
        int lt = nd[0] & 0x07;
        s += fmt(" addr=0x%04X type=%s macCap=0x%02X manuf=0x%04X maxBuf=%u maxIn=%u serverMask=0x%04X maxOut=%u descCap=0x%02X", u16(d + 1),
                 lt == 0 ? "coord" : lt == 1 ? "router" : lt == 2 ? "enddev" : "?", nd[2], u16(nd + 3), nd[5], u16(nd + 6), u16(nd + 8), u16(nd + 10), nd[12]);
      }
      break;
    case 0x8004:
      if (dn >= 12) {
        const uint8_t *sd = d + 4;
        int sl = d[3];
        s += fmt(" addr=0x%04X ep=%u profile=0x%04X devId=0x%04X ver=%u", u16(d + 1), sd[0], u16(sd + 1), u16(sd + 3), sd[5] & 0x0F);
        int o = 6;
        for (int dir = 0; dir < 2 && o < sl && 4 + o < dn; dir++) {
          int cnt = sd[o++];
          s += dir == 0 ? " in=[" : " out=[";
          for (int i = 0; i < cnt && o + 1 < sl && 4 + o + 1 < dn; i++, o += 2) s += (i ? "," : "") + cluster_name(u16(sd + o));
          s += "]";
        }
      }
      break;
    case 0x8005:
      if (dn >= 4) {
        s += fmt(" addr=0x%04X eps=[", u16(d + 1));
        for (int i = 0; i < d[3] && 4 + i < dn; i++) s += fmt("%s%u", i ? "," : "", d[4 + i]);
        s += "]";
      }
      break;
    case 0x8034:
      note_event(fmt("Mgmt_Leave_rsp status=%s", dn >= 1 ? zdo_status(d[0]) : "?"));
      break;
  }
  return s;
}

// ── Decodificador ZCL (qualsevol profile d'aplicacio: HA 0x0104, ZLL 0xC05E...) ──
inline std::string decode_zcl(uint16_t cluster, const uint8_t *p, int n) {
  if (n < 3) return " ZCL:(curt)";
  uint8_t fc = p[0];
  bool specific = (fc & 0x03) == 1, manuf = fc & 0x04, to_client = fc & 0x08;
  int o = 1;
  uint16_t mcode = 0;
  if (manuf) { if (n < 5) return " ZCL:(curt)"; mcode = u16(p + 1); o += 2; }
  uint8_t tsn = p[o++], cmd = p[o++];
  const uint8_t *d = p + o;
  int dn = n - o;
  std::string cl = cluster_name(cluster);
  std::string s = " ZCL[" + cl + (to_client ? " srv->cli" : " cli->srv") + (manuf ? fmt(" manuf=0x%04X", mcode) : std::string()) + fmt(" tsn=%u", tsn);
  if (specific) {
    s += fmt(" cmd=0x%02X", cmd);
    if (dn > 0) s += " args=" + hex_bytes(d, dn);
    return s + "]";
  }
  s += std::string(" ") + global_cmd_name(cmd);
  int i = 0;
  switch (cmd) {
    case 0x00:   // ReadAttr: llista d'atributs
      s += " ";
      for (; i + 1 < dn; i += 2) s += (i ? "," : "") + attr_name(cluster, u16(d + i));
      break;
    case 0x01:   // ReadAttrRsp: [attr status (type value)]
      while (i + 2 < dn + 0 && i + 3 <= dn) {
        uint16_t a = u16(d + i);
        uint8_t stt = d[i + 2];
        i += 3;
        s += " " + attr_name(cluster, a);
        if (stt != 0) {
          s += std::string(":") + zcl_status(stt);
          note_event(cl + " " + attr_name(cluster, a) + " -> " + zcl_status(stt));
          continue;
        }
        if (i >= dn) break;
        uint8_t type = d[i++];
        int used = 0;
        s += "=" + zcl_value(type, d + i, dn - i, used);
        if (used < 0) break;
        i += used;
      }
      break;
    case 0x02: case 0x03: case 0x05: case 0x0A:   // WriteAttr* / ReportAttr: [attr type value]
      while (i + 3 <= dn) {
        uint16_t a = u16(d + i);
        uint8_t type = d[i + 2];
        i += 3;
        int used = 0;
        s += " " + attr_name(cluster, a) + "=" + zcl_value(type, d + i, dn - i, used);
        if (used < 0) break;
        i += used;
      }
      break;
    case 0x04: case 0x07:   // WriteAttrRsp / ConfigReportingRsp: status [dir] attr ...
      if (dn == 1) { s += std::string(" ") + zcl_status(d[0]); break; }
      while (i < dn) {
        uint8_t stt = d[i++];
        if (cmd == 0x07 && i < dn) i++;   // direction
        if (i + 1 >= dn) { s += std::string(" ") + zcl_status(stt); break; }
        uint16_t a = u16(d + i);
        i += 2;
        s += " " + attr_name(cluster, a) + ":" + zcl_status(stt);
        if (stt != 0) note_event(cl + " " + global_cmd_name(cmd) + " " + attr_name(cluster, a) + " -> " + zcl_status(stt));
      }
      break;
    case 0x06:   // ConfigReporting: [dir attr type min max (change)] — el change nomes es llegeix per tipus analogics
      while (i + 1 <= dn) {
        uint8_t dir = d[i++];
        if (i + 1 >= dn) break;
        uint16_t a = u16(d + i);
        i += 2;
        if (dir == 0) {
          if (i + 5 > dn) break;
          uint8_t type = d[i];
          s += " " + attr_name(cluster, a) + fmt("(type0x%02X min=%u max=%u", type, u16(d + i + 1), u16(d + i + 3));
          i += 5;
          bool analog = (type >= 0x20 && type <= 0x2F) || (type >= 0x38 && type <= 0x3A) || (type >= 0xE0 && type <= 0xE2);
          if (analog) {
            int used = 0;
            s += " change=" + zcl_value(type, d + i, dn - i, used);
            if (used < 0) { s += ")"; break; }
            i += used;
          }
          s += ")";
        } else {
          if (i + 2 > dn) break;
          s += " " + attr_name(cluster, a) + fmt("(timeout=%u)", u16(d + i));
          i += 2;
        }
      }
      break;
    case 0x0B:   // DefaultRsp: cmd status
      if (dn >= 2) {
        s += fmt(" cmd=0x%02X ", d[0]) + zcl_status(d[1]);
        if (d[1] != 0) note_event(cl + fmt(" DefaultRsp cmd=0x%02X -> ", d[0]) + zcl_status(d[1]));
      }
      break;
    case 0x0C:   // DiscoverAttr: start max
      if (dn >= 3) s += " start=" + attr_name(cluster, u16(d)) + fmt(" max=%u", d[2]);
      break;
    case 0x0D:   // DiscoverAttrRsp: complete [attr type]
      if (dn >= 1) {
        s += fmt(" complete=%u", d[0]);
        for (i = 1; i + 2 < dn + 1 && i + 3 <= dn; i += 3) s += " " + attr_name(cluster, u16(d + i)) + fmt("(0x%02X)", d[i + 2]);
      }
      break;
    case 0x11: case 0x13: case 0x15:
      if (dn >= 2) s += fmt(" start=0x%04X max=%u", dn >= 3 ? u16(d) : d[0], d[dn - 1]);
      break;
    case 0x12: case 0x14:
      if (dn >= 1) { s += fmt(" complete=%u cmds=", d[0]); for (i = 1; i < dn; i++) s += fmt("%s0x%02X", i > 1 ? "," : "", d[i]); }
      break;
    default:
      if (dn > 0) s += " " + hex_bytes(d, dn);
      break;
  }
  return s + "]";
}

// ── Decodificador APS ──
inline std::string decode_aps(const uint8_t *p, int n) {
  if (n < 1) return " APS:(buit)";
  uint8_t fcf = p[0];
  int type = fcf & 0x03, delivery = (fcf >> 2) & 0x03;
  bool sec = fcf & 0x20, ack_req = fcf & 0x40, ext = fcf & 0x80;
  int o = 1;
  uint16_t cluster = 0xFFFF, profile = 0xFFFF;
  std::string s = " APS:";
  s += type == 0 ? "DATA" : type == 1 ? "CMD" : type == 2 ? "ACK" : "?";
  static const char *const deliv[] = {"unicast", "?", "broadcast", "group"};
  s += fmt(" %s", deliv[delivery]);
  if (type == 0 || type == 2) {
    if (delivery == 0 || delivery == 2) { if (o < n) s += fmt(" dstEp=%u", p[o]); o += 1; }
    if (delivery == 3) { if (o + 1 < n) s += fmt(" group=0x%04X", u16(p + o)); o += 2; }
    if (o + 3 < n) {
      cluster = u16(p + o);
      profile = u16(p + o + 2);
      s += fmt(" cluster=0x%04X profile=0x%04X", cluster, profile);
    }
    o += 4;
    if (o < n) s += fmt(" srcEp=%u", p[o]);
    o += 1;
  }
  if (o < n) s += fmt(" cnt=%u", p[o]);
  o += 1;
  if (ext) o += 1;   // extended header (fragmentacio)
  if (ack_req) s += " ackReq";
  if (sec) {
    if (o < n) {
      uint8_t sc = p[o];
      int keyid = (sc >> 3) & 0x03;
      bool ext_nonce = sc & 0x20;
      static const char *const keys[] = {"LINK/DATA key", "NWK key", "KEY-TRANSPORT key (derivada de la TC link key)", "KEY-LOAD key"};
      s += fmt(" SECURED[%s", keys[keyid]);
      o += 1;
      if (o + 3 < n) { s += fmt(" fc=%lu", (unsigned long) u32(p + o)); }
      o += 4;
      if (ext_nonce) { if (o + 7 < n) s += " src=" + ieee_str(p + o); o += 8; }
      if (keyid == 1) { if (o < n) s += fmt(" keySeq=%u", p[o]); o += 1; }
      s += "]";
      if (type == 1) s += " (comanda APS xifrada: Transport Key / Update Device / ...)";
    }
    return s;
  }
  if (type == 1 && o < n) {
    uint8_t cmd = p[o];
    static const char *const names[] = {"?", "?", "?", "?", "?", "TRANSPORT-KEY", "UPDATE-DEVICE", "REMOVE-DEVICE", "REQUEST-KEY", "SWITCH-KEY",
                                        "?", "?", "?", "?", "TUNNEL", "VERIFY-KEY", "CONFIRM-KEY"};
    s += fmt(" cmd=0x%02X %s", cmd, cmd < 17 ? names[cmd] : "?");
    if (cmd == 0x05 && o + 1 < n) {
      uint8_t kt = p[o + 1];
      s += fmt(" keyType=%u(%s)", kt, kt == 1 ? "standard NWK key" : kt == 3 ? "app link key" : kt == 4 ? "TC link key" : "?");
    }
    return s;
  }
  if (type == 0 && o <= n && cluster != 0xFFFF) {
    if (profile == 0x0000) s += decode_zdo(cluster, p + o, n - o);
    else s += decode_zcl(cluster, p + o, n - o);
  }
  return s;
}

// ── Comandes NWK (en clar o desxifrades) ──
inline std::string decode_nwk_cmd(const uint8_t *p, int n, uint16_t nwk_src) {
  if (n < 1) return "";
  uint8_t cmd = p[0];
  static const char *const names[] = {"?", "ROUTE-REQUEST", "ROUTE-REPLY", "NETWORK-STATUS", "LEAVE", "ROUTE-RECORD", "REJOIN-REQUEST",
                                      "REJOIN-RESPONSE", "LINK-STATUS", "NETWORK-REPORT", "NETWORK-UPDATE", "ED-TIMEOUT-REQUEST", "ED-TIMEOUT-RESPONSE"};
  std::string s = fmt(" cmd=0x%02X %s", cmd, cmd < 13 ? names[cmd] : "?");
  if (cmd == 0x04 && n >= 2) {
    s += fmt(" opts=0x%02X%s%s%s", p[1], (p[1] & 0x20) ? " REJOIN" : "", (p[1] & 0x40) ? " REQUEST" : "", (p[1] & 0x80) ? " REMOVE-CHILDREN" : "");
    note_event(fmt("NWK LEAVE de 0x%04X%s%s", nwk_src, (p[1] & 0x40) ? " (peticio: fa fora un altre node)" : " (el node se'n va)", (p[1] & 0x20) ? " rejoin" : ""));
  }
  if (cmd == 0x07 && n >= 4) s += fmt(" addr=0x%04X status=%u", u16(p + 1), p[3]);
  if (cmd == 0x03 && n >= 4) s += fmt(" status=0x%02X dst=0x%04X", p[1], u16(p + 2));
  if (cmd == 0x08 && n >= 2) s += fmt(" entries=%u", p[1] & 0x1F);
  return s;
}

// ── Decodificador NWK Zigbee ──
inline std::string decode_nwk(const uint8_t *p, int n) {
  if (n < 8) return fmt(" NWK:(massa curta, %d bytes)", n);
  uint16_t fcf = u16(p);
  int type = fcf & 0x03, ver = (fcf >> 2) & 0x0F;
  bool multicast = fcf & 0x0100, sec = fcf & 0x0200, src_route = fcf & 0x0400, dst_ieee = fcf & 0x0800, src_ieee = fcf & 0x1000;
  uint16_t dst = u16(p + 2), src = u16(p + 4);
  uint8_t radius = p[6], seq = p[7];
  int o = 8;
  std::string s = fmt(" NWK:%s v%d dst=0x%04X src=0x%04X radius=%u seq=%u", type == 0 ? "DATA" : type == 1 ? "CMD" : type == 3 ? "INTERPAN" : "?", ver, dst, src, radius, seq);
  if (dst_ieee) { if (o + 7 < n) s += " dstIEEE=" + ieee_str(p + o); o += 8; }
  if (src_ieee) { if (o + 7 < n) s += " srcIEEE=" + ieee_str(p + o); o += 8; }
  if (multicast) o += 1;
  if (src_route) { if (o < n) { int cnt = p[o]; o += 2 + 2 * cnt; s += fmt(" srcRoute(%d)", cnt); } }
  if (sec) {
    st.nwk_secured++;
    if (o >= n) return s;
    int aux = o;
    uint8_t sc = p[o];
    int keyid = (sc >> 3) & 0x03;
    bool ext_nonce = sc & 0x20;
    s += fmt(" SECURED[%s", keyid == 1 ? "NWK key" : keyid == 0 ? "link key" : keyid == 2 ? "key-transport" : "key-load");
    o += 1;
    if (o + 3 < n) s += fmt(" fc=%lu", (unsigned long) u32(p + o));
    o += 4;
    if (ext_nonce) { if (o + 7 < n) s += " src=" + ieee_str(p + o); o += 8; }
    if (keyid == 1) { if (o < n) s += fmt(" keySeq=%u", p[o]); o += 1; }
    s += "]";
    if (!g_have_key || keyid != 1 || o > n) return s;
    uint8_t out[FRAME_MAX];
    int len = nwk_decrypt(p, n, aux, o, out);
    if (len < 0) {
      st.mic_fail++;
      return s + " DEC:MIC-FAIL";
    }
    st.decrypted++;
    st.plain_hex = hex_bytes(out, len);
    s += " DEC:";
    if (type == 1) return s + decode_nwk_cmd(out, len, src);
    if (type == 0) return s + decode_aps(out, len);
    return s;
  }
  if (type == 1 && o < n) return s + decode_nwk_cmd(p + o, n - o, src);
  if (type == 0) return s + decode_aps(p + o, n - o);
  return s;
}

// ── Finestra d'unio per PAN (beacons assocPermit): per saber si el pont esta "cercant llums" ──
struct PanWindow { uint16_t pan = 0; bool used = false, open = false; double opened_t = 0, last_permit_t = 0; };
inline PanWindow g_pans[8];
inline void track_beacon(uint16_t pan, uint16_t src, bool permit, double t) {
  PanWindow *w = nullptr;
  for (auto &x : g_pans) if (x.used && x.pan == pan) { w = &x; break; }
  if (!w) for (auto &x : g_pans) if (!x.used) { x.used = true; x.pan = pan; w = &x; break; }
  if (!w) return;
  if (permit) {
    w->last_permit_t = t;
    if (!w->open) {
      w->open = true;
      w->opened_t = t;
      note_event(fmt("PAN 0x%04X: FINESTRA D'UNIO OBERTA (beacon assocPermit de 0x%04X)", pan, src));
    }
  } else if (w->open && t - w->last_permit_t > 5.0) {
    w->open = false;
    note_event(fmt("PAN 0x%04X: finestra d'unio TANCADA (oberta ~%.0f s)", pan, w->last_permit_t - w->opened_t));
  }
}

// ── Decodificador MAC 802.15.4 ──
inline std::string decode_mac(const uint8_t *p, int n, int &type_out) {
  type_out = -1;
  if (n < 3) return fmt("MAC:(massa curta, %d bytes)", n);
  uint16_t fcf = u16(p);
  int type = fcf & 0x07;
  type_out = type;
  bool sec = fcf & 0x0008, pending = fcf & 0x0010, ar = fcf & 0x0020, panc = fcf & 0x0040;
  int dam = (fcf >> 10) & 0x03, ver = (fcf >> 12) & 0x03, sam = (fcf >> 14) & 0x03;
  uint8_t seq = p[2];
  int o = 3;
  static const char *const types[] = {"BEACON", "DATA", "ACK", "CMD", "?", "?", "?", "?"};
  std::string s = fmt("MAC:%s seq=%u", types[type], seq);
  if (type == 2) return s;   // ACK: nomes FCF + seq
  uint16_t dst_pan = 0xFFFF, src_pan = 0xFFFF, src_short = 0xFFFF;
  std::string src_long;
  if (dam != 0) { if (o + 1 < n) dst_pan = u16(p + o); o += 2; s += fmt(" dstPAN=0x%04X", dst_pan); }
  if (dam == 2) { if (o + 1 < n) s += fmt(" dst=0x%04X", u16(p + o)); o += 2; }
  else if (dam == 3) { if (o + 7 < n) s += " dst=" + ieee_str(p + o); o += 8; }
  if (sam != 0 && !panc) { if (o + 1 < n) src_pan = u16(p + o); o += 2; s += fmt(" srcPAN=0x%04X", src_pan); }
  if (sam == 2) { if (o + 1 < n) { src_short = u16(p + o); s += fmt(" src=0x%04X", src_short); } o += 2; }
  else if (sam == 3) { if (o + 7 < n) { src_long = ieee_str(p + o); s += " src=" + src_long; } o += 8; }
  if (ar) s += " AR";
  if (pending) s += " PEND";
  if (ver == 2) s += " v2015";
  if (sec) return s + " MAC-SECURED";
  if (o > n) return s;
  const uint8_t *pl = p + o;
  int pn = n - o;
  if (type == 3 && pn >= 1) {
    uint8_t cmd = pl[0];
    static const char *const names[] = {"?", "ASSOCIATION-REQUEST", "ASSOCIATION-RESPONSE", "DISASSOCIATION", "DATA-REQUEST", "PANID-CONFLICT",
                                        "ORPHAN", "BEACON-REQUEST", "COORD-REALIGN", "GTS-REQUEST"};
    s += fmt(" cmd=0x%02X %s", cmd, cmd < 10 ? names[cmd] : "?");
    if (cmd == 0x01 && pn >= 2) {
      s += fmt(" cap=0x%02X[%s%s%s%s]", pl[1], (pl[1] & 0x02) ? "FFD " : "RFD ", (pl[1] & 0x04) ? "mains " : "batt ", (pl[1] & 0x08) ? "rxOnIdle " : "", (pl[1] & 0x80) ? "allocAddr" : "");
      note_event("ASSOCIATION-REQUEST de " + (src_long.empty() ? std::string("?") : src_long) + fmt(" a PAN 0x%04X", dst_pan));
    }
    if (cmd == 0x02 && pn >= 4) {
      uint8_t stt = pl[3];
      s += fmt(" shortAddr=0x%04X status=%u(%s)", u16(pl + 1), stt, stt == 0 ? "SUCCESS" : stt == 1 ? "PAN-AT-CAPACITY" : stt == 2 ? "PAN-ACCESS-DENIED" : "?");
      note_event(fmt("ASSOCIATION-RESPONSE shortAddr=0x%04X %s", u16(pl + 1), stt == 0 ? "SUCCESS" : "REBUTJADA"));
    }
    return s;
  }
  if (type == 0 && pn >= 4) {
    uint16_t ss = u16(pl);
    bool permit = ss & 0x8000;
    s += fmt(" beacon[%s%s]", (ss & 0x4000) ? "PANcoord " : "", permit ? "assocPermit" : "assocDENIED");
    track_beacon(src_pan, src_short, permit, st.cur_t);
    int bo = 4;   // superframe(2) + GTS(1) + pending(1) — si hi ha adreces pendents seria mes llarg
    int gts = pl[2] & 0x07, pend = (pl[3] & 0x07) + ((pl[3] >> 4) & 0x07);
    bo += gts ? 1 + 3 * gts : 0;
    bo += pend * 2;   // aproximat (curt); els llargs son 8
    if (pn >= bo + 15 && pl[bo] == 0x00) {
      const uint8_t *z = pl + bo;
      s += fmt(" ZB{profile=%u nwkVer=%u routerCap=%u depth=%u edCap=%u extPAN=%s updateId=%u}", z[1] & 0x0F, (z[1] >> 4) & 0x0F, (z[2] >> 2) & 1, (z[2] >> 3) & 0x0F, (z[2] >> 7) & 1, ieee_str(z + 3).c_str(), z[14]);
    }
    return s;
  }
  if (type == 1) return s + " |" + decode_nwk(pl, pn);
  return s;
}

// ── ISR del driver: copia a l'anell i allibera el buffer ──
extern "C" void IRAM_ATTR esp_ieee802154_receive_done(uint8_t *frame, esp_ieee802154_frame_info_t *frame_info) {
  g_received = g_received + 1;
  uint32_t head = g_head, next = (head + 1) % RING_SIZE;
  if (next == g_tail) {
    g_dropped = g_dropped + 1;
  } else {
    Slot &s = g_ring[head];
    int len = frame[0];
    int useful = len >= 2 ? len - 2 : 0;   // els 2 ultims bytes son RSSI/LQI (substitueixen el FCS)
    if (useful > FRAME_MAX - 1) useful = FRAME_MAX - 1;
    memcpy(s.data, frame + 1, useful);
    s.len = (uint8_t) useful;
    s.rssi = frame_info ? frame_info->rssi : 0;
    s.lqi = frame_info ? frame_info->lqi : 0;
    s.channel = frame_info ? frame_info->channel : 0;
    s.ts_us = frame_info ? frame_info->timestamp : (uint64_t) esp_timer_get_time();
    g_head = next;
  }
  esp_ieee802154_receive_handle_done(frame);
}

// ── API per al YAML ──
inline bool start(uint8_t channel, bool hex) {
  if (st.running) { ESP_LOGW(TAG, "sniffer ja en marxa (canal %u)", st.channel); return true; }
  if (channel < 11 || channel > 26) { ESP_LOGE(TAG, "canal %u invalid (11..26)", channel); return false; }
  st.channel = channel;
  st.hex = hex;
  esp_err_t e = esp_ieee802154_enable();
  if (e != ESP_OK) { ESP_LOGE(TAG, "esp_ieee802154_enable: %s", esp_err_to_name(e)); return false; }
  // Identitat que no casa amb res: aixi el filtre d'adreces mai fa match i el hardware no envia ACKs per nosaltres.
  static const uint8_t ext[8] = {0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE};
  esp_ieee802154_set_panid(0xFFFE);
  esp_ieee802154_set_short_address(0xFFFE);
  esp_ieee802154_set_extended_address(ext);
  esp_ieee802154_set_coordinator(false);
  esp_ieee802154_set_promiscuous(true);
  esp_ieee802154_set_rx_when_idle(true);
  esp_ieee802154_set_channel(channel);
  e = esp_ieee802154_receive();
  if (e != ESP_OK) { ESP_LOGE(TAG, "esp_ieee802154_receive: %s", esp_err_to_name(e)); return false; }
  st.running = true;
  st.t0_us = esp_timer_get_time();
  ESP_LOGI(TAG, "SNIFFER EN MARXA: canal %u, promiscu, hex=%s, desxifrat=%s. Una linia per trama: #n +t ch rssi lqi len | MAC | NWK | APS/ZDO/ZCL | hex",
           channel, hex ? "si" : "no", g_have_key ? "si" : "no (sense clau)");
  return true;
}

inline void stop() {
  if (!st.running) return;
  esp_ieee802154_disable();
  st.running = false;
  ESP_LOGI(TAG, "sniffer parat");
}

/// Treu al log les trames encuades. Cridar des d'un interval curt (5-20 ms).
inline void drain(int max_lines = 64) {
  int n = 0;
  while (g_tail != g_head && n < max_lines) {
    Slot s = g_ring[g_tail];
    g_tail = (g_tail + 1) % RING_SIZE;
    n++;
    st.logged++;
    st.cur_t = (double) (int64_t) (s.ts_us - st.t0_us) / 1e6;
    st.plain_hex.clear();
    st.events.clear();
    int type = -1;
    std::string mac = decode_mac(s.data, s.len, type);
    switch (type) { case 0: st.beacon++; break; case 1: st.data++; break; case 2: st.ack++; break; case 3: st.cmd++; break; default: st.other++; break; }
    double t = st.cur_t;
    if (type == 2 && !st.hex) {
      ESP_LOGI(TAG, "#%lu +%.3fs ch%u rssi=%d lqi=%u len=%u %s", (unsigned long) st.logged, t, s.channel, s.rssi, s.lqi, s.len, mac.c_str());
    } else if (!st.hex) {
      ESP_LOGI(TAG, "#%lu +%.3fs ch%u rssi=%d lqi=%u len=%u %s", (unsigned long) st.logged, t, s.channel, s.rssi, s.lqi, s.len, mac.c_str());
    } else if (!st.plain_hex.empty()) {
      // Trama desxifrada: el volcat es el payload NWK en clar (el xifrat no aporta res)
      ESP_LOGI(TAG, "#%lu +%.3fs ch%u rssi=%d lqi=%u len=%u %s | plain %s", (unsigned long) st.logged, t, s.channel, s.rssi, s.lqi, s.len, mac.c_str(),
               st.plain_hex.c_str());
    } else {
      ESP_LOGI(TAG, "#%lu +%.3fs ch%u rssi=%d lqi=%u len=%u %s | %s", (unsigned long) st.logged, t, s.channel, s.rssi, s.lqi, s.len, mac.c_str(),
               hex_bytes(s.data, s.len).c_str());
    }
    if (!st.events.empty()) ESP_LOGW(TAG, ">>> #%lu +%.3fs %s", (unsigned long) st.logged, t, st.events.c_str());
  }
}

/// Resum per segon (cridar cada 1 s): trames rebudes/perdudes des de l'ultim resum i acumulats per tipus.
inline void stats() {
  if (!st.running) return;
  uint32_t r = g_received, d = g_dropped;
  uint32_t dr = r - st.last_received, dd = d - st.last_dropped;
  st.last_received = r;
  st.last_dropped = d;
  if (dr == 0 && dd == 0) return;
  ESP_LOGI(TAG, "-- 1s: %lu trames/s (perdudes %lu) | total beacon=%lu data=%lu cmd=%lu ack=%lu altres=%lu nwkSecured=%lu desxifrades=%lu micFail=%lu | perdudes total %lu",
           (unsigned long) dr, (unsigned long) dd, (unsigned long) st.beacon, (unsigned long) st.data, (unsigned long) st.cmd, (unsigned long) st.ack,
           (unsigned long) st.other, (unsigned long) st.nwk_secured, (unsigned long) st.decrypted, (unsigned long) st.mic_fail, (unsigned long) d);
}

}  // namespace zbsniff
