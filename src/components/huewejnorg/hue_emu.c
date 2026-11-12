// hue_emu.c - emulacio "Philips Hue" (vegeu hue_emu.h). Valors copiats de les LCT015 1.116.12 del
// pont capturades el 2026-10-11 amb el sniffer zigbeelogger.
#include "hue_emu.h"

#include <stdio.h>
#include <string.h>

#include "zboss_api.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"

// Els ESP_LOGx de l'IDF no es veuen en aquest build (CONFIG_LOG_DEFAULT_LEVEL_ERROR): formategem i ho passem al
// logger d'ESPHome per un pont en C++ (zigbee.cpp).
extern void esphome_hue_log(const char *msg);
// Implementat a zigbee.cpp: fa el mateix que el callback SET_ATTR_VALUE de la pila (on_value del YAML + refresc Hue).
extern void esphome_hue_attr_changed(uint8_t ep, uint16_t cluster, uint16_t attr_id, uint8_t type, void *value,
                                     uint8_t size);
#define HUE_LOGI(...)                      \
  do {                                     \
    char b_[200];                          \
    snprintf(b_, sizeof(b_), __VA_ARGS__); \
    esphome_hue_log(b_);                   \
  } while (0)

static uint8_t s_hue_ep = 11;

void esphome_hue_init(uint8_t endpoint) { s_hue_ep = endpoint; }

// ---- valors d'atribut (la pila els copia en afegir-los; els RW els reescriu el pont) ----
static uint8_t s_basic_0020[] = {9, '0', ':', 'P', 'W', 'R', 'O', 'N', '@', '0'};  // char string "0:PWRON@0"
static uint32_t s_basic_0021 = 0;                                                  // u32: segons des de l'arrencada
static uint32_t s_basic_0053 = 0;                                                  // u32 RW: el pont hi escriu 0x01788D76
static uint8_t s_basic_0054[16] = {0};                                             // clau 128 bits RW: el pont hi escriu 16 bytes
static uint16_t s_ident_0000 = 0x000B;                                             // map16
static uint16_t s_level_0003 = 1000;                                               // u16
static uint32_t s_scenes_0001 = 3;                                                 // map32
static uint16_t s_color_4000 = 0;                                                  // EnhancedCurrentHue
static uint16_t s_color_manuf_xy[2] = {0xFFFF, 0xFFFF};  // Color manuf 0x0003/0x0004 (la real respon 0xFFFF)
static uint8_t s_color_4002 = 0;                                                   // ColorLoopActive
static uint16_t s_gamut[6] = {45317, 20204, 11141, 45875, 10040, 3116};            // ColorPoint R/G/B X,Y (gamut C)
static uint8_t s_fc01_0000 = 0x0B;                                                 // map8
static uint32_t s_fc03_0001 = 7;                                                   // map32
static uint8_t s_fc03_0002[1 + 32];  // octet string d'estat: reservem 32 bytes (els sets posteriors son mes curts)
static uint16_t s_fc03_0010 = 1;                                                   // map16
static uint64_t s_fc03_0011 = 0x1C0EULL;                                           // map64
static uint32_t s_fc03_0012 = 0;                                                   // map32

static void add_manuf(esp_zb_attribute_list_t *l, uint16_t cid, uint16_t aid, uint8_t type, uint8_t access, void *v) {
  esp_err_t r = esp_zb_cluster_add_manufacturer_attr(l, cid, aid, HUE_MANUF_CODE, type, access, v);
  if (r != ESP_OK)
    HUE_LOGI("AVIS: atribut manuf 0x%04X/0x%04X: %s", cid, aid, esp_err_to_name(r));
}

static void add_std(esp_zb_attribute_list_t *l, uint16_t cid, uint16_t aid, uint8_t type, uint8_t access, void *v) {
  esp_err_t r = esp_zb_cluster_update_attr(l, aid, v);
  if (r == ESP_OK)
    return;
  r = esp_zb_cluster_add_attr(l, cid, aid, type, access, v);
  if (r != ESP_OK)
    HUE_LOGI("AVIS: atribut 0x%04X/0x%04X: %s", cid, aid, esp_err_to_name(r));
}

void esphome_hue_add_cluster_attrs(uint16_t cluster_id, esp_zb_attribute_list_t *l) {
  const uint8_t RO = ESP_ZB_ZCL_ATTR_ACCESS_READ_ONLY;
  const uint8_t RW = ESP_ZB_ZCL_ATTR_ACCESS_READ_WRITE;
  switch (cluster_id) {
    case ESP_ZB_ZCL_CLUSTER_ID_BASIC:
      add_manuf(l, cluster_id, 0x0020, ESP_ZB_ZCL_ATTR_TYPE_CHAR_STRING, RO, s_basic_0020);
      add_manuf(l, cluster_id, 0x0021, ESP_ZB_ZCL_ATTR_TYPE_U32, RO, &s_basic_0021);
      add_manuf(l, cluster_id, 0x0053, ESP_ZB_ZCL_ATTR_TYPE_U32, RW, &s_basic_0053);
      add_manuf(l, cluster_id, 0x0054, ESP_ZB_ZCL_ATTR_TYPE_128_BIT_KEY, RW, s_basic_0054);
      break;
    case ESP_ZB_ZCL_CLUSTER_ID_IDENTIFY:
      add_manuf(l, cluster_id, 0x0000, ESP_ZB_ZCL_ATTR_TYPE_16BITMAP, RO, &s_ident_0000);
      break;
    case ESP_ZB_ZCL_CLUSTER_ID_LEVEL_CONTROL:
      add_manuf(l, cluster_id, 0x0003, ESP_ZB_ZCL_ATTR_TYPE_U16, RO, &s_level_0003);
      break;
    case ESP_ZB_ZCL_CLUSTER_ID_SCENES:
      add_manuf(l, cluster_id, 0x0001, ESP_ZB_ZCL_ATTR_TYPE_32BITMAP, RO, &s_scenes_0001);
      break;
    case ESP_ZB_ZCL_CLUSTER_ID_COLOR_CONTROL:
      add_std(l, cluster_id, 0x4000, ESP_ZB_ZCL_ATTR_TYPE_U16, RO, &s_color_4000);
      add_manuf(l, cluster_id, 0x0003, ESP_ZB_ZCL_ATTR_TYPE_U16, RO, &s_color_manuf_xy[0]);
      add_manuf(l, cluster_id, 0x0004, ESP_ZB_ZCL_ATTR_TYPE_U16, RO, &s_color_manuf_xy[1]);
      add_std(l, cluster_id, 0x4002, ESP_ZB_ZCL_ATTR_TYPE_U8, RO, &s_color_4002);
      add_std(l, cluster_id, 0x0032, ESP_ZB_ZCL_ATTR_TYPE_U16, RO, &s_gamut[0]);
      add_std(l, cluster_id, 0x0033, ESP_ZB_ZCL_ATTR_TYPE_U16, RO, &s_gamut[1]);
      add_std(l, cluster_id, 0x0036, ESP_ZB_ZCL_ATTR_TYPE_U16, RO, &s_gamut[2]);
      add_std(l, cluster_id, 0x0037, ESP_ZB_ZCL_ATTR_TYPE_U16, RO, &s_gamut[3]);
      add_std(l, cluster_id, 0x003A, ESP_ZB_ZCL_ATTR_TYPE_U16, RO, &s_gamut[4]);
      add_std(l, cluster_id, 0x003B, ESP_ZB_ZCL_ATTR_TYPE_U16, RO, &s_gamut[5]);
      break;
    default:
      break;
  }
}

esp_zb_attribute_list_t *esphome_hue_create_cluster(uint16_t cluster_id) {
  const uint8_t RO = ESP_ZB_ZCL_ATTR_ACCESS_READ_ONLY;
  if (cluster_id == HUE_CLUSTER_TOUCHLINK) {
    // Touchlink (ZLL commissioning) amb la configuracio per defecte de la pila: nomes per sortir al descriptor.
    return esp_zb_touchlink_commissioning_cluster_create(NULL);
  }
  esp_zb_attribute_list_t *l = esp_zb_zcl_attr_list_create(cluster_id);
  switch (cluster_id) {
    case HUE_CLUSTER_FC01:
      add_manuf(l, cluster_id, 0x0000, ESP_ZB_ZCL_ATTR_TYPE_8BITMAP, RO, &s_fc01_0000);
      break;
    case HUE_CLUSTER_FC03:
      memset(s_fc03_0002, 0, sizeof(s_fc03_0002));
      s_fc03_0002[0] = 32;  // longitud maxima reservada; esphome_hue_refresh_state() hi posa l'estat real
      add_manuf(l, cluster_id, 0x0001, ESP_ZB_ZCL_ATTR_TYPE_32BITMAP, RO, &s_fc03_0001);
      add_manuf(l, cluster_id, 0x0002, ESP_ZB_ZCL_ATTR_TYPE_OCTET_STRING, RO, s_fc03_0002);
      add_manuf(l, cluster_id, 0x0010, ESP_ZB_ZCL_ATTR_TYPE_16BITMAP, RO, &s_fc03_0010);
      add_manuf(l, cluster_id, 0x0011, ESP_ZB_ZCL_ATTR_TYPE_64BITMAP, RO, &s_fc03_0011);
      add_manuf(l, cluster_id, 0x0012, ESP_ZB_ZCL_ATTR_TYPE_32BITMAP, RO, &s_fc03_0012);
      break;
    default:  // 0xFC04: nomes ha d'apareixer al descriptor simple
      break;
  }
  return l;
}

// ---- estat compacte Hue: flags u16 LE + camps en ordre de bit ----
//   bit0 on/off (1 B), bit1 nivell (1 B), bit2 temperatura de color (u16 mireds), bit3 xy (u16 x, u16 y),
//   bit4 transicio (u16, 1/10 s), bits 5-7 efectes/gradient (no els fem servir).
#define HUE_F_ON 0x0001
#define HUE_F_LEVEL 0x0002
#define HUE_F_CT 0x0004
#define HUE_F_XY 0x0008
#define HUE_F_TRANSITION 0x0010

static bool get_u8(uint8_t ep, uint16_t cluster, uint16_t attr, uint8_t *out) {
  esp_zb_zcl_attr_t *a = esp_zb_zcl_get_attribute(ep, cluster, ESP_ZB_ZCL_CLUSTER_SERVER_ROLE, attr);
  if (a == NULL || a->data_p == NULL)
    return false;
  *out = *(uint8_t *) a->data_p;
  return true;
}

static bool get_u16(uint8_t ep, uint16_t cluster, uint16_t attr, uint16_t *out) {
  esp_zb_zcl_attr_t *a = esp_zb_zcl_get_attribute(ep, cluster, ESP_ZB_ZCL_CLUSTER_SERVER_ROLE, attr);
  if (a == NULL || a->data_p == NULL)
    return false;
  memcpy(out, a->data_p, 2);
  return true;
}

static void set_attr(uint8_t ep, uint16_t cluster, uint16_t attr, uint8_t type, uint8_t size, void *v) {
  esp_zb_zcl_status_t st = esp_zb_zcl_set_attribute_val(ep, cluster, ESP_ZB_ZCL_CLUSTER_SERVER_ROLE, attr, v, false);
  if (st != ESP_ZB_ZCL_STATUS_SUCCESS) {
    HUE_LOGI("AVIS: set 0x%04X/0x%04X -> estat %d", cluster, attr, st);
    return;
  }
  // Un set local no passa pel callback SET_ATTR_VALUE: avisem el component (on_value del YAML + estat compacte).
  esphome_hue_attr_changed(ep, cluster, attr, type, v, size);
}

void esphome_hue_refresh_state(uint8_t ep) {
  uint8_t on = 0, level = 254, mode = 1;
  uint16_t x = 0, y = 0, ct = 366;
  get_u8(ep, ESP_ZB_ZCL_CLUSTER_ID_ON_OFF, ESP_ZB_ZCL_ATTR_ON_OFF_ON_OFF_ID, &on);
  get_u8(ep, ESP_ZB_ZCL_CLUSTER_ID_LEVEL_CONTROL, ESP_ZB_ZCL_ATTR_LEVEL_CONTROL_CURRENT_LEVEL_ID, &level);
  get_u8(ep, ESP_ZB_ZCL_CLUSTER_ID_COLOR_CONTROL, ESP_ZB_ZCL_ATTR_COLOR_CONTROL_COLOR_MODE_ID, &mode);
  get_u16(ep, ESP_ZB_ZCL_CLUSTER_ID_COLOR_CONTROL, ESP_ZB_ZCL_ATTR_COLOR_CONTROL_CURRENT_X_ID, &x);
  get_u16(ep, ESP_ZB_ZCL_CLUSTER_ID_COLOR_CONTROL, ESP_ZB_ZCL_ATTR_COLOR_CONTROL_CURRENT_Y_ID, &y);
  get_u16(ep, ESP_ZB_ZCL_CLUSTER_ID_COLOR_CONTROL, ESP_ZB_ZCL_ATTR_COLOR_CONTROL_COLOR_TEMPERATURE_ID, &ct);
  uint8_t blob[1 + 2 + 1 + 1 + 4];
  uint16_t flags = HUE_F_ON | HUE_F_LEVEL | (mode == 2 ? HUE_F_CT : HUE_F_XY);
  uint8_t n = 0;
  blob[++n] = flags & 0xFF;
  blob[++n] = flags >> 8;
  blob[++n] = on ? 1 : 0;
  blob[++n] = level;
  if (mode == 2) {
    blob[++n] = ct & 0xFF;
    blob[++n] = ct >> 8;
  } else {
    blob[++n] = x & 0xFF;
    blob[++n] = x >> 8;
    blob[++n] = y & 0xFF;
    blob[++n] = y >> 8;
  }
  blob[0] = n;  // longitud de l'octet string
  esp_zb_zcl_status_t st = esp_zb_zcl_set_manufacturer_attribute_val(ep, HUE_CLUSTER_FC03, ESP_ZB_ZCL_CLUSTER_SERVER_ROLE,
                                                                     HUE_MANUF_CODE, 0x0002, blob, false);
  if (st != ESP_ZB_ZCL_STATUS_SUCCESS)
    HUE_LOGI("AVIS: estat 0xFC03/0x0002 -> %d", st);
}

void esphome_hue_update_uptime(uint8_t ep, uint32_t seconds) {
  s_basic_0021 = seconds;
  esp_zb_zcl_set_manufacturer_attribute_val(ep, ESP_ZB_ZCL_CLUSTER_ID_BASIC, ESP_ZB_ZCL_CLUSTER_SERVER_ROLE,
                                            HUE_MANUF_CODE, 0x0021, &s_basic_0021, false);
}

// Decodifica flags + camps. Torna false si el payload es massa curt.
typedef struct {
  uint16_t flags;
  uint8_t on, level;
  uint16_t ct, x, y, transition;
} hue_state_t;

static bool parse_state(const uint8_t *p, uint16_t n, hue_state_t *s) {
  if (n < 2)
    return false;
  memset(s, 0, sizeof(*s));
  s->flags = p[0] | (p[1] << 8);
  uint16_t pos = 2;
  if (s->flags & HUE_F_ON) {
    if (pos + 1 > n)
      return false;
    s->on = p[pos++];
  }
  if (s->flags & HUE_F_LEVEL) {
    if (pos + 1 > n)
      return false;
    s->level = p[pos++];
  }
  if (s->flags & HUE_F_CT) {
    if (pos + 2 > n)
      return false;
    s->ct = p[pos] | (p[pos + 1] << 8);
    pos += 2;
  }
  if (s->flags & HUE_F_XY) {
    if (pos + 4 > n)
      return false;
    s->x = p[pos] | (p[pos + 1] << 8);
    s->y = p[pos + 2] | (p[pos + 3] << 8);
    pos += 4;
  }
  if (s->flags & HUE_F_TRANSITION) {
    if (pos + 2 > n)
      return false;
    s->transition = p[pos] | (p[pos + 1] << 8);
    pos += 2;
  }
  return true;
}

void esphome_hue_apply_state(uint8_t ep, const uint8_t *payload, uint16_t len) {
  hue_state_t s;
  if (!parse_state(payload, len, &s)) {
    HUE_LOGI("AVIS: 0xFC03 cmd 0x00: payload curt (%u bytes)", len);
    return;
  }
  HUE_LOGI("Hue estat: flags 0x%04X on=%u level=%u ct=%u xy=(%u,%u) trans=%u", s.flags, s.on, s.level, s.ct, s.x, s.y,
           s.transition);
  const uint16_t CC = ESP_ZB_ZCL_CLUSTER_ID_COLOR_CONTROL;
  if (s.flags & HUE_F_XY) {
    uint8_t m = 1;  // ColorMode / EnhancedColorMode = xy
    set_attr(ep, CC, ESP_ZB_ZCL_ATTR_COLOR_CONTROL_COLOR_MODE_ID, ESP_ZB_ZCL_ATTR_TYPE_8BIT_ENUM, 1, &m);
    set_attr(ep, CC, ESP_ZB_ZCL_ATTR_COLOR_CONTROL_ENHANCED_COLOR_MODE_ID, ESP_ZB_ZCL_ATTR_TYPE_8BIT_ENUM, 1, &m);
    set_attr(ep, CC, ESP_ZB_ZCL_ATTR_COLOR_CONTROL_CURRENT_X_ID, ESP_ZB_ZCL_ATTR_TYPE_U16, 2, &s.x);
    set_attr(ep, CC, ESP_ZB_ZCL_ATTR_COLOR_CONTROL_CURRENT_Y_ID, ESP_ZB_ZCL_ATTR_TYPE_U16, 2, &s.y);
  } else if (s.flags & HUE_F_CT) {
    uint8_t m = 2;
    set_attr(ep, CC, ESP_ZB_ZCL_ATTR_COLOR_CONTROL_COLOR_MODE_ID, ESP_ZB_ZCL_ATTR_TYPE_8BIT_ENUM, 1, &m);
    set_attr(ep, CC, ESP_ZB_ZCL_ATTR_COLOR_CONTROL_ENHANCED_COLOR_MODE_ID, ESP_ZB_ZCL_ATTR_TYPE_8BIT_ENUM, 1, &m);
    set_attr(ep, CC, ESP_ZB_ZCL_ATTR_COLOR_CONTROL_COLOR_TEMPERATURE_ID, ESP_ZB_ZCL_ATTR_TYPE_U16, 2, &s.ct);
  }
  if (s.flags & HUE_F_LEVEL)
    set_attr(ep, ESP_ZB_ZCL_CLUSTER_ID_LEVEL_CONTROL, ESP_ZB_ZCL_ATTR_LEVEL_CONTROL_CURRENT_LEVEL_ID,
             ESP_ZB_ZCL_ATTR_TYPE_U8, 1, &s.level);
  if (s.flags & HUE_F_ON) {
    bool on = s.on != 0;
    set_attr(ep, ESP_ZB_ZCL_CLUSTER_ID_ON_OFF, ESP_ZB_ZCL_ATTR_ON_OFF_ON_OFF_ID, ESP_ZB_ZCL_ATTR_TYPE_BOOL, 1, &on);
  }
  esphome_hue_refresh_state(ep);
}

// ---- Degradats d'escena ----
typedef struct {
  uint16_t group;
  uint8_t scene, n;
  uint16_t x12[HUE_GRAD_MAX], y12[HUE_GRAD_MAX];
} hue_grad_scene_t;
static hue_grad_scene_t s_grad_tab[4];
static uint8_t s_grad_next = 0;
static esphome_hue_gradient_t s_grad_active;
static uint16_t s_last_recall_group = 0;
static uint8_t s_last_recall_scene = 0;
static uint32_t s_last_recall_ms = 0;
static portMUX_TYPE s_grad_mux = portMUX_INITIALIZER_UNLOCKED;

static uint8_t parse_gradient(const uint8_t *p, uint16_t n, uint16_t *x12, uint16_t *y12) {
  for (uint16_t i = 0; i + 5 <= n; i++) {
    const uint8_t L = p[i], cnt = p[i + 1] >> 4;
    if (cnt >= 2 && cnt <= HUE_GRAD_MAX && L == 1 + 3 * (cnt + 1) && (uint16_t) (i + 1 + L) <= n) {
      const uint8_t *col = p + i + 5;  // [L][cnt<<4][3 bytes estil/reservats][colors]
      for (uint8_t k = 0; k < cnt; k++) {
        const uint32_t v = col[3 * k] | (col[3 * k + 1] << 8) | ((uint32_t) col[3 * k + 2] << 16);
        x12[k] = v & 0xFFF;
        y12[k] = (v >> 12) & 0xFFF;
      }
      return cnt;
    }
  }
  return 0;
}

static void grad_apply(const hue_grad_scene_t *g) {
  portENTER_CRITICAL(&s_grad_mux);
  s_grad_active.n = g->n;
  for (uint8_t k = 0; k < g->n; k++) {
    s_grad_active.x[k] = g->x12[k] / 4095.0f * HUE_ENT_X_MAX;
    s_grad_active.y[k] = g->y12[k] / 4095.0f * HUE_ENT_Y_MAX;
  }
  s_grad_active.serial++;
  portEXIT_CRITICAL(&s_grad_mux);
}

static void hue_gradient_scene(const uint8_t *p, uint16_t n) {
  if (p == NULL || n < 4)
    return;
  hue_grad_scene_t g;
  memset(&g, 0, sizeof(g));
  g.group = p[0] | (p[1] << 8);
  g.scene = p[2];
  g.n = parse_gradient(p + 3, (uint16_t) (n - 3), g.x12, g.y12);
  HUE_LOGI("Hue escena amb degradat: grup 0x%04X escena %u, %u punts", g.group, g.scene, g.n);
  if (g.n == 0)
    return;
  uint8_t slot = s_grad_next;
  for (uint8_t i = 0; i < 4; i++) {
    if (s_grad_tab[i].n && s_grad_tab[i].group == g.group && s_grad_tab[i].scene == g.scene) {
      slot = i;
      break;
    }
  }
  if (slot == s_grad_next)
    s_grad_next = (uint8_t) ((s_grad_next + 1) % 4);
  s_grad_tab[slot] = g;
  const uint32_t now = (uint32_t) (esp_timer_get_time() / 1000);
  if (s_last_recall_ms && s_last_recall_group == g.group && s_last_recall_scene == g.scene &&
      now - s_last_recall_ms < 5000) {
    HUE_LOGI("Hue: aplico el degradat (Recall de la mateixa escena fa %u ms)", (unsigned) (now - s_last_recall_ms));
    grad_apply(&g);
  }
}

void esphome_hue_scene_recalled(uint16_t group, uint8_t scene) {
  s_last_recall_group = group;
  s_last_recall_scene = scene;
  s_last_recall_ms = (uint32_t) (esp_timer_get_time() / 1000);
  for (uint8_t i = 0; i < 4; i++) {
    if (s_grad_tab[i].n && s_grad_tab[i].group == group && s_grad_tab[i].scene == scene) {
      HUE_LOGI("Hue: Recall de l'escena %u del grup 0x%04X amb degradat desat (%u punts)", scene, group,
               s_grad_tab[i].n);
      grad_apply(&s_grad_tab[i]);
      return;
    }
  }
}

void esphome_hue_gradient_get(esphome_hue_gradient_t *out) {
  portENTER_CRITICAL(&s_grad_mux);
  *out = s_grad_active;
  portEXIT_CRITICAL(&s_grad_mux);
}

// Handler "raw" ZCL: comandes de fabricant 0x100B (client -> servidor).
//  - Scenes 0x0005 cmd 0x02: "guardar escena amb estat" (grup u16, escena u8, estat compacte). Es el que el pont fa
//    servir per crear l'escena 1 del grup de la llum (captura: C0 76 01 | 1B 00 01 64 x y 04 00).
//  - Qualsevol altra comanda de fabricant en un cluster estandard (p. ex. Basic cmd 0xC0): la bombeta real contesta
//    amb una Default Response DE FABRICANT i UNSUP_CLUSTER_COMMAND (0x81), i ho fa encara que la comanda porti
//    "disable default response" (fc 0x15; ZCL 2.5.12: les respostes d'error s'envien sempre). La de la pila surt
//    sense codi de fabricant o no surt, el pont reintenta 4 cops i fa fora el dispositiu (14:48 i 15:12 del
//    2026-10-11).
//  - Clusters propietaris (>= 0xFC00): es deixen passar al callback de cluster custom (0xFC03 cmd 0x00).
bool esphome_hue_raw_handler(uint8_t bufid) {
  zb_zcl_parsed_hdr_t *hdr = ZB_BUF_GET_PARAM(bufid, zb_zcl_parsed_hdr_t);
  if (hdr->cluster_id == HUE_CLUSTER_TOUCHLINK) {
    // Stream d'entreteniment reemes pel proxy (Inter-PAN): ZLL cluster 0x1000, fabricant 0x100B, cmd 0x02.
    if (hdr->is_manuf_specific && hdr->manuf_specific == HUE_MANUF_CODE && !hdr->is_common_command &&
        hdr->cmd_id == 0x02) {
      esphome_hue_ent_frame(zb_buf_begin(bufid), (uint16_t) zb_buf_len(bufid), 1);
      zb_buf_free(bufid);
      return true;
    }
    return false;  // la resta de Touchlink, a la pila
  }
  if (!hdr->is_manuf_specific || hdr->manuf_specific != HUE_MANUF_CODE || hdr->is_common_command ||
      hdr->cmd_direction != ZB_ZCL_FRAME_DIRECTION_TO_SRV)
    return false;
  if (ZB_ZCL_PARSED_HDR_SHORT_DATA(hdr).source.addr_type != ZB_ZCL_ADDR_TYPE_SHORT)
    return false;
  const uint8_t ep = ZB_ZCL_PARSED_HDR_SHORT_DATA(hdr).dst_endpoint;
  const uint16_t src_addr = ZB_ZCL_PARSED_HDR_SHORT_DATA(hdr).source.u.short_addr;
  const uint8_t src_ep = ZB_ZCL_PARSED_HDR_SHORT_DATA(hdr).src_endpoint;
  const uint8_t seq = hdr->seq_number;
  const uint16_t prof = hdr->profile_id;
  const bool want_resp = !hdr->disable_default_response;
  const uint16_t cluster = hdr->cluster_id;
  const uint8_t cmd = hdr->cmd_id;
  // Groupcast o broadcast (adreca de desti diferent de la nostra): mai es respon (ZCL i bombetes reals).
  const bool unicast = ZB_ZCL_PARSED_HDR_SHORT_DATA(hdr).dst_addr == esp_zb_get_short_address();

  if (cluster == ESP_ZB_ZCL_CLUSTER_ID_SCENES && cmd == 0x00) {
    // Escena amb degradat (gradient). La desem i, si toca, l'apliquem.
    const uint8_t *gp = zb_buf_begin(bufid);
    const uint16_t gn = (uint16_t) zb_buf_len(bufid);
    const uint16_t group = gn >= 2 ? (gp[0] | (gp[1] << 8)) : 0;
    const uint8_t scene = gn >= 3 ? gp[2] : 0;
    hue_gradient_scene(gp, gn);
    if (unicast) {
      zb_uint8_t *ptr = ZB_ZCL_START_PACKET(bufid);
      ZB_ZCL_CONSTRUCT_SPECIFIC_COMMAND_RESP_FRAME_CONTROL_A(ptr, ZB_ZCL_FRAME_DIRECTION_TO_CLI, ZB_TRUE);
      ZB_ZCL_CONSTRUCT_COMMAND_HEADER_EXT(ptr, seq, ZB_TRUE, HUE_MANUF_CODE, 0x00);
      ZB_ZCL_PACKET_PUT_DATA8(ptr, (zb_uint8_t) ZB_ZCL_STATUS_SUCCESS);
      ZB_ZCL_PACKET_PUT_DATA16_VAL(ptr, group);
      ZB_ZCL_PACKET_PUT_DATA8(ptr, scene);
      ZB_ZCL_FINISH_PACKET(bufid, ptr)
      ZB_ZCL_SEND_COMMAND_SHORT(bufid, src_addr, ZB_APS_ADDR_MODE_16_ENDP_PRESENT, src_ep, ep, prof,
                                ESP_ZB_ZCL_CLUSTER_ID_SCENES, NULL);
    } else {
      zb_buf_free(bufid);
    }
    return true;
  }

  if (!(cluster == ESP_ZB_ZCL_CLUSTER_ID_SCENES && cmd == 0x02)) {
    if (cluster >= 0xFC00)
      return false;
    if (!unicast) {  // comanda de fabricant a un grup: no es contesta
      zb_buf_free(bufid);
      return true;
    }
    HUE_LOGI("Hue: comanda manuf 0x%04X cmd 0x%02X no implementada -> DefaultRsp manuf UNSUP_CLUSTER_COMMAND", cluster,
             cmd);
    ZB_ZCL_SEND_DEFAULT_RESP_MANUF_WITH_CB(bufid, src_addr, ZB_APS_ADDR_MODE_16_ENDP_PRESENT, src_ep, ep, prof, cluster,
                                           seq, cmd, 0x81, HUE_MANUF_CODE, ZB_ZCL_FRAME_DIRECTION_TO_CLI, NULL);
    return true;
  }

  uint8_t *p = zb_buf_begin(bufid);
  uint16_t n = (uint16_t) zb_buf_len(bufid);
  hue_state_t s;
  if (n < 3 || !parse_state(p + 3, n - 3, &s)) {
    HUE_LOGI("AVIS: Hue store scene: payload curt (%u bytes)", n);
    return false;
  }
  const uint16_t group = p[0] | (p[1] << 8);
  const uint8_t scene = p[2];

  uint8_t on = (s.flags & HUE_F_ON) ? (s.on ? 1 : 0) : 1;
  uint8_t level = (s.flags & HUE_F_LEVEL) ? s.level : 254;
  uint8_t colorxy[4] = {(uint8_t) (s.x & 0xFF), (uint8_t) (s.x >> 8), (uint8_t) (s.y & 0xFF), (uint8_t) (s.y >> 8)};
  esp_zb_zcl_scenes_extension_field_t color_f = {.cluster_id = ESP_ZB_ZCL_CLUSTER_ID_COLOR_CONTROL,
                                                 .length = 4,
                                                 .extension_field_attribute_value_list = colorxy,
                                                 .next = NULL};
  esp_zb_zcl_scenes_extension_field_t level_f = {.cluster_id = ESP_ZB_ZCL_CLUSTER_ID_LEVEL_CONTROL,
                                                 .length = 1,
                                                 .extension_field_attribute_value_list = &level,
                                                 .next = (s.flags & HUE_F_XY) ? &color_f : NULL};
  esp_zb_zcl_scenes_extension_field_t onoff_f = {.cluster_id = ESP_ZB_ZCL_CLUSTER_ID_ON_OFF,
                                                 .length = 1,
                                                 .extension_field_attribute_value_list = &on,
                                                 .next = &level_f};
  esp_err_t r = esp_zb_zcl_scenes_table_store(ep, group, scene, s.transition, &onoff_f);
  // El pont reenvia aquesta comanda cada 1,5 s mentre la llum reporta un estat diferent del de l escena (despres d un
  // reinici els atributs tornen als valors del YAML i el pont no torna a enviar el cmd 0x00): tractem el "guardar
  // escena" com a guardar I aplicar, que es el que la llum real acaba reportant.
  esphome_hue_apply_state(ep, p + 3, (uint16_t) (n - 3));
  HUE_LOGI("Hue store scene: ep %u grup 0x%04X escena %u flags 0x%04X on=%u level=%u xy=(%u,%u) ct=%u trans=%u -> %s", ep,
           group, scene, s.flags, on, level, s.x, s.y, s.ct, s.transition, esp_err_to_name(r));

  // Resposta: el pont reenvia la comanda cada 1,5 s tant si contestem amb Default Response com si callem (15:28-17:46).
  // El sniffer te punts cecs amb les bombetes noves, aixi que no sabem que contesta la real. Provem la resposta
  // especifica de cluster, com la Add Scene Response estandard: cmd 0x02 servidor->client, de fabricant, amb el mateix
  // TSN i payload [estat][grup u16][escena u8].
  (void) want_resp;
  {
    zb_uint8_t *ptr = ZB_ZCL_START_PACKET(bufid);
    ZB_ZCL_CONSTRUCT_SPECIFIC_COMMAND_RESP_FRAME_CONTROL_A(ptr, ZB_ZCL_FRAME_DIRECTION_TO_CLI, ZB_TRUE);
    ZB_ZCL_CONSTRUCT_COMMAND_HEADER_EXT(ptr, seq, ZB_TRUE, HUE_MANUF_CODE, 0x02);
    ZB_ZCL_PACKET_PUT_DATA8(ptr, (zb_uint8_t) (r == ESP_OK ? ZB_ZCL_STATUS_SUCCESS : ZB_ZCL_STATUS_FAIL));
    ZB_ZCL_PACKET_PUT_DATA16_VAL(ptr, group);
    ZB_ZCL_PACKET_PUT_DATA8(ptr, scene);
    ZB_ZCL_FINISH_PACKET(bufid, ptr)
    ZB_ZCL_SEND_COMMAND_SHORT(bufid, src_addr, ZB_APS_ADDR_MODE_16_ENDP_PRESENT, src_ep, ep, prof,
                              ESP_ZB_ZCL_CLUSTER_ID_SCENES, NULL);
    HUE_LOGI("Hue store scene: resposta cmd 0x02 (estat/grup/escena) tsn %u a 0x%04X", seq, src_addr);
  }
  return true;
}

// ---- descriptor simple "ZLL" per al pont ----
// Simple_Desc_req: [tsn][nwk lo][nwk hi][endpoint]. Simple_Desc_rsp: [tsn][status][nwk lo][nwk hi][len][descriptor].
// Descriptor = [ep][profile u16][device u16][version(4 bits)][n in][in u16...][n out][out u16...].
bool esphome_hue_aps_indication(esp_zb_apsde_data_ind_t ind) {
  if (ind.status == 0 && (ind.profile_id == HUE_PROFILE_ZLL || ind.cluster_id == HUE_CLUSTER_TOUCHLINK) &&
      ind.asdu != NULL && ind.asdu_length >= 3) {
    const uint8_t *a = ind.asdu;
    const uint8_t fc = a[0];
    uint16_t pos = 1, manuf = 0;
    if (fc & 0x04) {
      if (ind.asdu_length < 5)
        return false;
      manuf = a[1] | (a[2] << 8);
      pos = 3;
    }
    if (pos + 2 > ind.asdu_length)
      return false;
    const uint8_t cmd = a[pos + 1];
    pos += 2;
    if ((fc & 0x03) == 0x01 && manuf == HUE_MANUF_CODE && cmd == 0x02) {
      esphome_hue_ent_frame(a + pos, (uint16_t) (ind.asdu_length - pos), 2);
      return true;
    }
    return false;
  }
  if (ind.status != 0 || ind.profile_id != 0x0000 || ind.cluster_id != 0x0004 || ind.dst_endpoint != 0 ||
      ind.asdu_length < 4 || ind.asdu == NULL)
    return false;
  const uint8_t *q = ind.asdu;
  const uint16_t nwk = q[1] | (q[2] << 8);
  const uint8_t ep = q[3];
  if (ep != s_hue_ep || nwk != esp_zb_get_short_address())
    return false;
  static const uint16_t in_cl[] = {0x0000, 0x0003, 0x0004, 0x0005, 0x0006, 0x0008,
                                   0x1000, 0xFC03, 0xFC04, 0x0300, 0xFC01};  // ordre d'una LCT015 real
  static const uint16_t out_cl[] = {0x0019};
  static uint8_t buf[64];
  uint8_t n = 0;
  buf[n++] = q[0];  // tsn
  buf[n++] = 0x00;  // SUCCESS
  buf[n++] = nwk & 0xFF;
  buf[n++] = nwk >> 8;
  const uint8_t len_pos = n++;
  buf[n++] = ep;
  buf[n++] = HUE_PROFILE_ZLL & 0xFF;
  buf[n++] = HUE_PROFILE_ZLL >> 8;
  buf[n++] = HUE_DEVICE_EXTENDED_COLOR_LIGHT & 0xFF;
  buf[n++] = HUE_DEVICE_EXTENDED_COLOR_LIGHT >> 8;
  buf[n++] = 0x02;  // app device version 2
  buf[n++] = (uint8_t) (sizeof(in_cl) / sizeof(in_cl[0]));
  for (unsigned i = 0; i < sizeof(in_cl) / sizeof(in_cl[0]); i++) {
    buf[n++] = in_cl[i] & 0xFF;
    buf[n++] = in_cl[i] >> 8;
  }
  buf[n++] = (uint8_t) (sizeof(out_cl) / sizeof(out_cl[0]));
  for (unsigned i = 0; i < sizeof(out_cl) / sizeof(out_cl[0]); i++) {
    buf[n++] = out_cl[i] & 0xFF;
    buf[n++] = out_cl[i] >> 8;
  }
  buf[len_pos] = n - (len_pos + 1);

  esp_zb_apsde_data_req_t req;
  memset(&req, 0, sizeof(req));
  req.dst_addr_mode = ESP_ZB_APS_ADDR_MODE_16_ENDP_PRESENT;
  req.dst_addr.addr_short = ind.src_short_addr;
  req.dst_endpoint = 0;
  req.profile_id = 0x0000;
  req.cluster_id = 0x8004;
  req.src_endpoint = 0;
  req.asdu_length = n;
  req.asdu = buf;
  req.tx_options = 0;
  req.radius = 30;
  esp_err_t r = esp_zb_aps_data_request(&req);
  HUE_LOGI("Hue: Simple_Desc_rsp ZLL (0xC05E/0x0210 v2, %u in, %u out, %u bytes) a 0x%04X -> %s",
           (unsigned) (sizeof(in_cl) / sizeof(in_cl[0])), (unsigned) (sizeof(out_cl) / sizeof(out_cl[0])), n,
           ind.src_short_addr, esp_err_to_name(r));
  return true;
}

// ---- Hue Entertainment ----
static portMUX_TYPE s_ent_mux = portMUX_INITIALIZER_UNLOCKED;
static esphome_hue_ent_stats_t s_ent;
typedef struct {
  uint16_t addr, v;
  uint32_t col;
} hue_ent_entry_t;
static hue_ent_entry_t s_tab[HUE_ENT_MAX_ENTRIES];
static uint8_t s_tab_n = 0;
static uint16_t s_me = 0xFFFF;
static uint32_t s_last_frame_ms = 0;

void esphome_hue_ent_frame(const uint8_t *p, uint16_t n, uint8_t path) {
  if (p == NULL || n < 6)
    return;
  const uint16_t me = esp_zb_get_short_address();
  const uint16_t seq = p[0] | (p[1] << 8);
  const uint8_t entries = (uint8_t) ((n - 6) / 7);
  bool found = false;
  uint16_t v = 0;
  uint32_t col = 0;
  for (uint8_t i = 0; i < entries; i++) {
    const uint8_t *e = p + 6 + 7 * i;
    if ((uint16_t) (e[0] | (e[1] << 8)) == me) {
      v = e[2] | (e[3] << 8);
      col = e[4] | (e[5] << 8) | ((uint32_t) e[6] << 16);
      found = true;
      break;
    }
  }
  const uint32_t now = (uint32_t) (esp_timer_get_time() / 1000);
  portENTER_CRITICAL(&s_ent_mux);
  s_me = me;
  s_last_frame_ms = now;
  s_tab_n = entries > HUE_ENT_MAX_ENTRIES ? HUE_ENT_MAX_ENTRIES : entries;
  for (uint8_t i = 0; i < s_tab_n; i++) {
    const uint8_t *e = p + 6 + 7 * i;
    s_tab[i].addr = e[0] | (e[1] << 8);
    s_tab[i].v = e[2] | (e[3] << 8);
    s_tab[i].col = e[4] | (e[5] << 8) | ((uint32_t) e[6] << 16);
  }
  if (path == 0)
    s_ent.uni++;
  else if (path == 1)
    s_ent.ip_raw++;
  else if (path == 2)
    s_ent.ip_aps++;
  else
    s_ent.ip_wrap++;
  s_ent.seq = seq;
  s_ent.entries = entries;
  if (found) {
    s_ent.mine++;
    s_ent.flags = v & 0x1F;
    s_ent.bri = v >> 5;
    s_ent.x12 = col & 0xFFF;
    s_ent.y12 = (col >> 12) & 0xFFF;
    s_ent.last_mine_ms = now;
  } else {
    s_ent.other++;
  }
  portEXIT_CRITICAL(&s_ent_mux);
}

void esphome_hue_ent_session(const uint8_t *p, uint16_t n) {
  portENTER_CRITICAL(&s_ent_mux);
  s_ent.cmd3++;
  if (p != NULL && n >= 2)
    s_ent.session = p[1];
  portEXIT_CRITICAL(&s_ent_mux);
}

void esphome_hue_ent_stats(esphome_hue_ent_stats_t *out) {
  portENTER_CRITICAL(&s_ent_mux);
  *out = s_ent;
  portEXIT_CRITICAL(&s_ent_mux);
}

bool esphome_hue_ent_active(uint32_t timeout_ms) {
  const uint32_t now = (uint32_t) (esp_timer_get_time() / 1000);
  portENTER_CRITICAL(&s_ent_mux);
  const bool act = s_ent.mine > 0 && (now - s_ent.last_mine_ms) < timeout_ms;
  portEXIT_CRITICAL(&s_ent_mux);
  return act;
}

bool esphome_hue_ent_color(float *bri01, float *x, float *y) {
  portENTER_CRITICAL(&s_ent_mux);
  const uint32_t mine = s_ent.mine;
  const uint16_t b = s_ent.bri, xx = s_ent.x12, yy = s_ent.y12;
  portEXIT_CRITICAL(&s_ent_mux);
  if (mine == 0)
    return false;
  *bri01 = b / 2047.0f;
  *x = xx / 4095.0f * HUE_ENT_X_MAX;
  *y = yy / 4095.0f * HUE_ENT_Y_MAX;
  return true;
}

uint32_t esphome_hue_ent_diag(void) {
  esphome_hue_ent_stats_t st;
  esphome_hue_ent_stats(&st);
  if (st.uni + st.ip_raw + st.ip_aps + st.ip_wrap + st.wrap_calls == 0)
    return 0;
  uint32_t flags = (st.uni ? 1u : 0u) | (st.ip_raw ? 2u : 0u) | (st.ip_aps ? 4u : 0u) | (st.ip_wrap ? 8u : 0u);
  uint32_t calls = st.wrap_calls > 255 ? 255 : st.wrap_calls;
  uint32_t mine = st.mine > 65535 ? 65535 : st.mine;
  return 0xD0000000u | (flags << 24) | (calls << 16) | mine;
}

// ---- Inter-PAN interceptat al linker ----
// La pila no exporta cap hook per a l'Inter-PAN (zb_af_interpan_set_data_indication no hi es), i el broadcast del proxy
// no arriba ni al handler raw ni al hook APS (prova de les 20:55). Amb -Wl,--wrap=zb_intrp_data_indication (afegit
// pel __init__.py quan hue_emulation es actiu) cada trama Inter-PAN passa primer per aqui. Busquem la signatura
// cluster 0x1000 + profile 0xC05E (LE 00 10 5E C0) + ZCL especific de fabricant 0x100B, comanda 0x02, i despres la
// tornem a la pila sense tocar-la.
extern void __real_zb_intrp_data_indication(zb_uint8_t param);

void __wrap_zb_intrp_data_indication(zb_uint8_t param) {
  const uint8_t *b = (const uint8_t *) zb_buf_begin(param);
  const uint16_t n = (uint16_t) zb_buf_len(param);
  portENTER_CRITICAL(&s_ent_mux);
  s_ent.wrap_calls++;
  portEXIT_CRITICAL(&s_ent_mux);
  if (b != NULL) {
    for (uint16_t i = 0; i + 9 <= n && i < 48; i++) {
      if (b[i] == 0x00 && b[i + 1] == 0x10 && b[i + 2] == 0x5E && b[i + 3] == 0xC0) {
        const uint8_t fc = b[i + 4];
        if ((fc & 0x07) == 0x05 && b[i + 5] == 0x0B && b[i + 6] == 0x10 && b[i + 8] == 0x02)
          esphome_hue_ent_frame(b + i + 9, (uint16_t) (n - (i + 9)), 3);
        break;
      }
    }
  }
  __real_zb_intrp_data_indication(param);
}

bool esphome_hue_ent_frame_active(uint32_t timeout_ms) {
  const uint32_t now = (uint32_t) (esp_timer_get_time() / 1000);
  portENTER_CRITICAL(&s_ent_mux);
  const bool act = s_tab_n > 0 && (now - s_last_frame_ms) < timeout_ms;
  portEXIT_CRITICAL(&s_ent_mux);
  return act;
}

bool esphome_hue_ent_color_of(uint16_t addr, float *bri01, float *x, float *y) {
  bool found = false;
  uint16_t v = 0;
  uint32_t col = 0;
  portENTER_CRITICAL(&s_ent_mux);
  const uint16_t want = addr == 0 ? s_me : addr;
  for (uint8_t i = 0; i < s_tab_n; i++) {
    if (s_tab[i].addr == want) {
      v = s_tab[i].v;
      col = s_tab[i].col;
      found = true;
      break;
    }
  }
  portEXIT_CRITICAL(&s_ent_mux);
  if (!found)
    return false;
  *bri01 = (v >> 5) / 2047.0f;
  *x = (col & 0xFFF) / 4095.0f * HUE_ENT_X_MAX;
  *y = ((col >> 12) & 0xFFF) / 4095.0f * HUE_ENT_Y_MAX;
  return true;
}

uint8_t esphome_hue_ent_table(uint16_t *addr, uint16_t *bri, uint16_t *x12, uint16_t *y12, uint8_t max) {
  portENTER_CRITICAL(&s_ent_mux);
  const uint8_t n = s_tab_n < max ? s_tab_n : max;
  for (uint8_t i = 0; i < n; i++) {
    addr[i] = s_tab[i].addr;
    bri[i] = s_tab[i].v >> 5;
    x12[i] = s_tab[i].col & 0xFFF;
    y12[i] = (s_tab[i].col >> 12) & 0xFFF;
  }
  portEXIT_CRITICAL(&s_ent_mux);
  return n;
}
