#pragma once
// hue_emu.h - emulacio "Philips Hue" per al pont Hue (2026-10-11). Tot el que el pont demana a una bombeta real i el
// cactus no tenia:
//   - atributs de fabricant 0x100B als clusters Basic/Identify/Level/Scenes i atributs estandard de gamut al Color,
//   - clusters propietaris 0xFC01/0xFC03/0xFC04 i Touchlink 0x1000 al descriptor simple,
//   - estat compacte Hue (0xFC03 attr 0x0002: flags u16 + camps) i la comanda d'estat 0xFC03 cmd 0x00,
//   - la comanda de fabricant "guardar escena amb estat" (Scenes 0x0005, manuf 0x100B, cmd 0x02).
// Es C (no C++) perque el handler raw necessita les capçaleres de zboss.
#include <stdbool.h>
#include <stdint.h>

#include "esp_zigbee_core.h"
#include "aps/esp_zigbee_aps.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HUE_MANUF_CODE 0x100B
#define HUE_CLUSTER_FC01 0xFC01
#define HUE_CLUSTER_FC03 0xFC03
#define HUE_CLUSTER_FC04 0xFC04
#define HUE_CLUSTER_TOUCHLINK 0x1000
#define HUE_PROFILE_ZLL 0xC05E
#define HUE_DEVICE_EXTENDED_COLOR_LIGHT 0x0210

/// Afegeix a un cluster estandard (0x0000, 0x0003, 0x0005, 0x0008, 0x0300) els atributs que el pont llegeix a una
/// Hue real. Cridar abans d'esp_zb_device_register.
void esphome_hue_add_cluster_attrs(uint16_t cluster_id, esp_zb_attribute_list_t *attr_list);

/// Crea el llistat d'atributs d'un cluster propietari Hue (0xFC01/0xFC03/0xFC04) o Touchlink (0x1000).
esp_zb_attribute_list_t *esphome_hue_create_cluster(uint16_t cluster_id);

/// Handler "raw" ZCL (esp_zb_raw_command_handler_register): intercepta Scenes manuf cmd 0x02 (guardar escena amb
/// estat) i la desa a la taula d'escenes de la pila. Torna true si ha consumit la trama.
bool esphome_hue_raw_handler(uint8_t bufid);

/// Aplica una comanda d'estat Hue (0xFC03 cmd 0x00): payload = flags u16 LE + camps (on, nivell, CT, xy, transicio).
/// Nomes des de la tasca Zigbee (callback de la pila).
void esphome_hue_apply_state(uint8_t endpoint, const uint8_t *payload, uint16_t len);

/// Recalcula l'atribut d'estat 0xFC03/0x0002 a partir d'OnOff/Level/Color. Des de la tasca Zigbee o amb el lock.
void esphome_hue_refresh_state(uint8_t endpoint);

/// Basic manuf 0x0021 = segons des de l'arrencada. Amb el lock.
void esphome_hue_update_uptime(uint8_t endpoint, uint32_t seconds);

// ---- Hue Entertainment (Ambilight + Hue) ----
// Trama: [comptador u16][08 0F 00 04][entrades de 7 bytes: adreca u16, u16 (5 bits baixos flags, 11 alts
// brillantor), 24 bits (x 12 baixos, y 12 alts)]. Arriba unicast pel cluster 0xFC01 cmd 0x01 (si som el proxy) o pel
// broadcast Inter-PAN del proxy (cluster 0x1000, profile 0xC05E, cmd 0x02).
#define HUE_ENT_X_MAX 0.7347f  // hipotesi d'escala (convertidors de zigbee2mqtt per al gradient Hue)
#define HUE_ENT_Y_MAX 0.8264f
typedef struct {
  uint32_t uni, ip_raw, ip_aps, cmd3, mine, other;
  uint32_t ip_wrap, wrap_calls;  // Inter-PAN interceptat a zb_intrp_data_indication (--wrap)
  uint16_t seq, bri, x12, y12;
  uint8_t flags, entries, session;
  uint32_t last_mine_ms;
} esphome_hue_ent_stats_t;
/// path: 0 = unicast 0xFC01 cmd 0x01, 1 = Inter-PAN pel handler raw, 2 = Inter-PAN pel hook APS,
/// 3 = Inter-PAN interceptat al linker (--wrap=zb_intrp_data_indication). Tasca Zigbee.
void esphome_hue_ent_frame(const uint8_t *payload, uint16_t len, uint8_t path);
/// 0xFC01 cmd 0x03 (broadcast de sessio): [00][estat][comptador u16][08 0F]. Tasca Zigbee.
void esphome_hue_ent_session(const uint8_t *payload, uint16_t len);
/// Copia dels comptadors i de l'ultim color propi (segur des de qualsevol tasca).
void esphome_hue_ent_stats(esphome_hue_ent_stats_t *out);
/// true si ha arribat color per a nosaltres fa menys de timeout_ms.
bool esphome_hue_ent_active(uint32_t timeout_ms);
/// Ultim color propi: brillantor 0..1 i xy CIE 1931 (escala HUE_ENT_X/Y_MAX). Torna false si encara no n'hi ha.
bool esphome_hue_ent_color(float *bri01, float *x, float *y);
/// Valor de diagnostic per a l'atribut Basic manuf 0x0021 (el pont el llegeix cada ~minut i el sniffer el veu):
/// 0 si encara no ha arribat res d'entreteniment; si no, 0xD0000000 | flags camins (bit24 unicast, bit25 raw,
/// bit26 aps, bit27 wrap) | min(crides wrap,255) << 16 | min(meves, 65535).
uint32_t esphome_hue_ent_diag(void);
// ---- Degradats de les escenes Hue (Scenes 0x0005, fabricant 0x100B, cmd 0x00) ----
// El pont envia (groupcast al grup de la llum) una escena amb degradat: [grup u16][escena u8][..][L][n<<4][3 bytes]
// [n colors de 3 bytes: x 12 bits baixos, y 12 alts], amb L = 1 + 3 * (n + 1). Arriba ~1,5 s despres del Recall
// Scene de la mateixa escena (captura 2026-10-12 10:56). El component la guarda per (grup, escena) i l'aplica en el
// Recall (o si el Recall ha arribat fa menys de 5 s). serial s'incrementa a cada degradat aplicat.
#define HUE_GRAD_MAX 9
typedef struct {
  uint8_t n;
  float x[HUE_GRAD_MAX], y[HUE_GRAD_MAX];
  uint32_t serial;
} esphome_hue_gradient_t;
void esphome_hue_gradient_get(esphome_hue_gradient_t *out);
/// Cridar des del handler de Recall Scene (tasca Zigbee).
void esphome_hue_scene_recalled(uint16_t group, uint8_t scene);

/// Taula de totes les entrades de l'ultima trama (fins a HUE_ENT_MAX_ENTRIES): per pintar segments amb el color
/// d'altres llums de l'area (Lola Lamp). addr 0 = l'entrada propia.
#define HUE_ENT_MAX_ENTRIES 16
bool esphome_hue_ent_frame_active(uint32_t timeout_ms);  // alguna trama (encara que no porti entrada propia)
bool esphome_hue_ent_color_of(uint16_t addr, float *bri01, float *x, float *y);
/// Copia la taula (adreca, brillantor 0..2047, x12, y12); torna el nombre d'entrades.
uint8_t esphome_hue_ent_table(uint16_t *addr, uint16_t *bri, uint16_t *x12, uint16_t *y12, uint8_t max);

/// Endpoint que emula la Hue (per al hook APS). Cridar abans de registrar el hook.
void esphome_hue_init(uint8_t endpoint);

/// Hook APSDE-DATA.indication (esp_zb_aps_data_indication_handler_register): respon la ZDO Simple_Desc_req del
/// nostre endpoint amb el descriptor d'una LCT015 real (profile ZLL 0xC05E, device 0x0210, v2, clusters en el seu
/// ordre i OTA de sortida). La pila no pot tenir l'endpoint a 0xC05E (descartaria les trames HA del pont), pero el
/// pont vol veure 0xC05E al descriptor per fer el cami "Hue". Torna true si ha respost (la pila no ho processa).
bool esphome_hue_aps_indication(esp_zb_apsde_data_ind_t ind);

#ifdef __cplusplus
}
#endif
