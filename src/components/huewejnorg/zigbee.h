#pragma once

#include <map>
#include <tuple>
#include <deque>

#include "esp_zigbee_core.h"
#include "zboss_api.h"
#include "ha/esp_zigbee_ha_standard.h"
#include "esphome/core/component.h"
#include "esphome/core/automation.h"
#include "esphome/core/log.h"
#include "zigbee_helpers.h"
#include "hue_emu.h"  // API Hue/Entertainment visible tambe des dels lambdas del YAML

#ifdef USE_ZIGBEE_TIME
#include "time/zigbee_time.h"
#endif

namespace esphome {
namespace zigbee {

static const char *const TAG = "zigbee";

using device_params_t = struct DeviceParamsS {
  esp_zb_ieee_addr_t ieee_addr;
  uint8_t endpoint;
  uint16_t short_addr;
};

using zdo_info_user_ctx_t = struct ZdoInfoCtxS {
  uint8_t endpoint;
  uint16_t short_addr;
};

using zb_device_params_t = struct zb_device_params_s {
  esp_zb_ieee_addr_t ieee_addr;
  uint8_t endpoint;
  uint16_t short_addr;
};

/* Zigbee configuration */
#define INSTALLCODE_POLICY_ENABLE false /* enable the install code policy for security */
#define ED_AGING_TIMEOUT ESP_ZB_ED_AGING_TIMEOUT_64MIN
#define ED_KEEP_ALIVE 3000 /* 3000 millisecond */
#define MAX_CHILDREN 10
#define ESP_ZB_PRIMARY_CHANNEL_MASK \
  ESP_ZB_TRANSCEIVER_ALL_CHANNELS_MASK /* Zigbee primary channel mask use in the example */

#define ESP_ZB_DEFAULT_RADIO_CONFIG() \
  { .radio_mode = ZB_RADIO_MODE_NATIVE, }

#define ESP_ZB_DEFAULT_HOST_CONFIG() \
  { .host_connection_mode = ZB_HOST_CONNECTION_MODE_NONE, }

template<class T> T get_value_by_type(uint8_t attr_type, void *data);
uint8_t *get_zcl_string(const char *str, uint8_t max_size, bool use_max_size = false);

class ZigBeeAttribute;
class ZigbeeTime;

class ZigBeeComponent : public Component {
 public:
  void setup() override;
  void dump_config() override;
  // manual_start: true -> setup() NO inicializa la pila Zigbee; hay que llamar
  // a start() (accion YAML zigbee.start). Permite una ventana WiFi al arrancar
  // (OTA) y pasar despues a Zigbee con la radio ya libre.
  void set_manual_start(bool v) { this->manual_start_ = v; }
  void set_join_distributed(bool v) { this->join_distributed_ = v; }
  // log_network_key: escriu la clau de xarxa al log en unir-se (per al sniffer zigbeelogger). Nomes per depurar.
  void set_log_network_key(bool v) { this->log_network_key_ = v; }
  bool log_network_key() const { return this->log_network_key_; }
  void set_manufacturer_code(uint16_t c) { this->has_manufacturer_code_ = true; this->manufacturer_code_ = c; }
  void set_zcl_version(uint8_t v) { this->has_zcl_version_ = true; this->zcl_version_ = v; }
  void set_sw_build_id(const std::string &v) { this->sw_build_id_ = v; }
  // Emulacio Hue (hue_emu.h): nomes a l'endpoint indicat.
  void set_hue_emulation(bool v, uint8_t ep) {
    this->hue_emulation_ = v;
    this->hue_endpoint_ = ep;
  }
  bool hue_emulation() const { return this->hue_emulation_; }
  uint8_t hue_endpoint() const { return this->hue_endpoint_; }
  bool has_manufacturer_code() const { return this->has_manufacturer_code_; }
  uint16_t manufacturer_code() const { return this->manufacturer_code_; }
  void loop() override;
  // Inicializa la pila Zigbee y lanza el task. Idempotente: la segunda llamada
  // no hace nada. Con manual_start: false, setup() la llama en el arranque.
  void start();
  esp_err_t create_endpoint(uint8_t endpoint_id, esp_zb_ha_standard_devices_t device_id);
  void set_ident_time(uint8_t ident_time);
  // Override the Zigbee IEEE EUI-64 / 802.15.4 long address. The value is the
  // EUI-64 packed as a big-endian uint64_t (octet written first = most
  // significant byte). When unset, the factory MAC from efuse is used.
  void set_custom_mac(uint64_t mac) {
    this->has_custom_mac_ = true;
    this->custom_mac_ = mac;
  }
  // Override the trust center link key used when joining. The 128-bit key is
  // passed as two big-endian halves (hi = key[0..7], lo = key[8..15]). Needed
  // to join networks that don't use the default ZigBeeAlliance09 key, such as
  // a Philips Hue Bridge (which uses the ZLL commissioning link key).
  void set_trust_center_key(uint64_t hi, uint64_t lo) {
    this->has_tc_key_ = true;
    this->tc_key_hi_ = hi;
    this->tc_key_lo_ = lo;
  }
  // Mascara de canales Zigbee (bit N = canal N). Por defecto, todos los canales.
  // Fijar el canal acelera y hace fiable el join cuando hay redes solapadas.
  void set_channel_mask(uint32_t mask) { this->channel_mask_ = mask; }
  void set_basic_cluster(std::string model, std::string manufacturer, std::string date, uint8_t power,
                         uint8_t app_version, uint8_t stack_version, uint8_t hw_version, std::string area,
                         uint8_t physical_env);
  void add_cluster(uint8_t endpoint_id, uint16_t cluster_id, uint8_t role);
  void create_default_cluster(uint8_t endpoint_id, esp_zb_ha_standard_devices_t device_id);

  template<typename T>
  void add_attr(ZigBeeAttribute *attr, uint8_t endpoint_id, uint16_t cluster_id, uint8_t role, uint16_t attr_id,
                uint8_t attr_type, uint8_t attr_access, uint8_t max_size, T value);

  void set_report(ZigBeeAttribute *attribute, esp_zb_zcl_reporting_info_t reporting_info);
  void handle_attribute(esp_zb_device_cb_common_info_t info, esp_zb_zcl_attribute_t attribute);
  void searchBindings();
  static void bindingTableCb(const esp_zb_zdo_binding_table_info_t *table_info, void *user_ctx);

  // Olvida la red Zigbee. Si la pila esta corriendo hace factory reset (zboss
  // borra su NVRAM y reinicia). Si aun NO ha arrancado (ventana manual_start),
  // borra directamente la particion zb_storage para el proximo arranque.
  void reset();
  void report();

#ifdef USE_ZIGBEE_TIME
  ZigbeeTime *zt_{nullptr};
#endif

  void add_on_join_callback(std::function<void()> &&callback) { this->on_join_callback_.add(std::move(callback)); }
  void add_on_recall_scene_callback(std::function<void(uint16_t, uint8_t)> &&callback) {
    this->on_recall_scene_callback_.add(std::move(callback));
  }

  bool is_started() { return this->started_; }
  bool is_connected() { return this->connected_; }
  bool connected_ = false;
  bool started_ = false;

  // Les crides de la pila (tasca "Zigbee_main") cap al YAML es passen al loop principal amb defer(): els scripts del
  // YAML toquen llums/transicions, i fer-ho des d'una altra tasca corromp LightState::transformer_ (3 Guru Meditation
  // "Load access fault" a AddressableLightTransformer::apply() el 2026-10-11 amb el pont Hue). El scheduler
  // d'ESPHome (>= 2025.7) accepta defer() des d'altres tasques.
  void post_join() {
    this->defer([this]() { this->on_join_callback_.call(); });
  }
  void post_recall_scene(uint16_t group, uint8_t scene) {
    this->defer([this, group, scene]() { this->on_recall_scene_callback_.call(group, scene); });
  }

  CallbackManager<void()> on_join_callback_{};
  CallbackManager<void(uint16_t, uint8_t)> on_recall_scene_callback_{};
  std::deque<std::tuple<ZigBeeAttribute *, esp_zb_zcl_reporting_info_t>> reporting_list;
  struct {
    std::string model;
    std::string manufacturer;
    std::string date;
    uint8_t power;
    uint8_t app_version;
    uint8_t stack_version;
    uint8_t hw_version;
    std::string area;
    uint8_t physical_env;
  } basic_cluster_data_;
#ifdef ZB_ED_ROLE
  esp_zb_nwk_device_type_t device_role_ = ESP_ZB_DEVICE_TYPE_ED;
#else
  esp_zb_nwk_device_type_t device_role_ = ESP_ZB_DEVICE_TYPE_ROUTER;
#endif

 protected:
  esp_zb_attribute_list_t *create_ident_cluster_();
  // Afegeix als llistats d'atributs de l'endpoint Hue tot el que el pont espera (abans de device_register).
  void hue_prepare_clusters_();
  bool hue_emulation_ = false;
  uint8_t hue_endpoint_ = 11;
  bool hue_state_init_ = false;
  uint32_t hue_last_uptime_ms_ = 0;
  uint32_t hue_ent_log_ms_ = 0;
  uint32_t hue_ent_last_total_ = 0;
  uint32_t hue_ent_tab_log_ms_ = 0;
  esp_zb_attribute_list_t *create_basic_cluster_();
  template<typename T>
  void add_attr_(ZigBeeAttribute *attr, uint8_t endpoint_id, uint16_t cluster_id, uint8_t role, uint16_t attr_id,
                 uint8_t attr_type, uint8_t attr_access, T *value_p);
  std::map<uint8_t, esp_zb_ha_standard_devices_t> endpoint_list_;
  std::map<uint8_t, esp_zb_cluster_list_t *> cluster_list_;
  std::map<std::tuple<uint8_t, uint16_t, uint8_t>, esp_zb_attribute_list_t *> attribute_list_;
  std::map<std::tuple<uint8_t, uint16_t, uint8_t, uint16_t>, ZigBeeAttribute *> attributes_;
  esp_zb_ep_list_t *esp_zb_ep_list_ = esp_zb_ep_list_create();
  uint8_t ident_time_;
  bool manual_start_ = false;
  bool start_called_ = false;
  bool has_custom_mac_ = false;
  uint64_t custom_mac_ = 0;
  bool has_tc_key_ = false;
  bool join_distributed_ = true;
  bool log_network_key_ = false;
  bool has_manufacturer_code_ = false;
  uint16_t manufacturer_code_ = 0;
  bool has_zcl_version_ = false;
  uint8_t zcl_version_ = 0;
  std::string sw_build_id_;
  uint64_t tc_key_hi_ = 0;
  uint64_t tc_key_lo_ = 0;
  uint32_t channel_mask_ = ESP_ZB_PRIMARY_CHANNEL_MASK;
};

extern "C" void esp_zb_app_signal_handler(esp_zb_app_signal_t *signal_struct);
extern "C" void zb_set_ed_node_descriptor(bool power_src, bool rx_on_when_idle, bool alloc_addr);

template<typename T>
void ZigBeeComponent::add_attr(ZigBeeAttribute *attr, uint8_t endpoint_id, uint16_t cluster_id, uint8_t role,
                               uint16_t attr_id, uint8_t attr_type, uint8_t attr_access, uint8_t max_size, T value) {
  // The size byte of the zcl_str must be set to the maximum value,
  // even though the initial string may be shorter.
  if constexpr (std::is_same<T, std::string>::value) {
    auto zcl_str = get_zcl_string(value.c_str(), max_size, true);
    add_attr_(attr, endpoint_id, cluster_id, role, attr_id, attr_type, attr_access, zcl_str);
    delete[] zcl_str;
  } else if constexpr (std::is_convertible<T, const char *>::value) {
    auto zcl_str = get_zcl_string(value, max_size, true);
    add_attr_(attr, endpoint_id, cluster_id, role, attr_id, attr_type, attr_access, zcl_str);
    delete[] zcl_str;
  } else {
    add_attr_(attr, endpoint_id, cluster_id, role, attr_id, attr_type, attr_access, &value);
  }
}

template<typename T>
void ZigBeeComponent::add_attr_(ZigBeeAttribute *attr, uint8_t endpoint_id, uint16_t cluster_id, uint8_t role,
                                uint16_t attr_id, uint8_t attr_type, uint8_t attr_access, T *value_p) {
  esp_zb_attribute_list_t *attr_list = this->attribute_list_[{endpoint_id, cluster_id, role}];
  esp_err_t ret =
      esphome_zb_cluster_add_or_update_attr(cluster_id, attr_list, attr_id, attr_type, attr_access, value_p);
  if (ret != ESP_OK) {
    ESP_LOGE(TAG, "Could not add attribute 0x%04X to cluster 0x%04X in endpoint %u: %s", attr_id, cluster_id,
             endpoint_id, esp_err_to_name(ret));
  }
  this->attributes_[{endpoint_id, cluster_id, role, attr_id}] = attr;
}

}  // namespace zigbee
}  // namespace esphome
