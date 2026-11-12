#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_check.h"
#include "nvs_flash.h"
#include "esp_mac.h"
#include "esp_ieee802154.h"
#include "esp_partition.h"
#include "esp_zigbee_secur.h"
#include "zigbee_attribute.h"
#include "zigbee.h"
#include "hue_emu.h"
#include <vector>
#include "esphome/core/log.h"
#include "zigbee_helpers.h"
#ifdef CONFIG_WIFI_COEX
#include "esp_coexist.h"
#endif

#if !(defined ZB_ED_ROLE || defined ZB_ROUTER_ROLE)
#error Define ZB_ED_ROLE or ZB_ROUTER_ROLE in idf.py menuconfig.
#endif

// Pont de log per a hue_emu.c (C): els ESP_LOGx de IDF no surten en aquest build.
extern "C" void esphome_hue_log(const char *msg) { ESP_LOGI("hue_emu", "%s", msg); }

namespace esphome {
namespace zigbee {

ZigBeeComponent *zigbeeC;

device_params_t coord;

/**
 * Creates a ZCL string from the given input string.
 *
 * @param str          Pointer to the input null-terminated C-style string.
 * @param max_size     Maximum allowable size for the resulting ZCL string. Maximum value: 254.
 * @param use_max_size Optional. If true, the `max_size` is used directly,
 *                     overriding the actual size of the input string.
 * @return             Pointer to a dynamically allocated ZCL string.
 *                     NOTE: Caller is responsible for freeing the allocated memory with `delete[]`.
 *
 */
uint8_t *get_zcl_string(const char *str, uint8_t max_size, bool use_max_size) {
  uint8_t str_len = static_cast<uint8_t>(strlen(str));
  uint8_t zcl_str_size = use_max_size ? max_size : std::min(max_size, str_len);

  uint8_t *zcl_str = new uint8_t[zcl_str_size + 1];  // string + length octet
  zcl_str[0] = zcl_str_size;
  memcpy(zcl_str + 1, str, str_len);

  return zcl_str;
}

/// log_network_key: escriu la clau de xarxa (32 hex, en l'ordre de l'AES) per carregar-la al sniffer zigbeelogger.
static void log_network_key_if_enabled(const char *why) {
  if (zigbeeC == nullptr || !zigbeeC->log_network_key()) return;
  uint8_t key[16] = {0};
  if (esp_zb_secur_primary_network_key_get(key) != ESP_OK) {
    ESP_LOGW(TAG, "log_network_key: no s'ha pogut llegir la clau de xarxa (%s)", why);
    return;
  }
  char hex[33];
  for (int i = 0; i < 16; i++) snprintf(hex + 2 * i, 3, "%02X", key[i]);
  ESP_LOGW(TAG, "NWK KEY (%s) per al sniffer zigbeelogger (set_nwk_key), NO la publiquis: %s", why, hex);
}

static void bdb_start_top_level_commissioning_cb(uint8_t mode_mask) {
  if (esp_zb_bdb_start_top_level_commissioning(mode_mask) != ESP_OK) {
    ESP_LOGE(TAG, "Start network steering failed!");
  }
}

void ZigBeeComponent::set_report(ZigBeeAttribute *attribute, esp_zb_zcl_reporting_info_t reporting_info) {
  this->reporting_list.push_back(std::make_tuple(attribute, reporting_info));
}

void ZigBeeComponent::report() {
  for (const auto &[attribute, _] : zigbeeC->reporting_list) {
    attribute->report();
  }
}

void esp_zb_app_signal_handler(esp_zb_app_signal_t *signal_struct) {
  static uint8_t steering_retry_count = 0;
  uint32_t *p_sg_p = signal_struct->p_app_signal;
  esp_err_t err_status = signal_struct->esp_err_status;
  esp_zb_app_signal_type_t sig_type = (esp_zb_app_signal_type_t) *p_sg_p;
  esp_zb_zdo_signal_leave_params_t *leave_params = NULL;
  switch (sig_type) {
    case ESP_ZB_ZDO_SIGNAL_SKIP_STARTUP:
      // Notifies the application that ZBOSS framework (scheduler, buffer pool, etc.) has started, but no
      // join/rejoin/formation/BDB initialization has been done yet.
      ESP_LOGD(TAG, "Zigbee stack initialized");
      esp_zb_bdb_start_top_level_commissioning(ESP_ZB_BDB_MODE_INITIALIZATION);
      break;
    case ESP_ZB_BDB_SIGNAL_DEVICE_FIRST_START:
      // Device started for the first time after the NVRAM erase
    case ESP_ZB_BDB_SIGNAL_DEVICE_REBOOT:
      // Device started using the NVRAM contents.
      if (err_status == ESP_OK) {
        ESP_LOGD(TAG, "Device started up in %sfactory-reset mode", esp_zb_bdb_is_factory_new() ? "" : "non ");
        {
          esp_zb_ieee_addr_t own_ieee;
          esp_zb_get_long_address(own_ieee);
          ESP_LOGI(TAG, "Own IEEE EUI-64: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
                   own_ieee[7], own_ieee[6], own_ieee[5], own_ieee[4],
                   own_ieee[3], own_ieee[2], own_ieee[1], own_ieee[0]);
        }
        zigbeeC->started_ = true;
        if (esp_zb_bdb_is_factory_new()) {
          ESP_LOGD(TAG, "Start network steering");
          esp_zb_bdb_start_top_level_commissioning(ESP_ZB_BDB_MODE_NETWORK_STEERING);
        } else {
          ESP_LOGD(TAG, "Device rebooted");
          log_network_key_if_enabled("rearrencada ja unit");
          zigbeeC->searchBindings();
        }
      } else {
        ESP_LOGE(TAG, "FIRST_START.  Device started up in %sfactory-reset mode with an error %d (%s)",
                 esp_zb_bdb_is_factory_new() ? "" : "non ", err_status, esp_err_to_name(err_status));
        ESP_LOGW(TAG, "Failed to initialize Zigbee stack (status: %s)", esp_err_to_name(err_status));
        esp_zb_scheduler_alarm((esp_zb_callback_t) bdb_start_top_level_commissioning_cb, ESP_ZB_BDB_MODE_INITIALIZATION,
                               1000);
      }
      break;
    case ESP_ZB_BDB_SIGNAL_STEERING:
      // BDB network steering completed (Network steering only)
      if (err_status == ESP_OK) {
        steering_retry_count = 0;
        esp_zb_ieee_addr_t extended_pan_id;
        esp_zb_get_extended_pan_id(extended_pan_id);
        ESP_LOGI(TAG,
                 "Joined network successfully (Extended PAN ID: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x, PAN ID: "
                 "0x%04hx, Channel:%d)",
                 extended_pan_id[7], extended_pan_id[6], extended_pan_id[5], extended_pan_id[4], extended_pan_id[3],
                 extended_pan_id[2], extended_pan_id[1], extended_pan_id[0], esp_zb_get_pan_id(),
                 esp_zb_get_current_channel());
        log_network_key_if_enabled("unio");
        zigbeeC->post_join();  // al loop principal (defer)
        zigbeeC->connected_ = true;
      } else {
        ESP_LOGI(TAG, "Network steering was not successful (status: %s)", esp_err_to_name(err_status));
        steering_retry_count++;
        // Reintento CONTINUO cada 3s (en vez del backoff a 10 min tras 10 intentos).
        // Asi puedes poner el Hue a buscar en cualquier momento y el steering lo caza,
        // sin depender de acertar la ventana de ~13s del arranque. Revertir al backoff
        // largo una vez emparejado, para no saturar la radio 802.15.4.
        esp_zb_scheduler_alarm((esp_zb_callback_t) bdb_start_top_level_commissioning_cb,
                               ESP_ZB_BDB_MODE_NETWORK_STEERING, 3000);
      }
      break;
    case ESP_ZB_ZDO_SIGNAL_LEAVE:
      // wejn.org fix #4: en un leave-with-reset (el pont ens treu, o la propia pila en fallar l'autenticacio)
      // NO reiniciem l'ESP (esp_zb_factory_reset rebota i, encadenat, dispara el safe mode d'ESPHome):
      // esborrem la NVRAM zboss al proper arranque i tornem a fer steering de seguida.
      leave_params = (esp_zb_zdo_signal_leave_params_t *) esp_zb_app_signal_get_params(p_sg_p);
      zigbeeC->connected_ = false;
      if (leave_params != NULL && leave_params->leave_type == ESP_ZB_NWK_LEAVE_TYPE_RESET) {
        ESP_LOGW(TAG, "ZDO leave with reset (status %s): NVRAM erase at next start + nou steering",
                 esp_err_to_name(err_status));
        esp_zb_nvram_erase_at_start(true);
        esp_zb_scheduler_alarm((esp_zb_callback_t) bdb_start_top_level_commissioning_cb,
                               ESP_ZB_BDB_MODE_NETWORK_STEERING, 1000);
      } else {
        ESP_LOGW(TAG, "ZDO leave: leave_type %u, status %s", leave_params ? leave_params->leave_type : 0xFF,
                 esp_err_to_name(err_status));
      }
      break;
    default:
      ESP_LOGD(TAG, "ZDO signal: %s (0x%x), status: %s", esp_zb_zdo_signal_to_string(sig_type), sig_type,
               esp_err_to_name(err_status));
      break;
  }
}

// Recall bounded devices from the binding table after reboot
void ZigBeeComponent::bindingTableCb(const esp_zb_zdo_binding_table_info_t *table_info, void *user_ctx) {
  bool done = true;
  esp_zb_zdo_mgmt_bind_param_t *req = (esp_zb_zdo_mgmt_bind_param_t *) user_ctx;
  esp_zb_zdp_status_t zdo_status = (esp_zb_zdp_status_t) table_info->status;
  ESP_LOGD(TAG, "Binding table callback for address 0x%04x with status %d", req->dst_addr, zdo_status);
  if (zdo_status == ESP_ZB_ZDP_STATUS_SUCCESS) {
    // Print binding table log simple
    ESP_LOGD(TAG, "Binding table info: total %d, index %d, count %d", table_info->total, table_info->index,
             table_info->count);

    if (table_info->total == 0) {
      ESP_LOGD(TAG, "No binding table entries found");
      free(req);
      zigbeeC->connected_ = true;
      return;
    }

    esp_zb_zdo_binding_table_record_t *record = table_info->record;
    for (int i = 0; i < table_info->count; i++) {
      ESP_LOGD(TAG, "Binding table record: src_endp %d, dst_endp %d, cluster_id 0x%04x, dst_addr_mode %d",
               record->src_endp, record->dst_endp, record->cluster_id, record->dst_addr_mode);

      zb_device_params_t *device = (zb_device_params_t *) calloc(1, sizeof(zb_device_params_t));
      device->endpoint = record->dst_endp;
      if (record->dst_addr_mode == ESP_ZB_APS_ADDR_MODE_16_ENDP_PRESENT ||
          record->dst_addr_mode == ESP_ZB_APS_ADDR_MODE_16_GROUP_ENDP_NOT_PRESENT) {
        device->short_addr = record->dst_address.addr_short;
      } else {  // ESP_ZB_APS_ADDR_MODE_64_ENDP_PRESENT
        memcpy(device->ieee_addr, record->dst_address.addr_long, sizeof(esp_zb_ieee_addr_t));
      }
      ESP_LOGD(TAG,
               "Device bound to EP %d -> device endpoint: %d, short addr: 0x%04x, ieee addr: "
               "%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
               record->src_endp, device->endpoint, device->short_addr, device->ieee_addr[7], device->ieee_addr[6],
               device->ieee_addr[5], device->ieee_addr[4], device->ieee_addr[3], device->ieee_addr[2],
               device->ieee_addr[1], device->ieee_addr[0]);
      record = record->next;
    }

    // Continue reading the binding table
    if (table_info->index + table_info->count < table_info->total) {
      /* There are unreported binding table entries, request for them. */
      req->start_index = table_info->index + table_info->count;
      esp_zb_zdo_binding_table_req(req, bindingTableCb, req);
      done = false;
    }
  }

  if (done) {
    // Print bound devices
    ESP_LOGD(TAG, "Filling bounded devices finished");
    free(req);
    zigbeeC->connected_ = true;
  }
}

void ZigBeeComponent::searchBindings() {
  esp_zb_zdo_mgmt_bind_param_t *mb_req = (esp_zb_zdo_mgmt_bind_param_t *) malloc(sizeof(esp_zb_zdo_mgmt_bind_param_t));
  mb_req->dst_addr = esp_zb_get_short_address();
  mb_req->start_index = 0;
  ESP_LOGD(TAG, "Requesting binding table for address 0x%04x", mb_req->dst_addr);
  esp_zb_zdo_binding_table_req(mb_req, bindingTableCb, (void *) mb_req);
}

static esp_err_t zb_attribute_handler(const esp_zb_zcl_set_attr_value_message_t *message) {
  esp_err_t ret = ESP_OK;

  ESP_RETURN_ON_FALSE(message, ESP_FAIL, TAG, "Empty message");
  ESP_RETURN_ON_FALSE(message->info.status == ESP_ZB_ZCL_STATUS_SUCCESS, ESP_ERR_INVALID_ARG, TAG,
                      "Received message: error status(%d)", message->info.status);
  ESP_LOGD(TAG, "Received message: endpoint(%d), cluster(0x%x), attribute(0x%x), data size(%d)",
           message->info.dst_endpoint, message->info.cluster, message->attribute.id, message->attribute.data.size);
  zigbeeC->handle_attribute(message->info, message->attribute);
  return ret;
}

static esp_err_t zb_cmd_attribute_handler(const esp_zb_zcl_cmd_read_attr_resp_message_t *message) {
  esp_err_t ret = ESP_OK;

  ESP_RETURN_ON_FALSE(message, ESP_FAIL, TAG, "Empty message");
  ESP_RETURN_ON_FALSE(message->info.status == ESP_ZB_ZCL_STATUS_SUCCESS, ESP_ERR_INVALID_ARG, TAG,
                      "Received message: error status(%d)", message->info.status);
  esp_zb_zcl_read_attr_resp_variable_t *variable = message->variables;
  switch (message->info.cluster) {
    case ESP_ZB_ZCL_CLUSTER_ID_TIME:
      ESP_LOGD(TAG, "Recieved time information");
#ifdef USE_ZIGBEE_TIME
      if (zigbeeC->zt_ == nullptr) {
        ESP_LOGD(TAG, "No time component linked to update time!");
      } else {
        zigbeeC->zt_->recieve_timesync_response(message->variables);
      }
#else
      ESP_LOGD(TAG, "No zigbee time component included at build time!");
#endif
      break;
    default:
      ESP_LOGD(TAG, "Attribute data recieved (but not yet handled):");
      while (variable) {
        ESP_LOGD(TAG, "Read attribute response: status(%d), cluster(0x%x), attribute(0x%x), type(0x%x), value(%d)",
                 variable->status, message->info.cluster, variable->attribute.id, variable->attribute.data.type,
                 variable->attribute.data.value ? *(uint8_t *) variable->attribute.data.value : 0);
        variable = variable->next;
      }
  }
  return ret;
}

// ------------------------------ Escenas (cluster SCENES) ------------------------------
// El endpoint COLOR_DIMMABLE_LIGHT ya incluye los clusters GROUPS y SCENES (los
// crea esp_zb_color_dimmable_light_clusters_create). La pila gestiona sola la
// pertenencia a grupos y los comandos Add/View/Remove Scene (guarda los field
// sets en su tabla, max. 10 escenas). Solo hay que implementar:
//   - STORE SCENE: fotografiar el estado actual (on/off + brillo + color xy) y
//     guardarlo en la tabla de escenas.
//   - RECALL SCENE: aplicar los field sets guardados. Se inyectan por
//     handle_attribute() para que disparen los mismos on_value del YAML que un
//     comando normal (y de paso se actualiza el atributo ZCL real).
//
// Aplica un atributo recuperado de una escena: actualiza el valor ZCL y lo
// inyecta en los automatismos on_value del YAML.
static void zb_scene_apply_attr(uint8_t endpoint, uint16_t cluster_id, uint16_t attr_id,
                                esp_zb_zcl_attr_type_t attr_type, void *value, uint8_t size) {
  esp_zb_zcl_set_attribute_val(endpoint, cluster_id, ESP_ZB_ZCL_CLUSTER_SERVER_ROLE, attr_id, value, false);
  esp_zb_device_cb_common_info_t info = {};
  info.status = ESP_ZB_ZCL_STATUS_SUCCESS;
  info.dst_endpoint = endpoint;
  info.cluster = cluster_id;
  esp_zb_zcl_attribute_t attribute = {};
  attribute.id = attr_id;
  attribute.data.type = attr_type;
  attribute.data.size = size;
  attribute.data.value = value;
  zigbeeC->handle_attribute(info, attribute);
}

static esp_err_t zb_scenes_store_handler(const esp_zb_zcl_store_scene_message_t *message) {
  ESP_RETURN_ON_FALSE(message, ESP_FAIL, TAG, "Empty message");
  ESP_RETURN_ON_FALSE(message->info.status == ESP_ZB_ZCL_STATUS_SUCCESS, ESP_ERR_INVALID_ARG, TAG,
                      "Store scene: error status(%d)", message->info.status);
  uint8_t ep = message->info.dst_endpoint;
  ESP_LOGI(TAG, "Store scene: endpoint %u, group 0x%04x, scene %u", ep, message->group_id, message->scene_id);

  // Snapshot del estado actual de los clusters de luz.
  uint8_t onoff = 0;
  uint8_t level = 254;
  uint8_t colorxy[4] = {0};
  esp_zb_zcl_attr_t *attr;
  attr = esp_zb_zcl_get_attribute(ep, ESP_ZB_ZCL_CLUSTER_ID_ON_OFF, ESP_ZB_ZCL_CLUSTER_SERVER_ROLE,
                                  ESP_ZB_ZCL_ATTR_ON_OFF_ON_OFF_ID);
  if (attr != nullptr && attr->data_p != nullptr)
    onoff = *(uint8_t *) attr->data_p;
  attr = esp_zb_zcl_get_attribute(ep, ESP_ZB_ZCL_CLUSTER_ID_LEVEL_CONTROL, ESP_ZB_ZCL_CLUSTER_SERVER_ROLE,
                                  ESP_ZB_ZCL_ATTR_LEVEL_CONTROL_CURRENT_LEVEL_ID);
  if (attr != nullptr && attr->data_p != nullptr)
    level = *(uint8_t *) attr->data_p;
  attr = esp_zb_zcl_get_attribute(ep, ESP_ZB_ZCL_CLUSTER_ID_COLOR_CONTROL, ESP_ZB_ZCL_CLUSTER_SERVER_ROLE,
                                  ESP_ZB_ZCL_ATTR_COLOR_CONTROL_CURRENT_X_ID);
  if (attr != nullptr && attr->data_p != nullptr)
    memcpy(&colorxy[0], attr->data_p, 2);  // CurrentX (u16 LE)
  attr = esp_zb_zcl_get_attribute(ep, ESP_ZB_ZCL_CLUSTER_ID_COLOR_CONTROL, ESP_ZB_ZCL_CLUSTER_SERVER_ROLE,
                                  ESP_ZB_ZCL_ATTR_COLOR_CONTROL_CURRENT_Y_ID);
  if (attr != nullptr && attr->data_p != nullptr)
    memcpy(&colorxy[2], attr->data_p, 2);  // CurrentY (u16 LE)

  // Field sets encadenados: ON_OFF -> LEVEL -> COLOR (x,y). La tabla copia los datos.
  esp_zb_zcl_scenes_extension_field_t color_field = {
      .cluster_id = ESP_ZB_ZCL_CLUSTER_ID_COLOR_CONTROL,
      .length = 4,
      .extension_field_attribute_value_list = colorxy,
      .next = nullptr,
  };
  esp_zb_zcl_scenes_extension_field_t level_field = {
      .cluster_id = ESP_ZB_ZCL_CLUSTER_ID_LEVEL_CONTROL,
      .length = 1,
      .extension_field_attribute_value_list = &level,
      .next = &color_field,
  };
  esp_zb_zcl_scenes_extension_field_t onoff_field = {
      .cluster_id = ESP_ZB_ZCL_CLUSTER_ID_ON_OFF,
      .length = 1,
      .extension_field_attribute_value_list = &onoff,
      .next = &level_field,
  };
  return esp_zb_zcl_scenes_table_store(ep, message->group_id, message->scene_id, 0x0000, &onoff_field);
}

static esp_err_t zb_scenes_recall_handler(const esp_zb_zcl_recall_scene_message_t *message) {
  ESP_RETURN_ON_FALSE(message, ESP_FAIL, TAG, "Empty message");
  uint8_t ep = message->info.dst_endpoint;
  // Log siempre el status del stack (util para depurar por que ZHA reporta
  // FAILURE aunque la escena exista).
  ESP_LOGI(TAG, "Recall scene: endpoint %u, group 0x%04x, scene %u, transition %u, status=%d", ep,
           message->group_id, message->scene_id, message->transition_time, message->info.status);
  // Hook al YAML (on_recall_scene): permite mapear scene_id -> logica propia
  // (p. ej. cambiar el modo de un select). Corre SIEMPRE, tambien con status
  // no-SUCCESS, para que el modo se aplique aunque el stack se queje del
  // field_set o del group_id (p.ej. HA envia group_id=0 por defecto).
  if (zigbeeC->hue_emulation())
    esphome_hue_scene_recalled(message->group_id, message->scene_id);  // degradats d'escena Hue
  zigbeeC->post_recall_scene(message->group_id, message->scene_id);  // al loop principal (defer)
  // Devolvemos SIEMPRE ESP_OK para que HA no muestre FAILURE. El mode ya se
  // ha aplicado via el hook, y no dependemos de que la escena exista en la
  // tabla del stack (mapeo scene_id -> modo se hace en el YAML).
  if (message->info.status != ESP_ZB_ZCL_STATUS_SUCCESS) {
    ESP_LOGD(TAG, "Recall scene: stack status no-SUCCESS (%d) ignorado (mode aplicado por hook)",
             message->info.status);
  }
  for (esp_zb_zcl_scenes_extension_field_t *field = message->field_set; field != nullptr; field = field->next) {
    uint8_t *v = field->extension_field_attribute_value_list;
    if (v == nullptr)
      continue;
    switch (field->cluster_id) {
      case ESP_ZB_ZCL_CLUSTER_ID_ON_OFF:
        if (field->length >= 1) {
          zb_scene_apply_attr(ep, ESP_ZB_ZCL_CLUSTER_ID_ON_OFF, ESP_ZB_ZCL_ATTR_ON_OFF_ON_OFF_ID,
                              ESP_ZB_ZCL_ATTR_TYPE_BOOL, &v[0], 1);
        }
        break;
      case ESP_ZB_ZCL_CLUSTER_ID_LEVEL_CONTROL:
        if (field->length >= 1) {
          zb_scene_apply_attr(ep, ESP_ZB_ZCL_CLUSTER_ID_LEVEL_CONTROL, ESP_ZB_ZCL_ATTR_LEVEL_CONTROL_CURRENT_LEVEL_ID,
                              ESP_ZB_ZCL_ATTR_TYPE_U8, &v[0], 1);
        }
        break;
      case ESP_ZB_ZCL_CLUSTER_ID_COLOR_CONTROL:
        // Extension field ZCL de Color Control: CurrentX (u16 LE) + CurrentY (u16 LE).
        if (field->length >= 4) {
          uint16_t x, y;
          memcpy(&x, &v[0], 2);
          memcpy(&y, &v[2], 2);
          zb_scene_apply_attr(ep, ESP_ZB_ZCL_CLUSTER_ID_COLOR_CONTROL, ESP_ZB_ZCL_ATTR_COLOR_CONTROL_CURRENT_X_ID,
                              ESP_ZB_ZCL_ATTR_TYPE_U16, &x, 2);
          zb_scene_apply_attr(ep, ESP_ZB_ZCL_CLUSTER_ID_COLOR_CONTROL, ESP_ZB_ZCL_ATTR_COLOR_CONTROL_CURRENT_Y_ID,
                              ESP_ZB_ZCL_ATTR_TYPE_U16, &y, 2);
        }
        break;
      default:
        ESP_LOGD(TAG, "Recall scene: cluster 0x%04x no soportado (len %u)", field->cluster_id, field->length);
        break;
    }
  }
  return ESP_OK;
}

static esp_err_t zb_action_handler(esp_zb_core_action_callback_id_t callback_id, const void *message) {
  esp_err_t ret = ESP_OK;
  switch (callback_id) {
    case ESP_ZB_CORE_SET_ATTR_VALUE_CB_ID:
      ret = zb_attribute_handler((esp_zb_zcl_set_attr_value_message_t *) message);
      break;
    case ESP_ZB_CORE_SCENES_STORE_SCENE_CB_ID:
      ret = zb_scenes_store_handler((esp_zb_zcl_store_scene_message_t *) message);
      break;
    case ESP_ZB_CORE_SCENES_RECALL_SCENE_CB_ID:
      ret = zb_scenes_recall_handler((esp_zb_zcl_recall_scene_message_t *) message);
      break;
    case ESP_ZB_CORE_CMD_READ_ATTR_RESP_CB_ID:
      ret = zb_cmd_attribute_handler((esp_zb_zcl_cmd_read_attr_resp_message_t *) message);
      break;
    case ESP_ZB_CORE_CMD_DEFAULT_RESP_CB_ID:
      ESP_LOGD(TAG, "Receive Zigbee default response callback");
      break;
    case ESP_ZB_CORE_CMD_CUSTOM_CLUSTER_REQ_CB_ID: {
      const esp_zb_zcl_custom_cluster_command_message_t *m =
          (const esp_zb_zcl_custom_cluster_command_message_t *) message;
      if (zigbeeC->hue_emulation() && m->info.cluster == HUE_CLUSTER_FC03 && m->info.command.id == 0x00) {
        esphome_hue_apply_state(m->info.dst_endpoint, (const uint8_t *) m->data.value, m->data.size);
      } else if (zigbeeC->hue_emulation() && m->info.cluster == HUE_CLUSTER_FC01 && m->info.command.id == 0x01) {
        // Stream d'entreteniment directe del pont: nomes arriba si el pont ens ha triat com a proxy.
        esphome_hue_ent_frame((const uint8_t *) m->data.value, m->data.size, 0);
      } else if (zigbeeC->hue_emulation() && m->info.cluster == HUE_CLUSTER_FC01 && m->info.command.id == 0x03) {
        esphome_hue_ent_session((const uint8_t *) m->data.value, m->data.size);
      } else {
        char hex[3 * 24 + 1] = {0};
        const uint8_t *b = (const uint8_t *) m->data.value;
        for (uint16_t i = 0; i < m->data.size && i < 24; i++)
          snprintf(hex + 3 * i, 4, "%02X ", b[i]);
        ESP_LOGW(TAG, "Comanda custom no gestionada: cluster 0x%04X cmd 0x%02X manuf 0x%04X (%u bytes): %s",
                 m->info.cluster, m->info.command.id, m->info.header.manuf_code, m->data.size, hex);
      }
      break;
    }
    default:
      ESP_LOGW(TAG, "Receive Zigbee action(0x%x) callback", callback_id);
      break;
  }
  return ret;
}

void ZigBeeComponent::handle_attribute(esp_zb_device_cb_common_info_t info, esp_zb_zcl_attribute_t attribute) {
  if (this->hue_emulation_ && info.dst_endpoint == this->hue_endpoint_ &&
      (info.cluster == ESP_ZB_ZCL_CLUSTER_ID_ON_OFF || info.cluster == ESP_ZB_ZCL_CLUSTER_ID_LEVEL_CONTROL ||
       info.cluster == ESP_ZB_ZCL_CLUSTER_ID_COLOR_CONTROL)) {
    esphome_hue_refresh_state(info.dst_endpoint);  // tasca Zigbee: sense lock
  }
  auto key = std::make_tuple(info.dst_endpoint, info.cluster, (uint8_t) ESP_ZB_ZCL_CLUSTER_SERVER_ROLE, attribute.id);
  auto it = this->attributes_.find(key);
  if (it == this->attributes_.end())
    return;
  // Som a la tasca Zigbee_main: copiem el valor (el punter de la pila nomes val durant el callback) i despatxem
  // on_value al loop principal amb defer(), que es on el YAML pot tocar llums i scripts sense carreres.
  ZigBeeAttribute *attr = it->second;
  size_t n = attribute.data.size;
  if (n == 0 || attribute.data.value == nullptr)
    n = 0;
  if (n > 32)
    n = 32;
  std::vector<uint8_t> buf((const uint8_t *) attribute.data.value, (const uint8_t *) attribute.data.value + n);
  this->defer([attr, attribute, buf]() mutable {
    esp_zb_zcl_attribute_t a = attribute;
    a.data.value = buf.empty() ? nullptr : (void *) buf.data();
    attr->on_value(a);
  });
}

void ZigBeeComponent::create_default_cluster(uint8_t endpoint_id, esp_zb_ha_standard_devices_t device_id) {
  this->cluster_list_[endpoint_id] = esphome_zb_default_clusters_create(device_id);
  this->endpoint_list_[endpoint_id] = device_id;
}

void ZigBeeComponent::add_cluster(uint8_t endpoint_id, uint16_t cluster_id, uint8_t role) {
  esp_zb_attribute_list_t *attr_list;
  switch (cluster_id) {
    case 0:
      attr_list = create_basic_cluster_();
      break;
    case 3:
      attr_list = create_ident_cluster_();
      break;
    default:
      attr_list = esphome_zb_default_attr_list_create(cluster_id);
  }
  this->attribute_list_[{endpoint_id, cluster_id, role}] = attr_list;
}

void ZigBeeComponent::set_basic_cluster(std::string model, std::string manufacturer, std::string date, uint8_t power,
                                        uint8_t app_version, uint8_t stack_version, uint8_t hw_version,
                                        std::string area, uint8_t physical_env) {
  this->basic_cluster_data_ = {
      .model = model,
      .manufacturer = manufacturer,
      .date = date,
      .power = power,
      .app_version = app_version,
      .stack_version = stack_version,
      .hw_version = hw_version,
      .area = area,
      .physical_env = physical_env,
  };
}

esp_zb_attribute_list_t *ZigBeeComponent::create_basic_cluster_() {
  // ------------------------------ Cluster BASIC ------------------------------
  esp_zb_basic_cluster_cfg_t basic_cluster_cfg = {
      .zcl_version = this->has_zcl_version_ ? this->zcl_version_ : (uint8_t) ESP_ZB_ZCL_BASIC_ZCL_VERSION_DEFAULT_VALUE,
      .power_source = this->basic_cluster_data_.power,
  };
  ESP_LOGD(TAG, "Model: %s", this->basic_cluster_data_.model.c_str());
  ESP_LOGD(TAG, "Manufacturer: %s", this->basic_cluster_data_.manufacturer.c_str());
  ESP_LOGD(TAG, "Date: %s", this->basic_cluster_data_.date.c_str());
  ESP_LOGD(TAG, "Area: %s", this->basic_cluster_data_.area.c_str());
  uint8_t *ManufacturerName = get_zcl_string(this->basic_cluster_data_.manufacturer.c_str(),
                                             32);  // warning: this is in format {length, 'string'} :
  uint8_t *ModelIdentifier = get_zcl_string(this->basic_cluster_data_.model.c_str(), 32);
  uint8_t *DateCode = get_zcl_string(this->basic_cluster_data_.date.c_str(), 16);
  uint8_t *Location = get_zcl_string(this->basic_cluster_data_.area.c_str(), 16);
  esp_zb_attribute_list_t *attr_list = esp_zb_basic_cluster_create(&basic_cluster_cfg);
  esp_zb_basic_cluster_add_attr(attr_list, ESP_ZB_ZCL_ATTR_BASIC_APPLICATION_VERSION_ID,
                                &(this->basic_cluster_data_.app_version));
  esp_zb_basic_cluster_add_attr(attr_list, ESP_ZB_ZCL_ATTR_BASIC_STACK_VERSION_ID,
                                &(this->basic_cluster_data_.stack_version));
  esp_zb_basic_cluster_add_attr(attr_list, ESP_ZB_ZCL_ATTR_BASIC_HW_VERSION_ID,
                                &(this->basic_cluster_data_.hw_version));
  esp_zb_basic_cluster_add_attr(attr_list, ESP_ZB_ZCL_ATTR_BASIC_MANUFACTURER_NAME_ID, ManufacturerName);
  esp_zb_basic_cluster_add_attr(attr_list, ESP_ZB_ZCL_ATTR_BASIC_MODEL_IDENTIFIER_ID, ModelIdentifier);
  esp_zb_basic_cluster_add_attr(attr_list, ESP_ZB_ZCL_ATTR_BASIC_DATE_CODE_ID, DateCode);
  esp_zb_basic_cluster_add_attr(attr_list, ESP_ZB_ZCL_ATTR_BASIC_LOCATION_DESCRIPTION_ID, Location);
  esp_zb_basic_cluster_add_attr(attr_list, ESP_ZB_ZCL_ATTR_BASIC_PHYSICAL_ENVIRONMENT_ID,
                                &(this->basic_cluster_data_.physical_env));
  if (!this->sw_build_id_.empty()) {
    uint8_t *SwBuildId = get_zcl_string(this->sw_build_id_.c_str(), 16);
    esp_zb_basic_cluster_add_attr(attr_list, ESP_ZB_ZCL_ATTR_BASIC_SW_BUILD_ID, SwBuildId);
    delete[] SwBuildId;
  }
  delete[] ManufacturerName;
  delete[] ModelIdentifier;
  delete[] DateCode;
  delete[] Location;
  return attr_list;
}

void ZigBeeComponent::set_ident_time(uint8_t ident_time) {
  // ------------------------------ Cluster IDENTIFY ------------------------------
  this->ident_time_ = ident_time;
}

esp_zb_attribute_list_t *ZigBeeComponent::create_ident_cluster_() {
  // ------------------------------ Cluster IDENTIFY ------------------------------
  esp_zb_identify_cluster_cfg_t identify_cluster_cfg = {
      .identify_time = this->ident_time_,
  };
  return esp_zb_identify_cluster_create(&identify_cluster_cfg);
}

esp_err_t ZigBeeComponent::create_endpoint(uint8_t endpoint_id, esp_zb_ha_standard_devices_t device_id) {
  esp_zb_cluster_list_t *esp_zb_cluster_list = this->cluster_list_[endpoint_id];
  // ------------------------------ Create endpoint list ------------------------------
  // app_device_version = 1 per wejn.org fix #2: Philips Hue Bridge cacheja
  // dades del device i amb version=0 mai apareix com a llum. version=1 basta.
  esp_zb_endpoint_config_t endpoint_config = {.endpoint = endpoint_id,
                                              .app_profile_id = ESP_ZB_AF_HA_PROFILE_ID,
                                              .app_device_id = device_id,
                                              .app_device_version = 1};
  if (this->hue_emulation_ && endpoint_id == this->hue_endpoint_) {
    // Com una LCT015 real (captura 2026-10-11): Extended Color Light ZLL 0x0210, versio 2. El profile es queda a HA
    // 0x0104: amb 0xC05E (ZLL, com la bombeta real) ZBOSS descarta totes les trames que el pont envia amb profile
    // 0x0104 i el cactus deixa de respondre (provat 14:05, 2026-10-11).
    // Device id: amb profile HA el pont nomes accepta l'Extended Color Light HA (0x010D, el del YAML); amb 0x0210
    // (id ZLL) sota 0x0104 va tallar l'entrevista just despres del Simple Descriptor (14:14, 2026-10-11).
    endpoint_config.app_device_version = 2;
    ESP_LOGI(TAG, "Hue: endpoint %u amb profile 0x%04X, device 0x%04X, versio 2", endpoint_id,
             ESP_ZB_AF_HA_PROFILE_ID, (unsigned) device_id);
  }
  return esp_zb_ep_list_add_ep(this->esp_zb_ep_list_, esp_zb_cluster_list, endpoint_config);
}

static void esp_zb_task_(void *pvParameters) {
  if (esp_zb_start(false) != ESP_OK) {
    ESP_LOGE(TAG, "Could not setup Zigbee");
    // this->mark_failed();
    vTaskDelete(NULL);
  }

  if ((zigbeeC->device_role_ == ESP_ZB_DEVICE_TYPE_ED) && (zigbeeC->basic_cluster_data_.power == 0x03)) {
    ESP_LOGD(TAG, "Battery powered!");
    // zb_set_ed_node_descriptor(0, 1, 1);  // workaround, rx_on_when_idle should be 0 for battery powered devices.
    esp_zb_set_node_descriptor_power_source(0);
  } else {
    esp_zb_set_node_descriptor_power_source(1);
  }
  // esp_zb_set_node_descriptor_power_source() reescriu el descriptor de node: el codi de fabricant posat abans
  // d'esp_zb_start sortia a l'aire com 0x1234 (captura 2026-10-11). El tornem a posar aqui.
  if (zigbeeC->has_manufacturer_code()) {
    esp_zb_set_node_descriptor_manufacturer_code(zigbeeC->manufacturer_code());
    ESP_LOGI(TAG, "Node descriptor manufacturer code (post power source): 0x%04X", zigbeeC->manufacturer_code());
  }
  esp_zb_stack_main_loop();
}

void ZigBeeComponent::setup() {
  zigbeeC = this;
  if (this->manual_start_) {
    // Ventana WiFi: la pila NO arranca hasta que el YAML llame a zigbee.start
    // (idealmente tras wifi.disable, para que la radio 2.4GHz quede libre).
    ESP_LOGI(TAG, "manual_start activo: esperando accion zigbee.start");
    return;
  }
  this->start();
}

void ZigBeeComponent::reset() {
  if (this->start_called_) {
    esp_zb_lock_acquire(portMAX_DELAY);
    esp_zb_factory_reset();
    esp_zb_lock_release();
    return;
  }
  // Pila aun no iniciada (ventana manual_start): borra la NVRAM de zboss para
  // que el proximo arranque haga steering desde cero (re-emparejar).
  const esp_partition_t *p =
      esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, "zb_storage");
  if (p == nullptr) {
    ESP_LOGE(TAG, "reset(): particion zb_storage no encontrada");
    return;
  }
  if (esp_partition_erase_range(p, 0, p->size) == ESP_OK) {
    ESP_LOGW(TAG, "reset(): zb_storage borrada; la red Zigbee se olvidara en el proximo arranque");
  } else {
    ESP_LOGE(TAG, "reset(): fallo borrando zb_storage");
  }
}

void ZigBeeComponent::start() {
  if (this->start_called_) {
    ESP_LOGW(TAG, "start(): la pila Zigbee ya esta iniciada");
    return;
  }
  this->start_called_ = true;
  ESP_LOGI(TAG, "Iniciando pila Zigbee");
  esp_zb_platform_config_t config = {
      .radio_config = ESP_ZB_DEFAULT_RADIO_CONFIG(),
      .host_config = ESP_ZB_DEFAULT_HOST_CONFIG(),
  };
#ifdef CONFIG_WIFI_COEX
  if (esp_coex_wifi_i154_enable() != ESP_OK) {
    this->mark_failed();
    return;
  }
#endif
  // ESP_ERROR_CHECK(nvs_flash_init()); not needed, called by esp32 component
  if (esp_zb_platform_config(&config) != ESP_OK) {
    this->mark_failed();
    return;
  }

  /* initialize Zigbee stack */
  esp_zb_zed_cfg_t zb_zed_cfg = {
      .ed_timeout = ED_AGING_TIMEOUT,
      .keep_alive = ED_KEEP_ALIVE,
  };
  esp_zb_zczr_cfg_t zb_zczr_cfg = {
      .max_children = MAX_CHILDREN,
  };
  esp_zb_cfg_t zb_nwk_cfg = {
      .esp_zb_role = this->device_role_,
      .install_code_policy = INSTALLCODE_POLICY_ENABLE,
  };
#ifdef ZB_ROUTER_ROLE
  zb_nwk_cfg.nwk_cfg.zczr_cfg = zb_zczr_cfg;
#else
  zb_nwk_cfg.nwk_cfg.zed_cfg = zb_zed_cfg;
#endif
  esp_zb_init(&zb_nwk_cfg);

  // EUI-64 / 802.15.4 long address.
  // La convencion de bytes en las APIs (esp_zb_ieee_addr_t) es LSB-first
  // (mac[0] = byte menos significativo).
  if (this->has_custom_mac_) {
    // MAC fijada por configuracion. custom_mac_ esta empaquetada big-endian
    // (el octeto escrito primero es el MSB); la desempaquetamos a LSB-first.
    esp_zb_ieee_addr_t mac = {0};
    for (int i = 0; i < 8; i++) {
      mac[i] = (uint8_t) ((this->custom_mac_ >> (8 * i)) & 0xFF);
    }
    ESP_LOGI(TAG, "Using configured EUI-64 (LSB-first bytes): %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1],
             mac[2], mac[3], mac[4], mac[5], mac[6], mac[7]);
    // Pisamos tanto la IEEE del stack Zigbee como la del radio 802.15.4 para
    // que ambos transmitan la misma direccion configurada.
    esp_zb_set_long_address(mac);
    esp_ieee802154_set_extended_address(mac);
  } else {
    // Workaround conocido (esp-zigbee-lib 1.6.x sobre esp-idf 5.5):
    // el stack Zigbee tiene la IEEE correcta, pero el radio MAC 802.15.4
    // a veces transmite frames con source EUI-64 = FF:FF:FF:FF:FF:FF:FF:FF
    // hasta que se llama explicitamente a esp_ieee802154_set_extended_address.
    // NOTA: NO llamamos a esp_zb_set_long_address (el stack ya tiene su IEEE
    // bien por esp_zb_init -> esp_read_mac internamente; pisarla lo rompe).
    uint8_t mac[8] = {0};
    if (esp_read_mac(mac, ESP_MAC_IEEE802154) == ESP_OK) {
      ESP_LOGI(TAG, "Set radio 802.15.4 EUI-64 to (LSB-first bytes): %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], mac[6], mac[7]);
      esp_ieee802154_set_extended_address(mac);
    } else {
      ESP_LOGE(TAG, "esp_read_mac(ESP_MAC_IEEE802154) failed");
    }
  }

  // Trust Center link key configurada.
  // join_mode: distributed (per defecte) — el Hue Bridge es una xarxa de seguretat DISTRIBUIDA (herencia ZLL):
  // la Transport Key arriba xifrada amb la ZLL Commissioning key, que la pila ha de tenir com a clau distribuida
  // (dTCLK) i a mes cal permetre el join a xarxes distribuides. Amb la clau al slot CENTRALITZAT (preconfigure) la
  // pila la rebutja: "violating secur policy: distributed security 1, aps_encr 1, encrypted by dTCLK 0" ->
  // "Have not got nwk key - authentication failed". Es exactament el que fan wejn.org (esp32-huello-world, e32wamb).
  // join_mode: centralized — clau preconfigurada de TC centralitzat (coordinadors Zigbee 3.0 amb clau propia).
  if (this->has_tc_key_) {
    uint8_t key[16];
    for (int i = 0; i < 8; i++) {
      key[i] = (uint8_t) ((this->tc_key_hi_ >> (8 * (7 - i))) & 0xFF);
      key[8 + i] = (uint8_t) ((this->tc_key_lo_ >> (8 * (7 - i))) & 0xFF);
    }
    if (this->join_distributed_) {
      ESP_LOGI(TAG, "Using custom TC link key as DISTRIBUTED key (dTCLK) + joining to distributed networks enabled");
      esp_zb_enable_joining_to_distributed(true);
      esp_zb_secur_TC_standard_distributed_key_set(key);
    } else {
      ESP_LOGI(TAG, "Using custom TC link key (CENTRALIZED preconfigure)");
      esp_zb_secur_TC_standard_preconfigure_key_set(key);
    }
  } else if (this->join_distributed_) {
    // Sense clau propia: nomes s'obre la porta a xarxes distribuides (clau distribuida per defecte de la pila).
    esp_zb_enable_joining_to_distributed(true);
  }

  esp_err_t ret;

  if (this->hue_emulation_)
    this->hue_prepare_clusters_();

  // clusters
  for (auto const &[key, val] : this->attribute_list_) {
    esp_zb_cluster_list_t *esp_zb_cluster_list = this->cluster_list_[std::get<0>(key)];
    ret = esphome_zb_cluster_list_add_or_update_cluster(std::get<1>(key), esp_zb_cluster_list, val, std::get<2>(key));
    if (ret != ESP_OK) {
      ESP_LOGE(TAG, "Could not create cluster 0x%04X with role %u: %s", std::get<1>(key), std::get<2>(key),
               esp_err_to_name(ret));
    }
  }

  // endpoints
  for (auto const &[ep_id, dev_id] : this->endpoint_list_) {
    // create_default_cluster(key, val);
    if (create_endpoint(ep_id, dev_id) != ESP_OK) {
      ESP_LOGE(TAG, "Could not create endpoint %u", ep_id);
    }
  }

  // Tamano de la tabla de escenas. IMPRESCINDIBLE llamarlo antes de
  // esp_zb_device_register: sin esto la tabla queda a 0 y todos los
  // esp_zb_zcl_scenes_table_store devuelven 0 pero no guardan nada, y el
  // stack responde NOT_FOUND (0x8B) al Recall Scene.
  esp_err_t sc_r = esp_zb_zcl_scenes_table_set_size(16);
  ESP_LOGI(TAG, "esp_zb_zcl_scenes_table_set_size(16) -> %d", sc_r);

  // ------------------------------ Register Device ------------------------------
  if (esp_zb_device_register(this->esp_zb_ep_list_) != ESP_OK) {
    ESP_LOGE(TAG, "Could not register the endpoint list");
    this->mark_failed();
    return;
  }

  esp_zb_core_action_handler_register(zb_action_handler);
  if (this->hue_emulation_) {
    esp_zb_raw_command_handler_register(esphome_hue_raw_handler);
    esphome_hue_init(this->hue_endpoint_);
    esp_zb_aps_data_indication_handler_register(esphome_hue_aps_indication);
    ESP_LOGI(TAG, "Hue: handler raw ZCL (Scenes manuf cmd 0x02) i hook APS (Simple_Desc_rsp ZLL) registrats");
  }

  // Node descriptor: manufacturer code (0x100B Philips/Signify per a un perfil Hue). Despres del register.
  if (this->has_manufacturer_code_) {
    esp_zb_set_node_descriptor_manufacturer_code(this->manufacturer_code_);
    ESP_LOGI(TAG, "Node descriptor manufacturer code: 0x%04X", this->manufacturer_code_);
  }

  ESP_LOGI(TAG, "Primary Zigbee channel mask: 0x%08X", (unsigned int) this->channel_mask_);
  if (esp_zb_set_primary_network_channel_set(this->channel_mask_) != ESP_OK) {
    ESP_LOGE(TAG, "Could not setup Zigbee");
    this->mark_failed();
    return;
  }

  // reporting
  for (auto &[_, reporting_info] : this->reporting_list) {
    ESP_LOGD(TAG, "set reporting for cluster: %u", reporting_info.cluster_id);
    if (esp_zb_zcl_update_reporting_info(&reporting_info) != ESP_OK) {
      ESP_LOGE(TAG, "Could not configure reporting for attribute 0x%04X in cluster 0x%04X in endpoint %u",
               reporting_info.attr_id, reporting_info.cluster_id, reporting_info.ep);
    }
  }
  xTaskCreate(esp_zb_task_, "Zigbee_main", 4096, NULL, 24, NULL);
}

void ZigBeeComponent::dump_config() {
  ESP_LOGCONFIG(TAG, "ZigBee:");
  for (auto const &[key, val] : this->endpoint_list_) {
    ESP_LOGCONFIG(TAG, "Endpoint: %u, %d", key, val);
  }
}

void ZigBeeComponent::hue_prepare_clusters_() {
  const uint8_t ep = this->hue_endpoint_;
  const uint8_t role = ESP_ZB_ZCL_CLUSTER_SERVER_ROLE;
  // Clusters estandard: si el YAML no els ha declarat, es creen amb els valors per defecte de la pila.
  const uint16_t std_clusters[] = {ESP_ZB_ZCL_CLUSTER_ID_BASIC, ESP_ZB_ZCL_CLUSTER_ID_IDENTIFY,
                                   ESP_ZB_ZCL_CLUSTER_ID_SCENES, ESP_ZB_ZCL_CLUSTER_ID_LEVEL_CONTROL,
                                   ESP_ZB_ZCL_CLUSTER_ID_COLOR_CONTROL};
  for (uint16_t cid : std_clusters) {
    auto key = std::make_tuple(ep, cid, role);
    if (this->attribute_list_.find(key) == this->attribute_list_.end()) {
      esp_zb_attribute_list_t *l = (cid == ESP_ZB_ZCL_CLUSTER_ID_BASIC)      ? this->create_basic_cluster_()
                                   : (cid == ESP_ZB_ZCL_CLUSTER_ID_IDENTIFY) ? this->create_ident_cluster_()
                                                                             : esphome_zb_default_attr_list_create(cid);
      this->attribute_list_[key] = l;
    }
    esphome_hue_add_cluster_attrs(cid, this->attribute_list_[key]);
  }
  // Clusters propietaris Hue + Touchlink (nomes al descriptor; les comandes Hue van per 0xFC03).
  const uint16_t hue_clusters[] = {HUE_CLUSTER_FC01, HUE_CLUSTER_FC03, HUE_CLUSTER_FC04, HUE_CLUSTER_TOUCHLINK};
  for (uint16_t cid : hue_clusters) {
    auto key = std::make_tuple(ep, cid, role);
    if (this->attribute_list_.find(key) == this->attribute_list_.end())
      this->attribute_list_[key] = esphome_hue_create_cluster(cid);
  }
  ESP_LOGI(TAG, "Hue: atributs de fabricant 0x%04X i clusters 0xFC01/0xFC03/0xFC04/0x1000 a l'endpoint %u",
           HUE_MANUF_CODE, ep);
}

void ZigBeeComponent::loop() {
  if (!this->hue_emulation_ || !this->is_connected())
    return;
  const uint32_t now = millis();
  if (!this->hue_state_init_ || now - this->hue_last_uptime_ms_ >= 10000) {
    if (esp_zb_lock_acquire(20 / portTICK_PERIOD_MS)) {
      if (!this->hue_state_init_) {
        esphome_hue_refresh_state(this->hue_endpoint_);
        this->hue_state_init_ = true;
      }
      // Diagnostic remot (sense USB): mentre hi ha hagut entreteniment, 0x0021 porta els comptadors en lloc del temps
      // encès (vegeu esphome_hue_ent_diag); el pont el llegeix cada ~minut i el sniffer el desxifra.
      const uint32_t diag = esphome_hue_ent_diag();
      esphome_hue_update_uptime(this->hue_endpoint_, diag != 0 ? diag : now / 1000);
      esp_zb_lock_release();
      this->hue_last_uptime_ms_ = now;
    }
  }
  // Diagnostic del stream d'entreteniment: un resum per segon mentre arriba alguna cosa.
  if (now - this->hue_ent_log_ms_ >= 1000) {
    this->hue_ent_log_ms_ = now;
    esphome_hue_ent_stats_t st;
    esphome_hue_ent_stats(&st);
    const uint32_t tot = st.uni + st.ip_raw + st.ip_aps + st.ip_wrap + st.wrap_calls + st.cmd3;
    if (tot != this->hue_ent_last_total_) {
      ESP_LOGI("hue_ent",
               "Entertainment: unicast=%u interpan_raw=%u interpan_aps=%u interpan_wrap=%u (crides wrap %u) cmd3=%u(estat %u) | "
               "meves=%u altres=%u | seq=0x%04X entrades=%u | flags=0x%02X bri=%u x12=%u y12=%u",
               (unsigned) st.uni, (unsigned) st.ip_raw, (unsigned) st.ip_aps, (unsigned) st.ip_wrap,
               (unsigned) st.wrap_calls, (unsigned) st.cmd3,
               (unsigned) st.session, (unsigned) st.mine, (unsigned) st.other, st.seq, st.entries, st.flags, st.bri,
               st.x12, st.y12);
      this->hue_ent_last_total_ = tot;
      // Cada 10 s, la taula d'entrades: per saber quina adreca curta te cada llum de l'area (segments de la Lola).
      if (now - this->hue_ent_tab_log_ms_ >= 10000) {
        this->hue_ent_tab_log_ms_ = now;
        uint16_t a[HUE_ENT_MAX_ENTRIES], b[HUE_ENT_MAX_ENTRIES], x[HUE_ENT_MAX_ENTRIES], y[HUE_ENT_MAX_ENTRIES];
        const uint8_t n = esphome_hue_ent_table(a, b, x, y, HUE_ENT_MAX_ENTRIES);
        std::string line;
        char buf[48];
        for (uint8_t i = 0; i < n; i++) {
          snprintf(buf, sizeof(buf), "%s0x%04X b=%u x=%.3f y=%.3f", i ? " | " : "", a[i], b[i],
                   x[i] / 4095.0f * HUE_ENT_X_MAX, y[i] / 4095.0f * HUE_ENT_Y_MAX);
          line += buf;
        }
        ESP_LOGI("hue_ent", "Entrades (%u): %s", n, line.c_str());
      }
    }
  }
}

}  // namespace zigbee
}  // namespace esphome

// Pont per a hue_emu.c: un set local d'atribut (comanda Hue 0xFC03 cmd 0x00) no dispara el callback SET_ATTR_VALUE
// de la pila; fem el mateix cami (handle_attribute -> on_value del YAML en el loop principal + estat compacte Hue).
extern "C" void esphome_hue_attr_changed(uint8_t ep, uint16_t cluster, uint16_t attr_id, uint8_t type, void *value,
                                         uint8_t size) {
  esp_zb_device_cb_common_info_t info;
  memset(&info, 0, sizeof(info));
  info.status = ESP_ZB_ZCL_STATUS_SUCCESS;
  info.dst_endpoint = ep;
  info.cluster = cluster;
  esp_zb_zcl_attribute_t attr;
  memset(&attr, 0, sizeof(attr));
  attr.id = attr_id;
  attr.data.type = (esp_zb_zcl_attr_type_t) type;
  attr.data.size = size;
  attr.data.value = value;
  if (esphome::zigbee::zigbeeC != nullptr)
    esphome::zigbee::zigbeeC->handle_attribute(info, attr);
}
