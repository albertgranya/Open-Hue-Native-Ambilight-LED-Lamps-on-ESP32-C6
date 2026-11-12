// coex_extern.h — declaracio de la API de coexistencia Wi-Fi / IEEE 802.15.4 del ESP32-C6 que cactushue.yaml crida
// des d'una lambda d'on_boot (prioritat 800) abans que el Wi-Fi arranqui l'scan:
//     int r = esp_coex_wifi_i154_enable();
// La funcio viu a la llibreria esp_coex de l'IDF (esp_coexist.h), pero aquell header no entra per defecte al main
// d'ESPHome; aqui nomes la declarem. (Recreat el 2026-09-27: el fitxer original no era a la carpeta.)
#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t esp_coex_wifi_i154_enable(void);

#ifdef __cplusplus
}
#endif
