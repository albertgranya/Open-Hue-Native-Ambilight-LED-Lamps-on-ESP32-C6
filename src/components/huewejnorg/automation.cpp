#include "automation.h"
#include <algorithm>
#include <cmath>
#include <cstring>
#include "esphome/core/log.h"

namespace esphome {
namespace zigbee {

/**
 * @brief sRGB to R'G'B' gamma correction as outlined in
 *        https://en.wikipedia.org/wiki/SRGB
 *
 * @param linear a component value in sRGB color space
 * @return float the corresponding component value in R'G'B' color space
 */
inline float gamma_correct(float linear) {
  if(linear < 0.0031308f) {
    return linear * 12.92f;
  } else {
    return (1.055f) * pow(linear, (1.0f / 2.4f)) - 0.055f;
  }
}

/* The following conversions operate on xyY with Y = 1.0, hence Y
   doesn't appear in the formulas. The coefficients originate from
   https://en.wikipedia.org/wiki/SRGB#Primaries
 */
float get_r_from_xy(float x, float y) {
  float z = 1.0f - x - y;
  float X = x / y;
  float Z = z / y;
  float r = X * 3.2406 - 1.5372f - Z * 0.4986f;
  return std::clamp(gamma_correct(r), 0.0f, 1.0f);
}

float get_g_from_xy(float x, float y) {
  float z = 1.0f - x - y;
  float X = x / y;
  float Z = z / y;
  float g = -X * 0.9689f + 1.8758f + Z * 0.0415f;
  return std::clamp(gamma_correct(g), 0.0f, 1.0f);
}

float get_b_from_xy(float x, float y) {
  float z = 1.0f - x - y;
  float X = x / y;
  float Z = z / y;

  float b = X * 0.0557f - 0.2040f + Z * 1.0570f;
  return std::clamp(gamma_correct(b), 0.0f, 1.0f);
}

// Gamut de la tira per a xy_to_rgb: matriu XYZ -> RGB lineal calculada a partir dels xy dels tres LEDs
// (xy_set_primaries) i normalitzada perque el blanc de referencia doni (1, 1, 1). Per defecte, els primaris sRGB.
// Sortida: el canal mes fort a 1, codificat amb 1/gamma perque el gamma_correct de la llum ESPHome el desfaci i el LED
// rebi el valor lineal (abans es codificava en sRGB i ESPHome hi aplicava 2,8 a sobre: els canals petits, el "blanc"
// d'un rosa o d'un blau clar, quedaven a la meitat). Els colors fora del gamut (canal negatiu) no es retallen: s'hi
// afegeix blanc fins a la vora, que conserva el to (el rosa Hue, fora de sRGB, sortia magenta pur).
static float s_xy_m[9] = {3.2406f, -1.5372f, -0.4986f, -0.9689f, 1.8758f, 0.0415f, 0.0557f, -0.2040f, 1.0570f};
static float s_xy_gamma = 2.8f;      // gamma_correct de la llum ESPHome
static float s_xy_white_mix = 0.0f;  // 0 = colorimetric; 1 = tot blanc

static void xyz_of_xy(float x, float y, float *v) {
  v[0] = x / y;
  v[1] = 1.0f;
  v[2] = (1.0f - x - y) / y;
}

static bool invert3(const float *a, float *o) {
  const float det = a[0] * (a[4] * a[8] - a[5] * a[7]) - a[1] * (a[3] * a[8] - a[5] * a[6]) +
                    a[2] * (a[3] * a[7] - a[4] * a[6]);
  if (fabsf(det) < 1e-9f)
    return false;
  const float d = 1.0f / det;
  o[0] = (a[4] * a[8] - a[5] * a[7]) * d;
  o[1] = -(a[1] * a[8] - a[2] * a[7]) * d;
  o[2] = (a[1] * a[5] - a[2] * a[4]) * d;
  o[3] = -(a[3] * a[8] - a[5] * a[6]) * d;
  o[4] = (a[0] * a[8] - a[2] * a[6]) * d;
  o[5] = -(a[0] * a[5] - a[2] * a[3]) * d;
  o[6] = (a[3] * a[7] - a[4] * a[6]) * d;
  o[7] = -(a[0] * a[7] - a[1] * a[6]) * d;
  o[8] = (a[0] * a[4] - a[1] * a[3]) * d;
  return true;
}

void xy_set_primaries(float rx, float ry, float gx, float gy, float bx, float by, float wx, float wy) {
  if (ry < 0.001f || gy < 0.001f || by < 0.001f || wy < 0.001f) {
    ESP_LOGW(TAG, "xy_set_primaries: y nul, mantinc la matriu actual");
    return;
  }
  float r[3], g[3], b[3], w[3];
  xyz_of_xy(rx, ry, r);
  xyz_of_xy(gx, gy, g);
  xyz_of_xy(bx, by, b);
  xyz_of_xy(wx, wy, w);
  // P: columnes = XYZ dels primaris. S = P^-1 * W escala cada primari perque R+G+B = blanc de referencia.
  const float p[9] = {r[0], g[0], b[0], r[1], g[1], b[1], r[2], g[2], b[2]};
  float pi[9], ps[9], m[9], sc[3];
  if (!invert3(p, pi)) {
    ESP_LOGW(TAG, "xy_set_primaries: primaris degenerats, mantinc la matriu actual");
    return;
  }
  for (int i = 0; i < 3; i++)
    sc[i] = pi[i * 3] * w[0] + pi[i * 3 + 1] * w[1] + pi[i * 3 + 2] * w[2];
  for (int i = 0; i < 3; i++)
    for (int j = 0; j < 3; j++)
      ps[i * 3 + j] = p[i * 3 + j] * sc[j];
  if (!invert3(ps, m)) {
    ESP_LOGW(TAG, "xy_set_primaries: matriu no invertible, mantinc la matriu actual");
    return;
  }
  memcpy(s_xy_m, m, sizeof(s_xy_m));
  ESP_LOGI(TAG, "gamut tira: R(%.3f,%.3f) G(%.3f,%.3f) B(%.3f,%.3f) blanc(%.4f,%.4f)", rx, ry, gx, gy, bx, by, wx, wy);
}

void xy_set_output(float gamma, float white_mix) {
  s_xy_gamma = gamma < 0.1f ? 1.0f : gamma;
  s_xy_white_mix = std::clamp(white_mix, 0.0f, 1.0f);
  ESP_LOGI(TAG, "sortida xy->rgb: gamma %.2f, mescla de blanc %.2f", s_xy_gamma, s_xy_white_mix);
}

void xy_to_rgb(float x, float y, float *r, float *g, float *b) {
  if (y < 0.001f) {
    *r = *g = *b = 1.0f;
    return;
  }
  float v[3], c[3];
  xyz_of_xy(x, y, v);
  for (int i = 0; i < 3; i++)
    c[i] = s_xy_m[i * 3] * v[0] + s_xy_m[i * 3 + 1] * v[1] + s_xy_m[i * 3 + 2] * v[2];
  const float mn = std::min(c[0], std::min(c[1], c[2]));
  if (mn < 0.0f)  // fora del gamut: blanc fins a la vora
    for (auto &ch : c)
      ch -= mn;
  const float m = std::max(c[0], std::max(c[1], c[2]));
  if (m <= 0.0f) {
    *r = *g = *b = 1.0f;
    return;
  }
  const float e = 1.0f / s_xy_gamma;
  for (auto &ch : c) {
    ch = ch / m;                                 // canal mes fort a 1
    ch = ch + s_xy_white_mix * (1.0f - ch);      // ajust fi: mescla cap al blanc
    ch = std::clamp(powf(ch, e), 0.0f, 1.0f);    // codificacio que desfa el gamma_correct de la llum
  }
  *r = c[0];
  *g = c[1];
  *b = c[2];
}

#ifdef USE_LIGHT
void set_light_color(uint8_t ep, light::LightCall *call, uint16_t value, bool is_x) {
  static std::map<uint8_t, float> x;
  static std::map<uint8_t, float> y;
  if (is_x) {
    x[ep] = (float) value / 65536;
  } else {
    y[ep] = (float) value / 65536;
  }
  ESP_LOGD(TAG, "Set color, x: %f, y: %f", x[ep], y[ep]);
  call->set_rgb(get_r_from_xy(x[ep], y[ep]), get_g_from_xy(x[ep], y[ep]), get_b_from_xy(x[ep], y[ep]));
}
#endif

}  // namespace zigbee
}  // namespace esphome
