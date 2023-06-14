/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ILIGHT_TYPE_VDI_H
#define ILIGHT_TYPE_VDI_H

#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

#define LIGHT_NAME_MAX_LEN    16

enum HdfLightIdVdi {
    VDI_LIGHT_ID_BATTERY = 1,
    VDI_LIGHT_ID_NOTIFICATIONS = 2,
    VDI_LIGHT_ID_ATTENTION = 3,
    VDI_LIGHT_ID_BUTT = 4,
};

enum HdfLightTypeVdi {
    VDI_LIGHT_TYPE_SINGLE_COLOR = 1,
    VDI_LIGHT_TYPE_RGB_COLOR = 2,
    VDI_LIGHT_TYPE_WRGB_COLOR = 3,
};

struct HdfLightInfoVdi {
    char lightName[LIGHT_NAME_MAX_LEN];
    int32_t lightId;
    int32_t lightNumber;
    int32_t lightType;
};

enum HdfLightFlashModeVdi {
    VDI_LIGHT_FLASH_NONE = 0,
    VDI_LIGHT_FLASH_BLINK = 1,
    VDI_LIGHT_FLASH_GRADIENT = 2,
    VDI_LIGHT_FLASH_BUTT = 3,
};

struct HdfLightFlashEffectVdi {
    int32_t flashMode;
    int32_t onTime;
    int32_t offTime;
};

struct RGBColorVdi {
    uint8_t r;
    uint8_t g;
    uint8_t b;
    uint8_t reserved;
};

struct WRGBColorVdi {
    uint8_t w;
    uint8_t r;
    uint8_t g;
    uint8_t b;
};

union ColorValueVdi {
    int32_t singleColor;
    struct WRGBColorVdi wrgbColor;
    struct RGBColorVdi rgbColor;
};

struct HdfLightColorVdi {
    union ColorValueVdi colorValue;
};

struct HdfLightEffectVdi {
    struct HdfLightColorVdi lightColor;
    struct HdfLightFlashEffectVdi flashEffect;
};

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* ILIGHT_TYPE_VDI_H */
/** @} */
