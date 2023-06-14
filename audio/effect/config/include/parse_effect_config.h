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

#ifndef PARSE_EFFECT_CONFIG_H
#define PARSE_EFFECT_CONFIG_H

#include <stdint.h>

#define HDF_EFFECT_LIB_NUM_MAX 32

struct LibraryConfigDescriptor {
    const char *libName;
    const char *libPath;
};

struct EffectConfigDescriptor {
    const char *name;
    const char *library;
    const char *effectId;
};

struct ConfigDescriptor {
    struct LibraryConfigDescriptor *libCfgDescs;
    uint32_t libNum;
    struct EffectConfigDescriptor *effectCfgDescs;
    uint32_t effectNum;
};

/**
 * @brief Parse the effect profile and get the effect config descriptor.
 *
 * @param path Indicates the effect configuration file path.
 * @param cfgDesc Indicates pointer of the effect config descriptor.
 *
 * @return Returns <b>0</b> if the process success; returns a non-zero value otherwise.
 *
 * @since 4.0
 * @version 1.0
 */
int32_t AudioEffectGetConfigDescriptor(const char *path, struct ConfigDescriptor **cfgDesc);

/**
 * @brief Release the effect config descriptor.
 *
 * @param cfgDesc Indicates pointer of the effect config descriptor.
 *
 * @return Returns <b>0</b> if the process success; returns a non-zero value otherwise.
 *
 * @since 4.0
 * @version 1.0
 */
void AudioEffectReleaseCfgDesc(struct ConfigDescriptor *cfgDesc);

#endif
