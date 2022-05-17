/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef HDF_AUDIO_EVENTS_H
#define HDF_AUDIO_EVENTS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AUDIO_PNP_MSG_LEN_MAX 256

int32_t AudioPnpMsgReadValue(const char *pnpInfo, const char *typeName, uint32_t *value);

#ifdef __cplusplus
    }
#endif
#endif /* HDF_AUDIO_EVENTS_H */
