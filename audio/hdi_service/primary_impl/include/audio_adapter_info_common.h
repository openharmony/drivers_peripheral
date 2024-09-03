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

#ifndef AUDIO_ADAPTER_INFO_COMMON_H
#define AUDIO_ADAPTER_INFO_COMMON_H

#include <stdio.h>
#include "audio_internal.h"
#include "v3_0/audio_types.h"

#define AUDIO_PRIMARY_ID_MIN 0
#define AUDIO_PRIMARY_ID_MAX 10

#define AUDIO_PRIMARY_EXT_ID_MIN 11
#define AUDIO_PRIMARY_EXT_ID_MAX 20

#define AUDIO_HDMI_ID_MIN 11
#define AUDIO_HDMI_ID_MAX 20

#define AUDIO_USB_ID_MIN 21
#define AUDIO_USB_ID_MAX 30

#define AUDIO_A2DP_ID_MIN 31
#define AUDIO_A2DP_ID_MAX 40

enum AudioAdapterType {
    AUDIO_ADAPTER_PRIMARY = 0, /* internel sound card */
    AUDIO_ADAPTER_PRIMARY_EXT, /* extern sound card */
    AUDIO_ADAPTER_HDMI,        /* hdmi sound card */
    AUDIO_ADAPTER_USB,         /* usb sound card */
    AUDIO_ADAPTER_A2DP,        /* blue tooth sound card */
    AUDIO_ADAPTER_MAX,         /* Invalid value. */
};

enum AudioAdapterType MatchAdapterType(const char *adapterName, uint32_t portId);
struct AudioAdapterDescriptor *AudioAdapterGetConfigDescs(void);
int32_t AudioAdapterGetAdapterNum(void);
int32_t AudioAdaptersForUser(InterfaceLibModeGetAllCardInfo getAllCardInfo,
    struct AudioAdapterDescriptor *descs, uint32_t *size);
int32_t AudioAdapterExist(const char *adapterName);
int32_t InitPortForCapabilitySub(struct AudioPort portIndex, struct AudioPortCapability *capabilityIndex);
int32_t AddElementToList(char *keyValueList, int32_t listLenth, const char *key, void *value);
int32_t GetErrorReason(int reason, char *reasonDesc);
int32_t GetCurrentTime(char *currentTime);
int32_t FormatToBits(enum AudioFormat format, uint32_t *formatBits);
int32_t AudioSetExtraParams(const char *keyValueList, int32_t *count, struct ExtraParams *mExtraParams, int32_t *sumOk);
int32_t SetDescParam(
    struct AudioMmapBufferDescriptor *desc, FILE *fp, int32_t reqSize, int64_t *fileSize, int32_t *flags);
bool ReleaseAudioManagerObjectComm(struct IAudioManager *object);

#endif
