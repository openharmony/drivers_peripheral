/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "securec.h"
#include "audio_types.h"

struct AudioAdapterDescriptor *AudioAdapterGetConfigOut(void);
struct AudioAdapterDescriptor *AudioAdapterGetConfigDescs(void);
int32_t AudioAdapterGetAdapterNum(void);
int32_t AudioAdaptersForUser(struct AudioAdapterDescriptor **descs, int *size);
int32_t AudioAdapterExist(const char *adapterName);
int32_t HdmiPortInit(struct AudioPort portIndex, struct AudioPortCapability *capabilityIndex);
#endif
