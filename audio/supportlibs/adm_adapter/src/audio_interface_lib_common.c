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

#include "audio_interface_lib_common.h"

struct HdfIoService *HdfIoServiceBindName(const char *serviceName)
{
    if (serviceName == NULL) {
        LOG_FUN_ERR("service name NULL!");
        return NULL;
    }
    if (strcmp(serviceName, "hdf_audio_control") == 0) {
        return (HdfIoServiceBind("hdf_audio_control"));
    }
    if (strcmp(serviceName, "hdf_audio_render") == 0) {
        return (HdfIoServiceBind("hdf_audio_render"));
    }
    if (strcmp(serviceName, "hdf_audio_capture") == 0) {
        return (HdfIoServiceBind("hdf_audio_capture"));
    }
    LOG_FUN_ERR("service name not support!");
    return NULL;
}