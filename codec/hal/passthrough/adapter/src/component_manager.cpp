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

#include "component_manager.h"
#include <hdf_log.h>
#include "codec_interface.h"
#include "hdf_base.h"

#define HDF_LOG_TAG codec_hdi_passthrough

namespace OHOS {
namespace Codec {
namespace CodecAdapter {
int32_t ComponentManager::CreateComponentInstance(const char *componentName, CODEC_HANDLETYPE &component)
{
    HDF_LOGI("ComponentManager::CreateComponentInstance:%{public}s", componentName);
    int32_t ret = CodecCreate(componentName, &component);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s error, CodecCreate failed errNo: %{public}x", __func__, ret);
    }
    return ret;
}

int32_t ComponentManager::DeleteComponentInstance(CODEC_HANDLETYPE component)
{
    if (component == nullptr) {
        HDF_LOGE("%{public}s error, component is null ", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret = CodecDestroy(component);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s error, CodecDestroy failed errNo: %{public}x", __func__, ret);
    }
    return ret;
}

int32_t ComponentManager::Init()
{
    int32_t ret = CodecInit();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s error, CodecInit failed errNo: %{public}x", __func__, ret);
    }
    return ret;
}

int32_t ComponentManager::Deinit()
{
    int32_t ret = CodecDeinit();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s error, CodecDeinit failed errNo: %{public}x", __func__, ret);
    }
    return ret;
}
}  // namespace CodecAdapter
}  // namespace Codec
}  // namespace OHOS
