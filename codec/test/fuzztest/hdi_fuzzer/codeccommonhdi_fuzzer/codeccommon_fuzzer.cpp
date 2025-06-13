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

#include "codeccommon_fuzzer.h"
#include <cstdlib>

using namespace OHOS::HDI::Codec::V4_0;

extern "C" __attribute__((visibility("default"))) int dlclose(void* handle)
{
    return 0;
}

namespace OHOS {
namespace Codec {
    static const int32_t DATA_BUFFERID = 10;
    static const int32_t DATA_SIZE = 20;
    static const int32_t DATA_VERSION_NVERSION = 30;
    static const int32_t DATA_ALLOCLEN = 60;
    static const int32_t DATA_FILLEDLEN = 70;
    static const int32_t DATA_OFFSET = 80;
    static const int32_t DATA_FENCEFD = 90;
    static const int32_t DATA_TYPE = 100;
    static const int32_t DATA_PTS = 200;
    static const int32_t DATA_FLAG = 300;
    static const int32_t TESTING_APP_DATA = 33;

    uint32_t g_componentId = 0;
    static int32_t g_appData = TESTING_APP_DATA;

    void Release()
    {
        g_component = nullptr;
        g_callback = nullptr;
        g_manager = nullptr;
    }

    void FillDataOmxCodecBuffer(struct OmxCodecBuffer *dataFuzz)
    {
        dataFuzz->bufferId = DATA_BUFFERID;
        dataFuzz->size = DATA_SIZE;
        dataFuzz->version.nVersion = DATA_VERSION_NVERSION;
        dataFuzz->bufferType = CODEC_BUFFER_TYPE_DMA_MEM_FD;
        dataFuzz->bufferhandle = nullptr;
        dataFuzz->fd = -1;
        dataFuzz->allocLen = DATA_ALLOCLEN;
        dataFuzz->filledLen = DATA_FILLEDLEN;
        dataFuzz->offset = DATA_OFFSET;
        dataFuzz->fenceFd = DATA_FENCEFD;
        dataFuzz->type = static_cast<enum ShareMemTypes>(DATA_TYPE);
        dataFuzz->pts = DATA_PTS;
        dataFuzz->flag = DATA_FLAG;
    }

    bool Preconditions()
    {
        g_manager = ICodecComponentManager::Get(true);
        if (g_manager == nullptr) {
            HDF_LOGE("%{public}s: ICodecComponentManager failed", __func__);
            return false;
        }

        g_callback = new CodecCallbackFuzz();
        if (g_callback == nullptr) {
            HDF_LOGE("%{public}s: codeccallback_fuzzer failed", __func__);
            Release();
            return false;
        }

        int32_t count = 0;
        auto err = g_manager->GetComponentNum(count);
        if (err != HDF_SUCCESS || count <= 0) {
            HDF_LOGE("%{public}s GetComponentNum return %{public}d, count = %{public}d", __func__, err, count);
            Release();
            return false;
        }

        std::vector<CodecCompCapability> caps;
        err = g_manager->GetComponentCapabilityList(caps, count);
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%{public}s GetComponentCapabilityList return %{public}d", __func__, err);
            Release();
            return false;
        }

        int32_t ret = g_manager->CreateComponent(g_component, g_componentId, caps[0].compName, g_appData, g_callback);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: CreateComponent failed\n", __func__);
            Release();
            return false;
        }

        return true;
    }

    bool Destroy()
    {
        if (g_manager == nullptr) {
            HDF_LOGE("%{public}s: ICodecComponentManager failed", __func__);
            return false;
        }

        int32_t ret = g_manager->DestroyComponent(g_componentId);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: DestroyComponent failed\n", __func__);
            Release();
            return false;
        }
        Release();
        return true;
    }
} // namespace codec
} // namespace OHOS
