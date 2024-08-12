/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "codec_omx_ext.h"
#include <cstdlib>

extern "C" __attribute__((visibility("default"))) int dlclose(void* handle)
{
    return 0;
}

namespace OHOS {
namespace Codec {
    static const int32_t DATA_BUFFERID = 10;
    static const int32_t DATA_SIZE = 20;
    static const int32_t DATA_VERSION_NVERSION = 30;
    static const int32_t DATA_BUFFERTYPE = 40;
    static const int32_t DATA_BUFFERLEN = 50;
    static const int32_t DATA_ALLOCLEN = 60;
    static const int32_t DATA_FILLEDLEN = 70;
    static const int32_t DATA_OFFSET = 80;
    static const int32_t DATA_FENCEFD = 90;
    static const int32_t DATA_TYPE = 100;
    static const int32_t DATA_PTS = 200;
    static const int32_t DATA_FLAG = 300;
    static const int32_t TESTING_APP_DATA = 33;

    CodecComponentManager *g_manager = nullptr;
    CodecComponentType *g_component = nullptr;
    CodecCallbackType *g_callback = nullptr;
    uint32_t g_componentId = 0;
    static int32_t g_appData = TESTING_APP_DATA;

    uint32_t Convert2Uint32(const uint8_t* ptr)
    {
        if (ptr == nullptr) {
            return 0;
        }
        /*
         * Move the 0th digit 24 to the left, the first digit 16 to the left, the second digit 8 to the left,
         * and the third digit no left
         */
        return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | (ptr[3]);
    }

    void FillDataOmxCodecBuffer(struct OmxCodecBuffer *dataFuzz)
    {
        dataFuzz->bufferId = DATA_BUFFERID;
        dataFuzz->size = DATA_SIZE;
        dataFuzz->version.nVersion = DATA_VERSION_NVERSION;
        dataFuzz->bufferType = static_cast<enum CodecBufferType>(DATA_BUFFERTYPE);
        dataFuzz->buffer = reinterpret_cast<uint8_t *>(OsalMemAlloc(DATA_BUFFERLEN));
        if (dataFuzz->buffer == nullptr) {
            HDF_LOGE("%{public}s: dataFuzz->buffer is nullptr", __func__);
            return;
        }
        dataFuzz->bufferLen = DATA_BUFFERLEN;
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
        g_manager = GetCodecComponentManager();
        if (g_manager == nullptr) {
            HDF_LOGE("%{public}s: GetCodecComponentManager failed\n", __func__);
            return false;
        }

        g_callback = CodecCallbackTypeStubGetInstance();
        if (g_callback == nullptr) {
            HDF_LOGE("%{public}s: CodecCallbackTypeStubGetInstance failed\n", __func__);
            return false;
        }

        int32_t count = g_manager->GetComponentNum();
        if (count <= 0) {
            CodecCallbackTypeRelease(g_callback);
            HDF_LOGE("%{public}s GetComponentNum count = %{public}d", __func__, count);
            return false;
        }

        CodecCompCapability *capList = reinterpret_cast<CodecCompCapability *>(OsalMemAlloc(sizeof(CodecCompCapability)
            * count));
        if (capList == nullptr) {
            CodecCallbackTypeRelease(g_callback);
            HDF_LOGE("%{public}s: OsalMemAlloc CodecCompCapability failed\n", __func__);
            return false;
        }

        int32_t ret = g_manager->GetComponentCapabilityList(capList, count);
        if (ret != HDF_SUCCESS) {
            OsalMemFree(capList);
            CodecCallbackTypeRelease(g_callback);
            HDF_LOGI("%{public}s: GetComponentCapabilityList succeed\n", __func__);
            return false;
        }

        ret = g_manager->CreateComponent(&g_component, &g_componentId, capList[0].compName, g_appData, g_callback);
        if (ret != HDF_SUCCESS) {
            OsalMemFree(capList);
            CodecCallbackTypeRelease(g_callback);
            HDF_LOGE("%{public}s: CreateComponent failed\n", __func__);
            return false;
        }
        OsalMemFree(capList);
        return true;
    }

    bool Destroy()
    {
        int32_t ret = g_manager->DestroyComponent(g_componentId);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: DestroyComponent failed\n", __func__);
            return false;
        }
        CodecCallbackTypeRelease(g_callback);
        CodecComponentTypeRelease(g_component);
        CodecComponentManagerRelease();
        return true;
    }
} // namespace codec
} // namespace OHOS
