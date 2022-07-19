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

#include "codeccommon_fuzzer.h"
#include "codec_omx_ext.h"
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
    static const int32_t testingAppData = 33;

    CodecComponentManager *manager = nullptr;
    CodecComponentType *component = nullptr;
    CodecCallbackType *callback = nullptr;
    uint32_t componentId = 0;
    static int32_t appData = testingAppData;

    void FillDataOmxCodecBuffer(struct OmxCodecBuffer *dataFuzz)
    {
        dataFuzz->bufferId = DATA_BUFFERID;
        dataFuzz->size = DATA_SIZE;
        dataFuzz->version.nVersion = DATA_VERSION_NVERSION;
        dataFuzz->bufferType = (enum CodecBufferType)DATA_BUFFERTYPE;
        dataFuzz->buffer = (uint8_t*)OsalMemAlloc(DATA_BUFFERLEN);
        dataFuzz->bufferLen = DATA_BUFFERLEN;
        dataFuzz->allocLen = DATA_ALLOCLEN;
        dataFuzz->filledLen = DATA_FILLEDLEN;
        dataFuzz->offset = DATA_OFFSET;
        dataFuzz->fenceFd = DATA_FENCEFD;
        dataFuzz->type = (enum ShareMemTypes)DATA_TYPE;
        dataFuzz->pts = DATA_PTS;
        dataFuzz->flag = DATA_FLAG;
    }

    bool Preconditions()
    {
        manager = GetCodecComponentManager();
        callback = CodecCallbackTypeStubGetInstance();
        if (manager == nullptr) {
            HDF_LOGE("%{public}s: GetCodecComponentManager failed\n", __func__);
            return false;
        }

        int32_t ret = manager->CreateComponent(&component, &componentId, (char*)"compName", appData, callback);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: CreateComponent failed\n", __func__);
            return false;
        }

        OMX_STATETYPE state;
        ret = component->GetState(component, &state);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: GetState Component failed\n", __func__);
            return false;
        }

        return true;
    }

    bool Destroy()
    {
        int32_t ret = manager->DestroyComponent(componentId);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: DestroyComponent failed\n", __func__);
            return false;
        }
        CodecComponentTypeRelease(component);
        CodecComponentManagerRelease();
        return true;
    }
} // namespace codec
} // namespace OHOS