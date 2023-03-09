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

#define HDF_LOG_TAG codec_fuzz

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

CodecComponentManager *g_manager = nullptr;
CodecComponentType *g_component = nullptr;
CodecCallbackType *g_callback = nullptr;
uint32_t g_componentId = 0;
static int32_t g_appData = testingAppData;

void FillDataOmxCodecBuffer(struct OmxCodecBuffer *dataFuzz)
{
    dataFuzz->bufferId = DATA_BUFFERID;
    dataFuzz->size = DATA_SIZE;
    dataFuzz->version.nVersion = DATA_VERSION_NVERSION;
    dataFuzz->bufferType = (enum CodecBufferType)DATA_BUFFERTYPE;
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
    dataFuzz->type = (enum ShareMemTypes)DATA_TYPE;
    dataFuzz->pts = DATA_PTS;
    dataFuzz->flag = DATA_FLAG;
}

bool Preconditions()
{
    g_manager = GetCodecComponentManager();
    if (g_manager == nullptr) {
        HDF_LOGE("%{public}s: GetCodecComponentManager failed", __func__);
        return false;
    }

    g_callback = CodecCallbackTypeGet(nullptr);
    if (g_callback == nullptr) {
        HDF_LOGE("%{public}s: CodecCallbackTypeGet failed", __func__);
        CodecComponentManagerRelease();
        return false;
    }

    int32_t componentCount = g_manager->GetComponentNum();
    if (componentCount <= 0) {
        HDF_LOGE("%{public}s: GetComponentNum failed", __func__);
        CodecCallbackTypeRelease(g_callback);
        CodecComponentManagerRelease();
        return false;
    }

    CodecCompCapability *capList = new CodecCompCapability[componentCount];
    if (capList == nullptr) {
        HDF_LOGE("%{public}s: new CodecCompCapability failed", __func__);
        CodecCallbackTypeRelease(g_callback);
        CodecComponentManagerRelease();
        return false;
    }

    int32_t ret = g_manager->GetComponentCapabilityList(capList, componentCount);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: GetComponentCapabilityList failed", __func__);
        delete[] capList;
        CodecCallbackTypeRelease(g_callback);
        CodecComponentManagerRelease();
        return false;
    }

    ret = g_manager->CreateComponent(&g_component, &g_componentId, capList[0].compName, g_appData, g_callback);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: CreateComponent failed", __func__);
        delete[] capList;
        CodecCallbackTypeRelease(g_callback);
        CodecComponentManagerRelease();
        return false;
    }
    delete[] capList;

    return true;
}

bool Destroy()
{
    int32_t ret = g_manager->DestroyComponent(g_componentId);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: DestroyComponent failed", __func__);
        return false;
    }
    CodecCallbackTypeRelease(g_callback);
    CodecComponentManagerRelease();
    return true;
}
} // namespace Codec
} // namespace OHOS