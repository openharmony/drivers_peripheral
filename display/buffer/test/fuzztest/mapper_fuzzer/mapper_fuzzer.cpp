/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "mapper_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <securec.h>
#include "hdf_base.h"
#include "display_common_fuzzer.h"
namespace OHOS {
using namespace OHOS::HDI::Display::Buffer;
using namespace OHOS::HDI::Display::Buffer::V1_2;
using namespace OHOS::HDI::Display::Composer::V1_0;
static std::shared_ptr<OHOS::HDI::Display::Buffer::V1_2::IDisplayBuffer> g_bufferInterface = nullptr;

static bool g_isInit = false;
static const uint8_t* RANDOM_DATA = nullptr;
static size_t g_dataSize = 0;
static size_t g_pos;
/*
* describe: get data from outside untrusted data(RANDOM_DATA) which size is according to sizeof(T)
* tips: only support basic type
*/
template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (RANDOM_DATA == nullptr || objectSize > g_dataSize - g_pos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, RANDOM_DATA + g_pos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_pos += objectSize;
    return object;
}

static int32_t GetAllocInfo(OHOS::HDI::Display::Buffer::V1_0::AllocInfo& info)
{
    uint32_t lenUsage = GetArrLength(CONVERT_TABLE_USAGE);
    if (lenUsage == 0) {
        HDF_LOGE("%{public}s: CONVERT_TABLE_USAGE length is equal to 0", __func__);
        return DISPLAY_FAILURE;
    }
    uint32_t lenFormat = GetArrLength(CONVERT_TABLE_FORMAT);
    if (lenFormat == 0) {
        HDF_LOGE("%{public}s: CONVERT_TABLE_FORMAT length is equal to 0", __func__);
        return DISPLAY_FAILURE;
    }

    info.width = GetData<uint32_t>() % WIDTH;
    info.height = GetData<uint32_t>() % HEIGHT;
    info.usage = CONVERT_TABLE_USAGE[GetData<uint32_t>() % lenUsage];
    info.format = CONVERT_TABLE_FORMAT[GetData<uint32_t>() % lenFormat];
    info.expectedSize = info.width * info.height;
    return DISPLAY_SUCCESS;
}

BufferHandle* UsingAllocmem()
{
    AllocInfo info = { 0 };
    int32_t ret = GetAllocInfo(info);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetAllocInfo failed", __func__);
        return nullptr;
    }

    BufferHandle* handle = nullptr;
    ret = g_bufferInterface->AllocMem(info, handle);
    if (ret != DISPLAY_SUCCESS && handle != nullptr) {
        HDF_LOGE("%{public}s: function AllocMem failed", __func__);
        g_bufferInterface->FreeMem(*handle);
        return nullptr;
    }
    return handle;
}

void TestFreeMem(const BufferHandle& handle)
{
    (void)g_bufferInterface->FreeMem(handle);
}

void TestMmapUnmap(const BufferHandle& handle)
{
    (void)g_bufferInterface->Mmap(handle);
    (void)g_bufferInterface->Unmap(handle);
    (void)g_bufferInterface->FreeMem(handle);
}

void TestFlushCache(const BufferHandle& handle)
{
    (void)g_bufferInterface->FlushCache(handle);
    (void)g_bufferInterface->FreeMem(handle);
}

void TestInvalidateCache(const BufferHandle& handle)
{
    (void)g_bufferInterface->InvalidateCache(handle);
    (void)g_bufferInterface->FreeMem(handle);
}

void TestGetImageLayout(const BufferHandle& handle)
{
    V1_2::ImageLayout layout = {0};
    (void)g_bufferInterface->GetImageLayout(handle, layout);
    (void)g_bufferInterface->FreeMem(handle);
}

using TestFuncs = void (*)(const BufferHandle&);

TestFuncs g_testFuncs[] = {
    TestFreeMem,
    TestMmapUnmap,
    TestFlushCache,
    TestInvalidateCache,
    TestGetImageLayout
};

bool FuzzTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr) {
        return false;
    }

    if (!g_isInit) {
        g_isInit = true;
        g_bufferInterface.reset(OHOS::HDI::Display::Buffer::V1_1::IDisplayBuffer::Get());
        if (g_bufferInterface == nullptr) {
            HDF_LOGE("%{public}s: get IDisplayBuffer failed", __func__);
            return false;
        }
    }

    // initialize data
    RANDOM_DATA = rawData;
    g_dataSize = size;
    g_pos = 0;
    BufferHandle* buffer = UsingAllocmem();
    if (buffer == nullptr) {
        HDF_LOGE("%{public}s: function UsingAllocmem failed", __func__);
        return false;
    }

    uint32_t code = GetData<uint32_t>();
    uint32_t len = GetArrLength(g_testFuncs);
    if (len == 0) {
        HDF_LOGE("%{public}s: g_testFuncs length is equal to 0", __func__);
        g_bufferInterface->FreeMem(*buffer);
        return false;
    }

    g_testFuncs[code % len](*buffer);
    return true;
}
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < OHOS::THRESHOLD) {
        return 0;
    }

    OHOS::FuzzTest(data, size);
    return 0;
}
