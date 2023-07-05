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

#include "display_buffer_mt.h"

#include <unistd.h>
#include <vector>
#include <thread>
#include <cinttypes>
#include <securec.h>
#include <cstring>

#include "gtest/gtest.h"
#include "v1_0/display_composer_type.h"
#include "hdf_base.h"
#include "hdf_log.h"

namespace OHOS {
namespace HDI {
namespace Display {
namespace TEST {
using namespace OHOS::HDI::Display::Composer::V1_0;
using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace OHOS;
using namespace testing::ext;

static IDisplayBuffer* g_dispbuf = nullptr;
static const int SIZE_TIMES = 3;
static const int HANDLE_NUM_1 = 2;
static const int HANDLE_NUM_2 = 32;
static const int LOOP_COUNT = 10;
static const int INFO_WIDTH = 1024;
static const int INFO_HEIGHT = 1024;

#define HDF_LOG_TAG display_buffer_module_test

static void WriteBuffer(const BufferHandle& handle)
{
    const char VERIFY_MSG[] = "12345678, (*~*)";
    // write msg to display buffer fully.
    int strSize = strlen(VERIFY_MSG) + 1;
    int i = 0;
    char* ptr = reinterpret_cast<char *>(handle.virAddr);
    if (ptr == nullptr) {
        HDF_LOGE("cast ptr failed");
        return;
    }

    for (; i < handle.size - strSize;) {
        errno_t ret = memcpy_s(&ptr[i], sizeof(VERIFY_MSG), VERIFY_MSG, sizeof(VERIFY_MSG));
        if (ret != EOK) {
            HDF_LOGE("memcpy_s error : %d", ret);
            return;
        }
        i += strSize;
        ptr[i - 1] = 0;
    }
    for (i = i - 1; i < handle.size; i++) {
        ptr[i] = 'z';
    }

    // read all contents from buffer
    HDF_LOGD("%{public}s(%{public}d), buffer size:%{public}d, len:%{public}d",
             __func__, __LINE__, handle.size, strSize);
    // verify buffer contents from strings written.
    for (i = 0; i < handle.size - SIZE_TIMES * strSize; i = i + strSize) {
        if (strncmp(VERIFY_MSG, &ptr[i], sizeof(VERIFY_MSG)) != 0) {
            HDF_LOGD("%{public}s(%{public}d), buffer[%{public}d]:%{public}s",
                     __func__, __LINE__, i, &ptr[i]);
        }
    }

    for (i = handle.size - HANDLE_NUM_1; i < (handle.size - HANDLE_NUM_2); i++) {
        HDF_LOGD("%{public}s(%{public}d), i:%{public}d, str:%{public}s",
                 __func__, __LINE__, i, &ptr[i]);
    }
}

static void DumpBufferHandle(const BufferHandle& handle)
{
    // dump buffer handle infomation
    HDF_LOGD("-------------------------------------");
    HDF_LOGD("fd                =%{public}d",   handle.fd);
    HDF_LOGD("width             =%{public}d",   handle.width);
    HDF_LOGD("stride            =%{public}d",   handle.stride);
    HDF_LOGD("height            =%{public}d",   handle.height);
    HDF_LOGD("size              =0x%{public}x", handle.size);
    HDF_LOGD("format            =%{public}d",   handle.format);
    HDF_LOGD("usage             =0x%{public}" PRIx64 "", handle.usage);
    HDF_LOGD("reserveFds        =%{public}d",   handle.reserveFds);
    HDF_LOGD("reserveInts       =%{public}d",   handle.reserveInts);
    HDF_LOGD("-------------------------------------");
}

int32_t DisplayBufferMt::RunTest(const AllocInfo& info)
{
    BufferHandle* bHandle = nullptr;
    // AllocMem
    int32_t ec = g_dispbuf->AllocMem(info, bHandle);
    if (ec != HDF_SUCCESS || bHandle == nullptr) {
        HDF_LOGE("%{public}s, line=%{public}d, AllocMem failed. ec=0x%{public}x",
                 __func__, __LINE__, ec);
        return HDF_FAILURE;
    }

    // Mmap
    void* buffer = g_dispbuf->Mmap(*bHandle);
    if (buffer == nullptr) {
        HDF_LOGE("Mmap failed.");
        g_dispbuf->FreeMem(*bHandle);
        return HDF_FAILURE;
    }
    HDF_LOGD("Mmap successful");

    DumpBufferHandle(*bHandle);
    WriteBuffer(*bHandle);

    // InvalidateCache
    ec = g_dispbuf->InvalidateCache(*bHandle);
    if (ec != HDF_SUCCESS) {
        HDF_LOGE("InvalidateCache failed.");
        g_dispbuf->Unmap(*bHandle);
        g_dispbuf->FreeMem(*bHandle);
        return HDF_FAILURE;
    }
    // InvalidateCache
    ec = g_dispbuf->FlushCache(*bHandle);
    if (ec != HDF_SUCCESS) {
        HDF_LOGE("flushCache failed.");
        g_dispbuf->Unmap(*bHandle);
        g_dispbuf->FreeMem(*bHandle);
        return HDF_FAILURE;
    }
    HDF_LOGD("flush Cache success.");
    // free buffer
    g_dispbuf->Unmap(*bHandle);
    g_dispbuf->FreeMem(*bHandle);
    return HDF_SUCCESS;
}

void DisplayBufferMt::SetUpTestCase()
{
    g_dispbuf = IDisplayBuffer::Get();
    ASSERT_TRUE(g_dispbuf != nullptr);
}

HWTEST_F(DisplayBufferMt, test_DisplayBuffer, TestSize.Level1)
{
    AllocInfo info;
    info.width  = INFO_WIDTH;
    info.height = INFO_HEIGHT;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_RGBA_8888;

    for (int i = 0; i < LOOP_COUNT; i++) {
        int32_t ret = RunTest(info);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}
} // OHOS
} // HDI
} // DISPLAY
} // TEST
