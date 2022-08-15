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

#include <unistd.h>
#include <vector>
#include <thread>
#include <inttypes.h>
#include <securec.h>
#include "hdf_base.h"
#include "hdf_log.h"
#include "gtest/gtest.h"
#include "v1_0/display_composer_type.h"
#include "v1_0/iallocator_interface.h"
#include "v1_0/imapper_interface.h"
#include "v1_0/display_buffer_type.h"
#include "v1_0/hdi_impl/display_buffer_hdi_impl.h"

#define HDF_LOG_TAG display_buffer_module_test

namespace {
    const int SIZE_TIMES = 3;
    const int HANDLE_NUM_1 = 2;
    const int HANDLE_NUM_2 = 32;
    const int LOOP_COUNT = 10;
    const int INFO_WIDTH = 1024;
    const int INFO_HEIGHT = 1024;
}

using namespace OHOS::HDI::Display::Composer::V1_0;
using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace OHOS;

static void WriteBuffer(const BufferHandle& handle)
{
    const char verifyMsg[] = "12345678, (*~*)";
    // write msg to display buffer fully.
    int strSize = strlen(verifyMsg) + 1;
    int i = 0;
    char* ptr = reinterpret_cast<char *>(handle.virAddr);

    for (; i < handle.size - strSize;) {
        errno_t ret = memcpy_s(&ptr[i], sizeof(verifyMsg), verifyMsg, sizeof(verifyMsg));
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
    HDF_LOGE("%{public}s(%{public}d), buffer size:%{public}d, len:%{public}d",
             __func__, __LINE__, handle.size, strSize);
    // verify buffer contents from strings written.
    for (i = 0; i < handle.size - SIZE_TIMES * strSize; i = i + strSize) {
        if (strcmp(verifyMsg, &ptr[i]) != 0) {
            HDF_LOGE("%{public}s(%{public}d), buffer[%{public}d]->%{public}p:%{public}s",
                     __func__, __LINE__, i, &ptr[i], &ptr[i]);
        }
    }

    for (i = handle.size - HANDLE_NUM_1; i < (handle.size - HANDLE_NUM_2); i++) {
        HDF_LOGE("%{public}s(%{public}d), i:%{public}d, addr=%{public}p, str:%{public}s",
                 __func__, __LINE__, i, &ptr[i], &ptr[i]);
    }
}

static void DumpBufferHandle(const BufferHandle& handle)
{
    // dump buffer handle infomation
    HDF_LOGE("-------------------------------------");
    HDF_LOGE("fd                =%{public}d",   handle.fd);
    HDF_LOGE("width             =%{public}d",   handle.width);
    HDF_LOGE("stride            =%{public}d",   handle.stride);
    HDF_LOGE("height            =%{public}d",   handle.height);
    HDF_LOGE("size              =0x%{public}x", handle.size);
    HDF_LOGE("format            =%{public}d",   handle.format);
    HDF_LOGE("usage             =0x%{public}" PRIx64 "", handle.usage);
    HDF_LOGE("virAddr           =%{public}p",   handle.virAddr);
    HDF_LOGE("key               =%{public}d",   handle.key);
    HDF_LOGE("reserveFds        =%{public}d",   handle.reserveFds);
    HDF_LOGE("reserveInts       =%{public}d",   handle.reserveInts);
    HDF_LOGE("-------------------------------------");
}

static void RunOnce(const AllocInfo& info)
{
    static int32_t count = 0;
    IDisplayBuffer* dispbuf = IDisplayBuffer::Get<DisplayBufferHdiImpl>();
    if (dispbuf == nullptr) {
        HDF_LOGE("Can't get IDisplayBuffer interface.");
        return;
    }
    BufferHandle* bHandle = nullptr;
    // AllocMem
    int32_t ec = dispbuf->AllocMem(info, bHandle);
    if (ec != HDF_SUCCESS) {
        HDF_LOGE("%{public}s, line=%{public}d, AllocMem failed. ec=0x%{public}x",
                 __func__, __LINE__, ec);
        return;
    }
    HDF_LOGE("AllocMem successful, BufferHandle=%{public}p", bHandle);
    // Mmap
    void* buffer = dispbuf->Mmap(*bHandle);
    if (buffer == nullptr) {
        HDF_LOGE("Mmap failed.");
        return;
    }
    HDF_LOGE("Mmap successful, buffer=%{public}p", buffer);

    DumpBufferHandle(*bHandle);

    WriteBuffer(*bHandle);

    // InvalidateCache
    ec = dispbuf->InvalidateCache(*bHandle);
    if (ec != HDF_SUCCESS) {
        HDF_LOGE("InvalidateCache failed.");
        return;
    }
    // InvalidateCache
    ec = dispbuf->FlushCache(*bHandle);
    if (ec != HDF_SUCCESS) {
        HDF_LOGE("flushCache failed.");
        return;
    }
    HDF_LOGE("flush Cache success.");
    // free buffer
    dispbuf->Unmap(*bHandle);
    dispbuf->FreeMem(*bHandle);
    HDF_LOGE("FreeMem, finished count = %{public}d", ++count);
    delete dispbuf;
    HDF_LOGE("FreeMem1, finished count = %{public}d", ++count);
}

int main()
{
    HDF_LOGE("Main process start.");
    AllocInfo info;
    info.width  = INFO_WIDTH;
    info.height = INFO_HEIGHT;
    info.usage = OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ |
            OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE;
    info.format = PIXEL_FMT_RGBA_8888;

    std::vector<std::thread *> ths;
    for (int i = 0; i < LOOP_COUNT; i++) {
        RunOnce(info);
    }
    HDF_LOGE("Main process end.");
    return 0;
}
