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

#include "set_display_backlight_fuzzer.h"
#include "buffer_handle.h"
#include "hdi_test_device.h"
#include "v1_0/display_buffer_type.h"
#include "v1_0/display_composer_type.h"
#include "v1_0/include/idisplay_buffer.h"
#include "v1_0/include/idisplay_composer_interface.h"

using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace OHOS::HDI::Display::Composer::V1_0;
using HDI::Display::TEST::HdiTestDevice;

std::shared_ptr<IDisplayComposerInterface> composerDevice {};
static bool g_isInit = false;

namespace OHOS {
bool FuzzTest(const uint8_t *data, size_t size)
{
    if (!g_isInit) {
        g_isInit = true;
        HdiTestDevice::GetInstance().InitDevice();
        composerDevice = HdiTestDevice::GetInstance().GetDeviceInterface();
    }

    bool result = false;
    auto ret = composerDevice->SetDisplayBacklight(*(uint32_t *)data, *(uint32_t *)data);
    if (!ret) {
        result = true;
    }
    return result;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzTest(data, size);
    return 0;
}
