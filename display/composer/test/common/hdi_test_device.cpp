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

#include "hdi_test_device.h"
#include <mutex>
#include "v1_0/include/idisplay_buffer.h"
#include "v1_1/display_composer_type.h"
#include "hdi_test_device_common.h"

namespace OHOS {
namespace HDI {
namespace Display {
namespace TEST {
using namespace OHOS::HDI::Display::Buffer::V1_0;
HdiTestDevice& HdiTestDevice::GetInstance()
{
    static HdiTestDevice device;
    return device;
}

void HdiTestDevice::HotPlug(uint32_t outputId, bool connected, void* data)
{
    DISPLAY_TEST_LOGD("outputId %{public}u connected %{public}d", outputId, connected);
    DISPLAY_TEST_CHK_RETURN_NOT_VALUE((data == nullptr), DISPLAY_TEST_LOGE("the data is null ptr"));
    HdiTestDevice* device = static_cast<HdiTestDevice *>(data);
    if (connected) {
        device->FindDisplayOrCreate(outputId);
    }
    DISPLAY_TEST_LOGD("end");
}

int32_t HdiTestDevice::InitDevice()
{
    displayDevice_ = Composer::V1_2::IDisplayComposerInterface::Get();
    DISPLAY_TEST_CHK_RETURN((displayDevice_ == nullptr), DISPLAY_FAILURE,
        DISPLAY_TEST_LOGE("get IDisplayComposerInterface failed"));

    gralloc_.reset(IDisplayBuffer::Get());
    DISPLAY_TEST_CHK_RETURN((gralloc_ == nullptr), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("get IDisplayBuffer failed"));

    displayDevice_->RegHotPlugCallback(HotPlug, static_cast<void *>(this));

    return DISPLAY_SUCCESS;
}

std::shared_ptr<HdiTestDisplay> HdiTestDevice::GetDisplayFromId(uint32_t id)
{
    auto iter = displays_.find(id);
    DISPLAY_TEST_CHK_RETURN((iter == displays_.end()), nullptr, DISPLAY_TEST_LOGD("can not find the display %{public}u",
        id));
    return displays_[id];
}

std::shared_ptr<HdiTestDisplay> HdiTestDevice::FindDisplayOrCreate(uint32_t id)
{
    int ret;
    std::shared_ptr<HdiTestDisplay> display = GetDisplayFromId(id);
    if (display == nullptr) {
        DISPLAY_TEST_LOGD("the display not find will creat a display");
    }
    display = std::make_shared<HdiTestDisplay>(id, displayDevice_);
    ret = display->Init();
    DISPLAY_TEST_CHK_RETURN((ret != DISPLAY_SUCCESS), nullptr, DISPLAY_TEST_LOGE("can not init the display"));
    displays_.emplace(id, display);
    displayIds_.push_back(id);
    return display;
}

std::shared_ptr<HdiTestDisplay> HdiTestDevice::GetFirstDisplay()
{
    DISPLAY_TEST_CHK_RETURN((displays_.begin() == displays_.end()), nullptr,
        DISPLAY_TEST_LOGE("the displays_ is empty"));
    return displays_.begin()->second;
}

void HdiTestDevice::Clear() const
{
    for (auto const & iter : displays_) {
        iter.second->Clear();
    }
}

std::vector<uint32_t> HdiTestDevice::GetDevIds() const
{
    return displayIds_;
}
} // OHOS
} // HDI
} // Display
} // TEST
