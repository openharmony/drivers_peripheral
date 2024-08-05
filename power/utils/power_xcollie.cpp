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

#include "power_hdf_log.h"
#include "power_xcollie.h"
#ifdef HICOLLIE_ENABLE
#include "xcollie/xcollie.h"
#endif

namespace OHOS {
namespace HDI {
namespace Power {
PowerXCollie::PowerXCollie(const std::string &logTag, uint32_t timeoutSeconds)
{
    logTag_ = logTag;
    isCanceled_ = false;
#ifdef HICOLLIE_ENABLE
    id_ = HiviewDFX::XCollie::GetInstance().SetTimer(
        logTag_, timeoutSeconds, nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG | HiviewDFX::XCOLLIE_FLAG_RECOVERY);
#else
    id_ = -1;
#endif
    HDF_LOGD("Start PowerXCollie, id:%{public}d, tag:%{public}s, timeout(s):%{public}u", id_, logTag_.c_str(),
        timeoutSeconds);
}

PowerXCollie::~PowerXCollie()
{
    CancelPowerXCollie();
}

void PowerXCollie::CancelPowerXCollie()
{
    if (!isCanceled_) {
#ifdef HICOLLIE_ENABLE
        HiviewDFX::XCollie::GetInstance().CancelTimer(id_);
#endif
        isCanceled_ = true;
        HDF_LOGD("Cancel PowerXCollie, id:%{public}d, tag:%{public}s", id_, logTag_.c_str());
    }
}

} // namespace Power
} // namespace HDI
} // namespace OHOS