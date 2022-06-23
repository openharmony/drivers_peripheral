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

#ifndef THERMAL_LOG_H
#define THERMAL_LOG_H

#define CONFIG_HILOG
#ifdef CONFIG_HILOG
#include "hilog/log.h"
namespace OHOS {
namespace HDI {
#define FILE_NAME         (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)
#define FORMAT(fmt, ...)  "[%{public}s:%{public}d] %{public}s# " fmt, FILE_NAME, __LINE__, __FUNCTION__, ##__VA_ARGS__

#ifdef THERMAL_HILOGF
#undef THERMAL_HILOGF
#endif

#ifdef THERMAL_HILOGE
#undef THERMAL_HILOGE
#endif

#ifdef THERMAL_HILOGW
#undef THERMAL_HILOGW
#endif

#ifdef THERMAL_HILOGI
#undef THERMAL_HILOGI
#endif

#ifdef THERMAL_HILOGD
#undef THERMAL_HILOGD
#endif

namespace {
// Thermal manager reserved domain id range
constexpr unsigned int THERMAL_DOMAIN_ID_START = 0xD002940;
constexpr unsigned int THERMAL_DOMAIN_ID_END = THERMAL_DOMAIN_ID_START + 32;
constexpr unsigned int TEST_DOMAIN_ID = 0xD000F00;
}

enum ThermalManagerLogLabel {
    // Component labels, you can add if needed
    COMP_APP = 0,
    COMP_FWK = 1,
    COMP_SVC = 2,
    COMP_HDI = 3,
    COMP_DRV = 4,
    // Feature labels, use to mark major features
    FEATURE_PROTECTOR,
    // Test label
    LABEL_TEST,
    // The end of labels, max to the domain id range length 32
    LABEL_END,
};

enum ThermalManagerLogDomain {
    DOMAIN_APP = THERMAL_DOMAIN_ID_START + COMP_APP, // 0xD002940
    DOMAIN_FRAMEWORK, // 0xD002941
    DOMAIN_SERVICE, // 0xD002942
    DOMAIN_HDI, // 0xD002943
    DOMAIN_DRIVER, // 0xD002944
    DOMAIN_FEATURE_PROTECTOR,
    DOMAIN_TEST = TEST_DOMAIN_ID, // 0xD000F00
    DOMAIN_END = THERMAL_DOMAIN_ID_END, // Max to 0xD002960, keep the sequence and length same as ThermalManagerLogLabel
};

// Keep the sequence and length same as ThermalManagerLogDomain
static constexpr OHOS::HiviewDFX::HiLogLabel THERMAL_LABEL[LABEL_END] = {
    {LOG_CORE, DOMAIN_APP, "ThermalApp"},
    {LOG_CORE, DOMAIN_FRAMEWORK, "ThermalFwk"},
    {LOG_CORE, DOMAIN_SERVICE, "ThermalSvc"},
    {LOG_CORE, DOMAIN_HDI, "ThermalHdi"},
    {LOG_CORE, DOMAIN_DRIVER, "ThermalDrv"},
    {LOG_CORE, DOMAIN_FEATURE_PROTECTOR, "ThermalProtector"},
    {LOG_CORE, DOMAIN_TEST, "ThermalTest"},
};

// In order to improve performance, do not check the module range, module should less than THERMALMGR_MODULE_BUTT.
#define THERMAL_HILOGF(module, ...) \
    (void)OHOS::HiviewDFX::HiLog::Fatal(THERMAL_LABEL[module], FORMAT(__VA_ARGS__))
#define THERMAL_HILOGE(module, ...) \
    (void)OHOS::HiviewDFX::HiLog::Error(THERMAL_LABEL[module], FORMAT(__VA_ARGS__))
#define THERMAL_HILOGW(module, ...) \
    (void)OHOS::HiviewDFX::HiLog::Warn(THERMAL_LABEL[module], FORMAT(__VA_ARGS__))
#define THERMAL_HILOGI(module, ...) \
    (void)OHOS::HiviewDFX::HiLog::Info(THERMAL_LABEL[module], FORMAT(__VA_ARGS__))
#define THERMAL_HILOGD(module, ...) \
    (void)OHOS::HiviewDFX::HiLog::Debug(THERMAL_LABEL[module], FORMAT(__VA_ARGS__))
} // namespace PowerMgr
} // namespace OHOS

#else

#define THERMAL_HILOGF(...)
#define THERMAL_HILOGE(...)
#define THERMAL_HILOGW(...)
#define THERMAL_HILOGI(...)
#define THERMAL_HILOGD(...)

#endif // CONFIG_HILOG
#endif // THERMAL_LOG_H
