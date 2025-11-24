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
constexpr unsigned int THERMAL_HDI_DOMAIN_ID_START = 0xD002943;
constexpr unsigned int THERMAL_DOMAIN_ID_END = 0xD002960;
constexpr unsigned int TEST_DOMAIN_ID = 0xD000F00;
}

enum ThermalManagerLogLabel {
    // Component labels, you can add if needed
    COMP_HDI = 0,
    // Test label
    LABEL_TEST,
    // The end of labels, max to the domain id range length 32
    LABEL_END,
};

enum ThermalManagerLogDomain {
    DOMAIN_HDI = THERMAL_HDI_DOMAIN_ID_START, // 0xD002943
    DOMAIN_TEST = TEST_DOMAIN_ID, // 0xD000F00
    DOMAIN_END = THERMAL_DOMAIN_ID_END, // Max to 0xD002960, keep the sequence and length same as ThermalManagerLogLabel
};

struct ThermalManagerLogLabelTag {
    uint32_t logLabel;
    const char* tag;
};

static constexpr ThermalManagerLogLabelTag THERMAL_LABEL_TAG[LABEL_END] = {
    {COMP_HDI,           "ThermalHdi"},
    {LABEL_TEST,         "ThermalTest"},
};

struct ThermalManagerLogLabelDomain {
    uint32_t logLabel;
    uint32_t domainId;
};

static constexpr ThermalManagerLogLabelDomain THERMAL_LABEL_DOMAIN[LABEL_END] = {
    {COMP_HDI,           DOMAIN_HDI},
    {LABEL_TEST,         DOMAIN_TEST},
};

// In order to improve performance, do not check the module range, module should less than THERMALMGR_MODULE_BUTT.
#define THERMAL_HILOGF(module, ...) \
    ((void)HILOG_IMPL(LOG_CORE, LOG_FATAL, THERMAL_LABEL_DOMAIN[module].domainId, THERMAL_LABEL_TAG[module].tag,   \
    ##__VA_ARGS__))
#define THERMAL_HILOGE(module, ...) \
    ((void)HILOG_IMPL(LOG_CORE, LOG_ERROR, THERMAL_LABEL_DOMAIN[module].domainId, THERMAL_LABEL_TAG[module].tag,   \
    ##__VA_ARGS__))
#define THERMAL_HILOGW(module, ...) \
    ((void)HILOG_IMPL(LOG_CORE, LOG_WARN, THERMAL_LABEL_DOMAIN[module].domainId, THERMAL_LABEL_TAG[module].tag,    \
    ##__VA_ARGS__))
#define THERMAL_HILOGI(module, ...) \
    ((void)HILOG_IMPL(LOG_CORE, LOG_INFO, THERMAL_LABEL_DOMAIN[module].domainId, THERMAL_LABEL_TAG[module].tag,    \
    ##__VA_ARGS__))
#define THERMAL_HILOGD(module, ...) \
    ((void)HILOG_IMPL(LOG_CORE, LOG_DEBUG, THERMAL_LABEL_DOMAIN[module].domainId, THERMAL_LABEL_TAG[module].tag,   \
    ##__VA_ARGS__))
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
