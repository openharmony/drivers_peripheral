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

#ifndef BATTERY_LOG_H
#define BATTERY_LOG_H

#include "hdf_base.h"
#include "hilog/log.h"

namespace OHOS {
namespace HDI {
namespace Battery {

#ifdef BATTERY_HILOGF
#undef BATTERY_HILOGF
#endif

#ifdef BATTERY_HILOGE
#undef BATTERY_HILOGE
#endif

#ifdef BATTERY_HILOGW
#undef BATTERY_HILOGW
#endif

#ifdef BATTERY_HILOGI
#undef BATTERY_HILOGI
#endif

#ifdef BATTERY_HILOGD
#undef BATTERY_HILOGD
#endif

namespace {
// Battery manager reserved domain id range
constexpr unsigned int BATTERY_HDI_DOMAIN_ID_START = 0xD002923;
constexpr unsigned int BATTERY_DOMAIN_ID_END = 0xD002940;
constexpr unsigned int TEST_DOMAIN_ID = 0xD000F00;
} // namespace

enum BatteryManagerLogLabel {
    // Component labels, you can add if needed
    COMP_HDI = 0,
    // Write to kmsg log
    COMP_DRV = 1,
    // Feature labels, use to mark major features
    FEATURE_BATT_INFO,
    // Test label
    LABEL_TEST,
    // The end of labels, max to the domain id range length 32
    LABEL_END,
};

enum BatteryManagerLogDomain {
    DOMAIN_HDI = BATTERY_HDI_DOMAIN_ID_START, // 0xD002923
    DOMAIN_TEST = TEST_DOMAIN_ID,       // 0xD000F00
    DOMAIN_END = BATTERY_DOMAIN_ID_END, // Max to 0xD002940, keep the sequence and length same as BatteryManagerLogLabel
};

struct BatteryManagerLogLabelTag {
    uint32_t logLabel;
    const char* tag;
};

static constexpr BatteryManagerLogLabelTag BATTERY_LABEL_TAG[LABEL_END] = {
    {COMP_HDI,              "BatteryHdi"     },
    {COMP_DRV,              "BatteryDrv"     },
    {FEATURE_BATT_INFO,     "BatteryInfo"    },
    {LABEL_TEST,            "BatteryTest"    },
};

struct BatteryManagerLogLabelDomain {
    uint32_t logLabel;
    uint32_t domainId;
};

static constexpr BatteryManagerLogLabelDomain BATTERY_LABEL_DOMAIN[LABEL_END] = {
    {COMP_HDI,              DOMAIN_HDI},
    {COMP_DRV,              DOMAIN_HDI},
    {FEATURE_BATT_INFO,     DOMAIN_HDI},
    {LABEL_TEST,            DOMAIN_TEST},
};

#define BATTERY_HILOGF(domain, ...) \
    ((void)HILOG_IMPL(LOG_CORE, LOG_FATAL, BATTERY_LABEL_DOMAIN[domain].domainId, BATTERY_LABEL_TAG[domain].tag,   \
    ##__VA_ARGS__))
#define BATTERY_HILOGE(domain, ...) \
    ((void)HILOG_IMPL(LOG_CORE, LOG_ERROR, BATTERY_LABEL_DOMAIN[domain].domainId, BATTERY_LABEL_TAG[domain].tag,   \
    ##__VA_ARGS__))
#define BATTERY_HILOGW(domain, ...) \
    ((void)HILOG_IMPL(LOG_CORE, LOG_WARN, BATTERY_LABEL_DOMAIN[domain].domainId, BATTERY_LABEL_TAG[domain].tag,    \
    ##__VA_ARGS__))
#define BATTERY_HILOGI(domain, ...) \
    ((void)HILOG_IMPL(LOG_CORE, LOG_INFO, BATTERY_LABEL_DOMAIN[domain].domainId, BATTERY_LABEL_TAG[domain].tag,    \
    ##__VA_ARGS__))
#define BATTERY_HILOGD(domain, ...) \
    ((void)HILOG_IMPL(LOG_CORE, LOG_DEBUG, BATTERY_LABEL_DOMAIN[domain].domainId, BATTERY_LABEL_TAG[domain].tag,   \
    ##__VA_ARGS__))
} // namespace Battery
} // namespace HDI
} // namespace OHOS

#endif // BATTERY_LOG_H
