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

#ifndef THERMAL_HDF_UTILS_H
#define THERMAL_HDF_UTILS_H

#include <string>

namespace OHOS {
namespace HDI {
namespace Thermal {
namespace V1_1 {
class ThermalHdfUtils {
public:
    ThermalHdfUtils() = default;
    ~ThermalHdfUtils() = default;
    ThermalHdfUtils(const ThermalHdfUtils&) = delete;
    ThermalHdfUtils& operator=(const ThermalHdfUtils) = delete;

    static int32_t ReadNodeToInt(const std::string& path);
    static bool ReadNode(const std::string& path, std::string& out);
    static void TrimStr(std::string& str);
    static int32_t GetMaxCommonDivisor(int32_t a, int32_t b);
};
} // V1_1
} // Thermal
} // HDI
} // OHOS
#endif // THERMAL_HDF_UTILS_H