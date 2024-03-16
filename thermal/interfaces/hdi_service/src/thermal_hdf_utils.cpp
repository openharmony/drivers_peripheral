/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "thermal_hdf_utils.h"

#include <securec.h>

#include "file_ex.h"
#include "hdf_base.h"
#include "string_ex.h"
#include "thermal_log.h"

namespace OHOS {
namespace HDI {
namespace Thermal {
namespace V1_1 {
namespace {
constexpr int32_t INVALID_NUM = -100000;
}

int32_t ThermalHdfUtils::ReadNodeToInt(const std::string& path)
{
    std::string content;
    if (!ReadNode(path, content)) {
        THERMAL_HILOGW(COMP_HDI, "get node failed");
        return INVALID_NUM;
    }
    int32_t value = INVALID_NUM;
    StrToInt(content, value);
    return value;
}

bool ThermalHdfUtils::ReadNode(const std::string& path, std::string& out)
{
    bool ret = LoadStringFromFile(path, out);
    TrimStr(out);
    return ret;
}

int32_t ThermalHdfUtils::WriteNode(const std::string& path, std::string& data)
{
    FILE* fp;
    int32_t ret = HDF_FAILURE;
    if ((fp = fopen(path.c_str(), "r")) == nullptr) {
        THERMAL_HILOGI(COMP_HDI, "open file failed");
        return ret;
    }

    if (fwrite(data.c_str(), sizeof(data.c_str()), 1, fp) == 0) {
        THERMAL_HILOGW(COMP_HDI, "write node failed");
    } else {
        ret = HDF_SUCCESS;
    }

    if (fclose(fp) != 0) {
        THERMAL_HILOGW(COMP_HDI, "close file stream failed");
    }
    return ret;
}

void ThermalHdfUtils::TrimStr(std::string& str)
{
    if (str.empty()) {
        return;
    }
    str.erase(std::remove(str.begin(), str.end(), '\n'), str.end());
    str.erase(std::remove(str.begin(), str.end(), '\r'), str.end());
}

int32_t ThermalHdfUtils::GetMaxCommonDivisor(int32_t a, int32_t b)
{
    if (b == 0) {
        return 0;
    }

    if (a % b == 0) {
        return b;
    } else {
        return GetMaxCommonDivisor(b, a % b);
    }
}
} // V1_1
} // Thermal
} // HDI
} // OHOS
