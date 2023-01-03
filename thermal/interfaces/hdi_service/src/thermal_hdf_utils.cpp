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

#include "thermal_hdf_utils.h"

#include <securec.h>

#include "hdf_base.h"
#include "thermal_log.h"

namespace OHOS {
namespace HDI {
namespace Thermal {
namespace V1_0 {
namespace {
constexpr int32_t MAX_INT_LEN = 32;
constexpr int32_t MAX_STR_LEN = 128;
constexpr int32_t INVALID_NUM = -100000;
}

int32_t ThermalHdfUtils::ReadNodeToInt(const std::string& path)
{
    FILE* fp;
    int32_t out = INVALID_NUM;
    if ((fp = fopen(path.c_str(), "r")) == nullptr) {
        THERMAL_HILOGI(COMP_HDI, "open file failed, path: %{private}s", path.c_str());
        return out;
    }

    char buf[MAX_INT_LEN];
    if (fgets(buf, sizeof(buf) - 1, fp) == nullptr) {
        THERMAL_HILOGW(COMP_HDI, "get node failed");
    } else {
        out = atoi(buf);
    }

    if (fclose(fp) != 0) {
        THERMAL_HILOGW(COMP_HDI, "close file stream failed");
    }
    return out;
}

int32_t ThermalHdfUtils::ReadNode(const std::string& path, std::string& out)
{
    FILE* fp;
    int32_t ret = HDF_FAILURE;
    if ((fp = fopen(path.c_str(), "r")) == nullptr) {
        THERMAL_HILOGI(COMP_HDI, "open file failed, path: %{private}s", path.c_str());
        return ret;
    }

    char buf[MAX_STR_LEN];
    if (fgets(buf, sizeof(buf) - 1, fp) == nullptr) {
        THERMAL_HILOGW(COMP_HDI, "get node failed");
    } else {
        out = buf;
        ret = HDF_SUCCESS;
    }

    if (fclose(fp) != 0) {
        THERMAL_HILOGW(COMP_HDI, "close file stream failed");
    }

    TrimStr(out);
    return ret;
}

int32_t ThermalHdfUtils::WriteNode(const std::string& path, std::string& data)
{
    FILE* fp;
    int32_t ret = HDF_FAILURE;
    if ((fp = fopen(path.c_str(), "r")) == nullptr) {
        THERMAL_HILOGI(COMP_HDI, "open file failed, path: %{private}s", path.c_str());
        return ret;
    }

    if (fwrite(data.c_str(), sizeof(data.c_str()), 1, fp) == 0) {
        THERMAL_HILOGW(COMP_HDI, "write node failed, path: %{private}s", path.c_str());
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
    std::string::iterator iter = str.begin();
    while (iter != str.end()) {
        if (*iter == '\n' || *iter == '\r') {
            str.erase(iter);
        } else {
            iter++;
        }
    }
}
} // V1_0
} // Thermal
} // HDI
} // OHOS
