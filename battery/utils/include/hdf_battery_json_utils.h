/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef HDF_BATTERY_CJSON_UTILS_H
#define HDF_BATTERY_CJSON_UTILS_H

#include <cJSON.h>

namespace OHOS {
namespace HDI {
namespace Battery {
namespace HdfBatteryJsonUtils {
inline bool IsEmptyJsonParse(const cJSON* jsonValue)
{
    return jsonValue && (cJSON_IsNull(jsonValue) || (cJSON_IsObject(jsonValue) && (jsonValue->child == nullptr)) ||
            (cJSON_IsArray(jsonValue) && (cJSON_GetArraySize(jsonValue) == 0)));
}

inline bool IsValidJsonObject(const cJSON* jsonValue)
{
    return jsonValue && cJSON_IsObject(jsonValue);
}

inline bool IsValidJsonString(const cJSON* jsonValue)
{
    return jsonValue && cJSON_IsString(jsonValue) && jsonValue->valuestring != nullptr;
}

inline bool IsValidJsonNumber(const cJSON* jsonValue)
{
    return jsonValue && cJSON_IsNumber(jsonValue);
}

inline bool IsValidJsonArray(const cJSON* jsonValue)
{
    return jsonValue && cJSON_IsArray(jsonValue);
}
} // namespace HdfBatteryJsonUtils
} // namespace Battery
} // namespace HDI
} // namespace OHOS
#endif // HDF_BATTERY_CJSON_UTILS_H
