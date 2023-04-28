/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "iam_fuzz_test.h"

#include <cstdint>
#include <string>
#include <vector>

#include "parcel.h"
#include "securec.h"

#include "iam_logger.h"

#define LOG_LABEL UserIam::Common::LABEL_IAM_COMMON

namespace OHOS {
namespace UserIam {
namespace Common {
namespace {
constexpr int32_t MAX_DATA_LEN = 200;
void FillFuzzBuffer(Parcel &parcel, void *p, uint32_t len)
{
    if (len == 0) {
        return;
    }

    auto buffer = parcel.ReadBuffer(len);
    if (buffer == nullptr) {
        IAM_LOGE("ReadBuffer len %{public}u fail", len);
        return;
    }

    if (memcpy_s(p, len, buffer, len) != EOK) {
        IAM_LOGE("memcpy_s fail");
        return;
    }

    return;
}
} // namespace

void FillFuzzUint8Vector(Parcel &parcel, std::vector<uint8_t> &data)
{
    uint32_t len = parcel.ReadUint32() % MAX_DATA_LEN;
    uint32_t memLen = len * sizeof(uint8_t);
    data.resize(len);
    FillFuzzBuffer(parcel, static_cast<void *>(&data[0]), memLen);
    IAM_LOGI("fill vector len %{public}u ok", len);
}

void FillFuzzInt8Vector(Parcel &parcel, std::vector<int8_t> &data)
{
    uint32_t len = parcel.ReadUint32() % MAX_DATA_LEN;
    uint32_t memLen = len * sizeof(int8_t);
    data.resize(len);
    FillFuzzBuffer(parcel, static_cast<void *>(&data[0]), memLen);
    IAM_LOGI("fill vector len %{public}u ok", len);
}

void FillFuzzUint32Vector(Parcel &parcel, std::vector<uint32_t> &data)
{
    uint32_t len = parcel.ReadUint32() % MAX_DATA_LEN;
    uint32_t memLen = len * sizeof(uint32_t);
    data.resize(len);
    FillFuzzBuffer(parcel, static_cast<void *>(&data[0]), memLen);
    IAM_LOGI("fill vector len %{public}u ok", len);
}

void FillFuzzUint64Vector(Parcel &parcel, std::vector<uint64_t> &data)
{
    uint32_t len = parcel.ReadUint32() % MAX_DATA_LEN;
    uint32_t memLen = len * sizeof(uint64_t);
    data.resize(len);
    FillFuzzBuffer(parcel, static_cast<void *>(&data[0]), memLen);
    IAM_LOGI("fill vector len %{public}u ok", len);
}

void FillFuzzString(Parcel &parcel, std::string &str)
{
    uint32_t len = parcel.ReadUint32() % MAX_DATA_LEN + 1;
    uint32_t memLen = len * sizeof(char);
    std::vector<char> data(len, 0);
    FillFuzzBuffer(parcel, static_cast<void *>(&data[0]), memLen - 1);
    str = std::string(&data[0]);
    IAM_LOGI("fill string len %{public}u ok", len - 1);
}
} // namespace Common
} // namespace UserIam
} // namespace OHOS