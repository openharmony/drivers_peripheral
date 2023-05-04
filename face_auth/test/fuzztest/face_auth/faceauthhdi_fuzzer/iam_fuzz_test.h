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

#ifndef IAM_FUZZ_TEST_H
#define IAM_FUZZ_TEST_H

#include <string>
#include <vector>

#include "parcel.h"

namespace OHOS {
namespace UserIam {
namespace Common {
void FillFuzzUint8Vector(Parcel &parcel, std::vector<uint8_t> &data);
void FillFuzzInt8Vector(Parcel &parcel, std::vector<int8_t> &data);
void FillFuzzUint32Vector(Parcel &parcel, std::vector<uint32_t> &data);
void FillFuzzUint64Vector(Parcel &parcel, std::vector<uint64_t> &data);
void FillFuzzString(Parcel &parcel, std::string &str);
} // namespace Common
} // namespace UserIam
} // namespace OHOS

#endif // IAM_FUZZ_TEST_H