/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef USB_DDK_HASH_H
#define USB_DDK_HASH_H
#include <stddef.h>
#include <stdint.h>
#include <memory>
#include <vector>
struct InterfaceInfo {
    uint64_t addr;
    uint8_t busNum;
    uint8_t devNum;
};

int32_t UsbDdkHash(const InterfaceInfo &info, uint64_t &hashVal);
int32_t UsbDdkUnHash(uint64_t hashVal, uint64_t &addr);
void UsbDdkDelHashRecord(uint64_t hashVal);
bool UsbDdkGetRecordByVal(const InterfaceInfo &info, uint64_t &hashVal);
int32_t GetInterfaceInfoByVal(const uint64_t hashVal, InterfaceInfo &Info);
bool UsbDdkGetAllRecords(const InterfaceInfo &info, std::vector<uint64_t> &records);
#endif // USB_DDK_IMPL_H
