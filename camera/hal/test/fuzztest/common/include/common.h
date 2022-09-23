/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <unistd.h>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <iostream>
#include "v1_0/camera_host_stub.h"
#include "v1_0/camera_device_stub.h"
#include "v1_0/stream_operator_stub.h"
#include "v1_0/offline_stream_operator_stub.h"

namespace OHOS {
using namespace OHOS::HDI::Camera::V1_0;

uint32_t U32_AT(const uint8_t *ptr);

constexpr size_t THRESHOLD = 10;
constexpr int32_t OFFSET = 4;
}
