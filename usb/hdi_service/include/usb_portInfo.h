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

#ifndef USBPORTINFO_H
#define USBPORTINFO_H

namespace OHOS {
namespace HDI {
namespace Usb {
namespace Port {

#define PORT_CONFIG_NONE "none"
#define SUPPORTED_MODE_DRP "drp"
#define SUPPORTED_MODE_UFP "ufp"
#define SUPPORTED_MODE_DFP "dfp"

#define PORT_MODE_UFP "UFP"
#define PORT_MODE_DFP "DFP"
#define PORT_MODE_DRP "DRP"

#define POWER_ROLE_SOURCE "source"
#define POWER_ROLE_SINK "sink"

#define DATA_ROLE_HOST "host"
#define DATA_ROLE_DEVICE "device"

enum class PortMode:int32_t {
    NONE = 0,
    UFP = 1,
    DFP = 2,
    DRP = 3,
    NUM_MODES = 4
};

enum class PowerRole:int32_t {
    NONE = 0,
    SOURCE = 1,
    SINK = 2,
    NUM_POWER_ROLES = 3
};

enum class DataRole:int32_t {
    NONE = 0,
    HOST = 1,
    DEVICE = 2,
    NUM_DATA_ROLES = 3
};
} // namespace Port
} // namespace Usb
} // namespace HDI
} // namespace OHOS
#endif
