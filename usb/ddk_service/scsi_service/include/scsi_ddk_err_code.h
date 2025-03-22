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

#ifndef SCSI_DDK_ERR_CODE_H
#define SCSI_DDK_ERR_CODE_H

namespace OHOS {
namespace HDI {
namespace Usb {
namespace ScsiDdk {
namespace V1_0 {

enum ScsiPeripheralDdkErrCode {
    SCSIPERIPHERAL_DDK_NO_PERM = 201,
    SCSIPERIPHERAL_DDK_INVALID_PARAMETER = 401,
    SCSIPERIPHERAL_DDK_MEMORY_ERROR = 31700001,
    SCSIPERIPHERAL_DDK_INVALID_OPERATION = 31700002,
    SCSIPERIPHERAL_DDK_IO_ERROR = 31700003,
    SCSIPERIPHERAL_DDK_TIMEOUT = 31700004,
    SCSIPERIPHERAL_DDK_INIT_ERROR = 31700005,
    SCSIPERIPHERAL_DDK_SERVICE_ERROR = 31700006,
    SCSIPERIPHERAL_DDK_DEVICE_NOT_FOUND = 31700007,
};

} // V1_0
} // ScsiDdk
} // Usb
} // HDI
} // OHOS

#endif // SCSI_DDK_ERR_CODE_H

