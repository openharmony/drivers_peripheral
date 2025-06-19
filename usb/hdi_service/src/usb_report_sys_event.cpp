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

#include "hisysevent.h"
#include "usb_report_sys_event.h"

using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace HDI {
namespace Usb {
namespace V1_2 {
void UsbReportSysEvent::ReportUsbRecognitionFailSysEvent(const std::string &operationType, int32_t code,
    const std::string &failDescription)
{
    HiSysEventWrite(HiSysEvent::Domain::HDF_USB, "RECOGNITION_FAIL", HiSysEvent::EventType::FAULT, "OPERATION_TYPE",
        operationType, "DEVICE_NAME", 0, "DEVICE_PROTOCOL", 0, "DEVICE_CLASS", 0, "VENDOR_ID", 0, "PRODUCT_ID", 0,
        "VERSION", 0, "FAIL_REASON", code, "FAIL_INFO", failDescription);
}
} // namespace V1_2
} // namespace Usb
} // namespace HDI
} // namespace OHOS