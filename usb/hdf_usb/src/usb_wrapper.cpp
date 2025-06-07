/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#include "usb_wrapper.h"

#include "hdf_core_log.h"
#include "hdf_usb_pnp_manage.h"

#ifdef USB_ENABLE_HISYSEVENT
#include "hisysevent.h"

using namespace OHOS::HiviewDFX;

#endif

void UsbDDKDriverMatchFailEvent(const struct UsbPnpNotifyMatchInfoTable *infoTable)
{
#ifdef USB_ENABLE_HISYSEVENT
    HiSysEventWrite(HiSysEvent::Domain::HDF_USB, "RECOGNITION_FAIL", HiSysEvent::EventType::FAULT,
        "DEVICE_NAME", std::to_string(infoTable->busNum) + "-" + std::to_string(infoTable->devNum),
        "DEVICE_PROTOCOL", infoTable->deviceInfo.deviceProtocol, "DEVICE_CLASS", infoTable->deviceInfo.deviceClass,
        "VENDOR_ID", infoTable->deviceInfo.vendorId, "PRODUCT_ID", infoTable->deviceInfo.productId,
        "VERSION", "1.0.0", "FAIL_REASON", 1, "FAIL_INFO", "Driver matching failed");
#endif
}

