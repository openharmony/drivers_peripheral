 /*
  * Copyright (c) 2023 Huawei Device Co., Ltd.
  *
  * HDF is dual licensed: you can use it either under the terms of
  * the GPL, or the BSD license, at your option.
  * See the LICENSE file in the root of this repository for complete details.
  */

#ifndef USB_WRAPPER_H
#define USB_WRAPPER_H
#include "hdf_base.h"

#ifdef __cplusplus
extern "C" {
#endif
#ifndef __LITEOS__
void UsbDDKDriverMatchFailEvent(const struct UsbPnpNotifyMatchInfoTable *infoTable);
#endif
#ifdef __cplusplus
};
#endif
#endif
