/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef USBD_GETCONTROLTRANSFERDATA_TEST_H
#define USBD_GETCONTROLTRANSFERDATA_TEST_H

#include <gtest/gtest.h>
#include "v2_1/iusb_device_interface.h"
#include "usbd_type.h"

namespace OHOS {
namespace USB {
namespace UsbGetControlTransferData {

class UsbGetControlTransferDataTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
} // UsbGetControlTransferData
} // USB
} // OHOS
#endif // USBD_GETCONTROLTRANSFERDATA_TEST_H
