/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <cmath>
#include <cstdio>
#include <unistd.h>
#include <gtest/gtest.h>
#include <securec.h>
#include "hdf_base.h"
#include "osal_time.h"
#include "v2_0/isensor_interface.h"
#include "sensor_type.h"
#include "sensor_callback_impl.h"
#include "sensor_uhdf_log.h"
#include "sensor_hdi_dump.h"

using namespace OHOS::HDI::Sensor::V2_0;
using namespace testing::ext;

namespace {

}

class HdfSensorDumpTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HdfSensorDumpTest::SetUpTestCase()
{
}

void HdfSensorDumpTest::TearDownTestCase()
{
}

void HdfSensorDumpTest::SetUp()
{
}

void HdfSensorDumpTest::TearDown()
{
}

/**
  * @tc.name: SensorDumpHelpTest
  * @tc.desc: Get a client and check whether the client is empty.
  * @tc.type: FUNC
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfSensorDumpTest, SensorDumpHelpTest, TestSize.Level1)
{
    struct HdfSBuf* reply = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf* data = HdfSbufTypedObtain(SBUF_IPC);
    HdfsbufWriteString(data, "-h");
    GetSensorDump(data, reply)
}