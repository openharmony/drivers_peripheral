/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file expected in compliance with the License.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "camera_hdi_sequenceable_test.h"
#include "map_data_sequenceable.h"
#include "buffer_handle_sequenceable.h"
#include "buffer_producer_sequenceable.h"
#include "buffer_util.h"
using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;
using namespace OHOS::HDI::Camera::V1_0;

void CameraHdiSequenceableTest::SetUpTestCase(void) {}
void CameraHdiSequenceableTest::TearDownTestCase(void) {}
void CameraHdiSequenceableTest::SetUp(void)
{
    cout << "CameraHdiSequenceableTest::SetUp()" << endl;
}

void CameraHdiSequenceableTest::TearDown(void)
{
    cout << "CameraHdiSequenceableTest::TearDown()" << endl;
}

/**
 * @tc.name: MapDataSequencebleTest_01
 * @tc.desc: MapDataSequencebleTest_01
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiSequenceableTest, MapDataSequencebleTest_01, TestSize.Level1)
{
    int32_t ret;
    cout << "CameraHdiSequenceableTest::MapDataSequencebleTest_01" << endl;
    auto mapDataSequenceable = make_shared<MapDataSequenceable>();
    // Get and Set Test
    int32_t i32Temp0 = 12345678;
    int32_t i32Temp1 = 0;
    ret= mapDataSequenceable->Set("i32Temp", i32Temp0);
    EXPECT_EQ(ret, 0);
    ret = mapDataSequenceable->Get("i32Temp", i32Temp1);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(i32Temp0, i32Temp1);

    int64_t i64Temp0 = 12345678;
    int64_t i64Temp1 = 0;
    ret = mapDataSequenceable->Set("i64Temp", i64Temp0);
    EXPECT_EQ(ret, 0);
    ret = mapDataSequenceable->Get("i64Temp", i64Temp1);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(i64Temp0, i64Temp1);

    double doubleTemp0 = 1234.5678;
    double doubleTemp1 = 0;
    ret = mapDataSequenceable->Set("doubleTemp", doubleTemp0);
    EXPECT_EQ(ret, 0);
    ret = mapDataSequenceable->Get("doubleTemp", doubleTemp1);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(doubleTemp1, doubleTemp0);

    string stringTemp0 = "s1234.5678";
    string stringTemp1 = "0";
    ret = mapDataSequenceable->Set("stringTemp", stringTemp0);
    EXPECT_EQ(ret, 0);
    ret = mapDataSequenceable->Get("stringTemp", stringTemp1);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(stringTemp1, stringTemp0);

    // Marshalling and Unmarshalling Test
    Parcel parcel;
    ret = mapDataSequenceable->Marshalling(parcel);
    EXPECT_EQ(ret, true);
    auto mapDataSequenceable2 = MapDataSequenceable::Unmarshalling(parcel);
    EXPECT_NE(mapDataSequenceable2, nullptr);

    int32_t i32Temp2 = 0;
    ret = mapDataSequenceable2->Get("i32Temp", i32Temp2);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(i32Temp0, i32Temp2);

    int64_t i64Temp2 = 0;
    ret = mapDataSequenceable2->Get("i64Temp", i64Temp2);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(i64Temp0, i64Temp2);

    double doubleTemp2 = 0;
    ret = mapDataSequenceable2->Get("doubleTemp", doubleTemp2);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(doubleTemp0, doubleTemp2);

    string stringTemp2= "0";
    ret = mapDataSequenceable2->Get("stringTemp", stringTemp2);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(stringTemp0, stringTemp2);
}

/**
 * @tc.name: BufferHandleSequencebleTest_01
 * @tc.desc: BufferHandleSequencebleTest_01
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiSequenceableTest, BufferHandleSequencebleTest_01, TestSize.Level1)
{
    constexpr int32_t reserveFds = 1;
    constexpr int32_t reserveInts = 0;
    int32_t ret;
    BufferHandle* handle0 = BufferHandleSequenceable::NewBufferHandle(reserveFds, reserveInts);
    handle0->fd = open("/dev/null", O_WRONLY);
    handle0->reserve[0] = dup(handle0->fd);
    EXPECT_NE(handle0, nullptr);
    auto bufferHandleSeq0 = make_shared<BufferHandleSequenceable>(handle0);
    BufferHandle* handle1 = bufferHandleSeq0->GetBufferHandle();
    EXPECT_NE(handle1, nullptr);
    Parcel parcel;
    ret = bufferHandleSeq0->Marshalling(parcel);
    EXPECT_EQ(ret, true);
    auto bufferHandleSeq1 = BufferHandleSequenceable::Unmarshalling(parcel);
    EXPECT_NE(bufferHandleSeq1, nullptr);
    BufferHandle* handle2 = bufferHandleSeq1->GetBufferHandle();
    EXPECT_NE(handle2, nullptr);
    EXPECT_EQ(handle2->reserveFds, reserveFds);
}

/**
 * @tc.name: BufferHandleSequencebleTest_02
 * @tc.desc: BufferHandleSequencebleTest_02
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiSequenceableTest, BufferHandleSequencebleTest_02, TestSize.Level1)
{
    constexpr int32_t reserveFds = 1;
    constexpr int32_t reserveInts = 0;
    BufferHandle* handle0 = BufferHandleSequenceable::NewBufferHandle(reserveFds, reserveInts);
    EXPECT_NE(handle0, nullptr);
    auto bufferHandleSeq0 = make_shared<BufferHandleSequenceable>(handle0);
    bufferHandleSeq0->SetBufferHandle(handle0);
    BufferHandle bufferHandle;
    bufferHandle.reserveFds = 1;
    bufferHandle.reserveInts = 2;
    new BufferHandleSequenceable(bufferHandle);
}

/**
 * @tc.name: BufferHandleSequenceTest_03
 * @tc.desc: BufferHandleSequenceTest_03
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiSequenceableTest, BufferHandleSequenceTest_03, TestSize.Level1)
{
    OHOS::HDI::Camera::V1_0::BufferHandleSequenceable bufferHandleSequenceble01;
    OHOS::HDI::Camera::V1_0::BufferHandleSequenceable bufferHandleSequenceble02;
    bufferHandleSequenceble01.operator = (bufferHandleSequenceble02);
    Parcel parcel;
    bufferHandleSequenceble01.Marshalling(parcel);
    BufferHandleSequenceable::Unmarshalling(parcel);
}

/**
 * @tc.name: BufferProducerSequenceTest_01
 * @tc.desc: BufferProducerSequenceTest_01
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiSequenceableTest, BufferProducerSequenceTest_01, TestSize.Level1)
{
    OHOS::HDI::Camera::V1_0::BufferProducerSequenceable bufferProducerSequenceble01;
    OHOS::HDI::Camera::V1_0::BufferProducerSequenceable bufferProducerSequenceble02;
    bufferProducerSequenceble01 = bufferProducerSequenceble02;
    Parcel parcel;
    bufferProducerSequenceble01.Marshalling(parcel);
    BufferProducerSequenceable::Unmarshalling(parcel);
}