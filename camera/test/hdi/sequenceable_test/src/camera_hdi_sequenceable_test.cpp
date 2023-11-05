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
#include "camera_hdi_sequenceable_test.h"
#include "map_data_sequenceable.h"
#include "buffer_handle_sequenceable.h"
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
    EXPECT_EQ(doubleTemp0, doubleTemp0);

    string stringTemp0 = "s1234.5678";
    string stringTemp1 = "0";
    ret = mapDataSequenceable->Set("stringTemp", stringTemp0);
    EXPECT_EQ(ret, 0);
    ret = mapDataSequenceable->Get("stringTemp", stringTemp1);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(stringTemp0, stringTemp0);

    // Marshalling and Unmarshalling Test
    Parcel parcel;
    ret = mapDataSequenceable->Marshalling(parcel);
    EXPECT_EQ(ret, 0);
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
    constexpr int32_t reserveFds = 10;
    constexpr int32_t reserveInts = 10;
    int32_t ret;
    shared_ptr<BufferHandle> handle(AllocateNativeBufferHandle(reserveFds, reserveInts));
    auto bufferHandleSeq = make_shared<BufferHandleSequenceable>(handle);
    Parcel parcel;
    ret = bufferHandleSeq->Marshalling(parcel);
    EXPECT_EQ(ret, 0);
    auto bufferHandleSeq2 = BufferHandleSequenceable::Unmarshalling(parcel);
    EXPECT_NE(bufferHandleSeq2, nullptr);
}