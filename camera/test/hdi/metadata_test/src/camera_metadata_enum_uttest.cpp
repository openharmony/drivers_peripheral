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
#include "camera_metadata_enum_uttest.h"

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;

void CameraMetadataEnumTest::SetUpTestCase(void) {}
void CameraMetadataEnumTest::TearDownTestCase(void) {}
void CameraMetadataEnumTest::SetUp(void)
{
    printf("CameraMetadataEnumTest start\r\n");
}

void CameraMetadataEnumTest::TearDown(void)
{
    printf("CameraMetadataEnumTest end\r\n");
}


/**
 * @tc.name: Camera_Metedate_Enum_001
 * @tc.desc: OperationMode
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataEnumTest, Camera_Metedate_Enum_001, TestSize.Level1)
{
    printf("CameraMetadataEnumTest Camera_Metedate_Enum_001 start...\n");
    int32_t operationMode_[] = {
        OHOS::HDI::Camera::V1_3::OperationMode::QUICK_SHOT_PHOTO,
        OHOS::HDI::Camera::V1_3::OperationMode::TIMELAPSE_PHOTO,
        OHOS::HDI::Camera::V1_3::OperationMode::FLUORESCENCE_PHOTO,
    };
    int32_t numColors = sizeof(operationMode_) / sizeof(OHOS::HDI::Camera::V1_3::OperationMode::QUICK_SHOT_PHOTO);
    for (int32_t i = 0; i < numColors; i++) {
        switch (operationMode_[i]) {
            case 16 : {
                printf("OHOS::HDI::Camera::V1_3::OperationMode::CAMERA_CUSTOM_COLOR_NORMAL is here\n");
                break;
            }
            case 19 : {
                printf("OHOS::HDI::Camera::V1_3::OperationMode::CAMERA_CUSTOM_COLOR_NORMAL is here\n");
                break;
            }
            case 21 : {
                printf("OHOS::HDI::Camera::V1_3::OperationMode::CAMERA_CUSTOM_COLOR_NORMAL is here\n");
                break;
            }
        }
    }
}

/**
 * @tc.name: Camera_Metedate_Enum_002
 * @tc.desc: DeferredDeliveryImageType
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataEnumTest, Camera_Metedate_Enum_002, TestSize.Level1)
{
    printf("CameraMetadataEnumTest Camera_Metedate_Enum_002 start...\n");
    int32_t DeferredDelivery[] = {
        OHOS::HDI::Camera::V1_3::DeferredDeliveryImageType::NONE,
        OHOS::HDI::Camera::V1_3::DeferredDeliveryImageType::MOVING_IMAGE,
    };
    int32_t numColors = sizeof(DeferredDelivery) / sizeof(OHOS::HDI::Camera::V1_3::DeferredDeliveryImageType::NONE);
    for (int32_t i = 0; i < numColors; i++) {
        switch (DeferredDelivery[i]) {
            case 0 : {
                printf("OHOS::HDI::Camera::V1_3::DeferredDeliveryImageType::NONE is here\n");
                break;
            }
            case 2 : {
                printf("OHOS::HDI::Camera::V1_3::DeferredDeliveryImageType::MOVING_IMAGE is here\n");
                break;
            }
        }
    }
}

/**
 * @tc.name: Camera_Metedate_Enum_003
 * @tc.desc: SessionStatus
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataEnumTest, Camera_Metedate_Enum_003, TestSize.Level1)
{
    printf("CameraMetadataEnumTest Camera_Metedate_Enum_003 start...\n");
    int32_t sessionstatus_[] = {
        OHOS::HDI::Camera::V1_3::SessionStatus::SESSION_STATUS_READY,
        OHOS::HDI::Camera::V1_3::SessionStatus::SESSION_STATUS_READY_SPACE_LIMIT_REACHED,
        OHOS::HDI::Camera::V1_3::SessionStatus::SESSSON_STATUS_NOT_READY_TEMPORARILY,
        OHOS::HDI::Camera::V1_3::SessionStatus::SESSION_STATUS_NOT_READY_OVERHEAT,
        OHOS::HDI::Camera::V1_3::SessionStatus::SESSION_STATUS_NOT_READY_PREEMPTED,
    };
    int32_t numColors = sizeof(sessionstatus_) / sizeof(OHOS::HDI::Camera::V1_3::SessionStatus::SESSION_STATUS_READY);
    for (int32_t i = 0; i < numColors; i++) {
        switch (sessionstatus_[i]) {
            case 0: {
                printf("OHOS::HDI::Camera::V1_3::SessionStatus::SESSION_STATUS_READY is here\n");
                break;
            }
            case 1: {
                printf("OHOS::HDI::Camera::V1_3::SessionStatus::SESSION_STATUS_READY_SPACE_LIMIT_REACHED is here\n");
                break;
            }
            case 2: {
                printf("OHOS::HDI::Camera::V1_3::SessionStatus::SESSSON_STATUS_NOT_READY_TEMPORARILY is here\n");
                break;
            }
            case 3: {
                printf("OHOS::HDI::Camera::V1_3::SessionStatus::SESSION_STATUS_NOT_READY_OVERHEAT is here\n");
                break;
            }
            case 4: {
                printf("OHOS::HDI::Camera::V1_3::SessionStatus::SESSION_STATUS_NOT_READY_PREEMPTED is here\n");
                break;
            }
        }
    }
}

/**
 * @tc.name: Camera_Metedate_Enum_004
 * @tc.desc: ErrorCode
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataEnumTest, Camera_Metedate_Enum_004, TestSize.Level1)
{
    printf("CameraMetadataEnumTest Camera_Metedate_Enum_004 start...\n");
    int32_t errorcode_[] = {
        OHOS::HDI::Camera::V1_3::ErrorCode::ERROR_INVALID_ID,
        OHOS::HDI::Camera::V1_3::ErrorCode::ERROR_PROCESS,
        OHOS::HDI::Camera::V1_3::ErrorCode::ERROR_TIMEOUT,
        OHOS::HDI::Camera::V1_3::ErrorCode::ERROR_HIGH_TEMPERATURE,
        OHOS::HDI::Camera::V1_3::ErrorCode::ERROR_ABNORMAL,
        OHOS::HDI::Camera::V1_3::ErrorCode::ERROR_ABORT,
    };
    int32_t numColors = sizeof(errorcode_) / sizeof(OHOS::HDI::Camera::V1_3::ErrorCode::ERROR_INVALID_ID);
    for (int32_t i = 0; i < numColors; i++) {
        switch (errorcode_[i]) {
            case 0: {
                printf("OHOS::HDI::Camera::V1_3::ErrorCode::ERROR_INVALID_ID is here\n");
                break;
            }
            case 1: {
                printf("OHOS::HDI::Camera::V1_3::ErrorCode::ERROR_PROCESS is here\n");
                break;
            }
            case 3: {
                printf("OHOS::HDI::Camera::V1_3::ErrorCode::ERROR_HIGH_TEMPERATURE is here\n");
                break;
            }
            case 4: {
                printf("OHOS::HDI::Camera::V1_3::ErrorCode::ERROR_ABNORMAL is here\n");
                break;
            }
            case 5: {
                printf("OHOS::HDI::Camera::V1_3::ErrorCode::ERROR_ABORT is here\n");
                break;
            }
        }
    } 
}

/**
 * @tc.name: Camera_Metedate_Enum_005
 * @tc.desc: ExtendedStreamInfoType
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataEnumTest, Camera_Metedate_Info_005, TestSize.Level1)
{
    printf("CameraMetadataEnumTest Camera_Metedate_Enum_005 start...\n");
    int32_t ExtendedStream[] = {
        OHOS::HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_DEPTH,
        OHOS::HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_MAKER_INFO,
        OHOS::HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_EXIF,
        OHOS::HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_GAINMAP,
        OHOS::HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_UNREFOCUS,
        OHOS::HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_LINEAR,
        OHOS::HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_FRAGMENT,
    };
    int32_t numColors = sizeof(ExtendedStream) / sizeof(OHOS::HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_DEPTH);
    for (int32_t i = 0; i < numColors; i++) {
        switch (ExtendedStream[i]) {
            case 3: {
                printf("OHOS::HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_DEPTH is here\n");
                break;
            }
            case 6: {
                printf("OHOS::HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_MAKER_INFO is here\n");
                break;
            }
            case 7: {
                printf("OHOS::HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_EXIF is here\n");
                break;
            }
            case 8: {
                printf("OHOS::HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_GAINMAP is here\n");
                break;
            }
            case 9: {
                printf("OHOS::HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_UNREFOCUS is here\n");
                break;
            }
            case 10: {
                printf("OHOS::HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_LINEAR is here\n");
                break;
            }
            case 11: {
                printf("OHOS::HDI::Camera::V1_3::ExtendedStreamInfoType::EXTENDED_STREAM_INFO_FRAGMENT is here\n");
                break;
            }
        }
    }
}

/**
 * @tc.name: Camera_Metedate_Enum_006
 * @tc.desc: StreamType
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataEnumTest, Camera_Metedate_Enum_006, TestSize.Level1)
{
    printf("CameraMetadataEnumTest Camera_Metedate_Enum_006 start...\n");
    int32_t streamytype_[] = {
        OHOS::HDI::Camera::V1_3::StreamType::STREAM_TYPE_PREVIEW,
        OHOS::HDI::Camera::V1_3::StreamType::STREAM_TYPE_VIDEO,
        OHOS::HDI::Camera::V1_3::StreamType::STREAM_TYPE_STILL_CAPTURE,
        OHOS::HDI::Camera::V1_3::StreamType::STREAM_TYPE_POST_VIEW,
        OHOS::HDI::Camera::V1_3::StreamType::STREAM_TYPE_ANALYZE,
        OHOS::HDI::Camera::V1_3::StreamType::STREAM_TYPE_CUSTOM,
    };
    int32_t numColors = sizeof(streamytype_) / sizeof(OHOS::HDI::Camera::V1_3::StreamType::STREAM_TYPE_PREVIEW);
    for (int32_t i = 0; i < numColors; i++) {
        switch (streamytype_[i]) {
            case 0: {
                printf("OHOS::HDI::Camera::V1_3::StreamType::STREAM_TYPE_PREVIEW is here\n");
                break;
            }
            case 1: {
                printf("OHOS::HDI::Camera::V1_3::StreamType::STREAM_TYPE_VIDEO is here\n");
                break;
            }
            case 2: {
                printf("OHOS::HDI::Camera::V1_3::StreamType::STREAM_TYPE_STILL_CAPTURE is here\n");
                break;
            }
            case 3: {
                printf("OHOS::HDI::Camera::V1_3::StreamType::EXTENDED_STREAM_INFO_GAINMAP is here\n");
                break;
            }
            case 4: {
                printf("OHOS::HDI::Camera::V1_3::StreamType::EXTENDED_STREAM_INFO_UNFOCUS is here\n");
                break;
            }
            case 5: {
                printf("OHOS::HDI::Camera::V1_3::StreamType::STREAM_TYPE_CUSTOM is here\n");
                break;
            }
        }
    } 
}

/**
 * @tc.name: Camera_Metedate_Enum_007
 * @tc.desc: MediaStreamType
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataEnumTest, Camera_Metedate_Enum_007, TestSize.Level1)
{
    printf("CameraMetadataEnumTest Camera_Metedate_Enum_007 start...\n");
    int32_t mediastream_[] = {
        OHOS::HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_VIDEO,
        OHOS::HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_METADATA,
        OHOS::HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_MAKER,
    };
    int32_t numColors = sizeof(mediastream_) / sizeof(OHOS::HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_METADATA);
    for (int32_t i = 0; i < numColors; i++) {
        switch (mediastream_[i]) {
            case 0: {
                printf("OHOS::HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_VIDEO is here\n");
                break;
            }
            case 1: {
                printf("OHOS::HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_METADATA is here\n");
                break;
            }
            case 2: {
                printf("OHOS::HDI::Camera::V1_3::MediaStreamType::MEDIA_STREAM_TYPE_MAKER is here\n");
                break;
            }
        }
    }
}

/**
 * @tc.name: Camera_Metedate_Enum_007
 * @tc.desc: MediaStreamType
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataEnumTest, Camera_Metedate_Enum_008, TestSize.Level1)
{
    printf("CameraMetadataEnumTest Camera_Metedate_Enum_008 start...\n");
    ASSERT_EQ(OHOS::HDI::Camera::V1_3::ExecutionMode::DEFAULT, 3);
    printf("OHOS::HDI::Camera::V1_3::ExecutionMode::DEFAULT is here\n");
    ASSERT_EQ(OHOS::HDI::Camera::V1_3::ErrorType::SENSOR_DATA_ERROR, 5);
    printf("OHOS::HDI::Camera::V1_3::ErrorType::SENSOR_DATA_ERROR is here\n");
    ASSERT_EQ(OHOS::HDI::Camera::V1_3::EncodeType::ENCODE_TYPE_HEIC, 4);
    printf("OHOS::HDI::Camera::V1_3::EncodeType::ENCODE_TYPE_HEIC is here\n");
    ASSERT_EQ(OHOS::HDI::Camera::V1_3::StreamError::HIGH_TEMPERATURE_ERROR, 2);
    printf("OHOS::HDI::Camera::V1_3::StreamError::HIGH_TEMPERATURE_ERROR is here\n");
}