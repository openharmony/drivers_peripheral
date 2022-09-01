/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @addtogroup Audio
 * @{
 *
 * @brief Test audio adm interface
 *
 * @since 1.0
 * @version 1.0
 */
#include "audio_adm_common.h"
#include "audio_adm_interface_test.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
    const int CONTROL_DISP_METHOD_CMD_ILLEGAL = 6;
    const int STREAM_DISP_METHOD_CMD_ILLEGAL = 30;
    const int CHANEL_MODE_ILLEGAL = 9;
    const int MAX_GAIN_VALUE = 15;
    const int MIN_GAIN_VALUE = 0;
    const int ERROR_GAIN_VALUE = MAX_GAIN_VALUE + 1;
    const int WAITE_TIME = 5;
    const int US_TO_MS = 1000;
    constexpr int MIDDLE_VOLUME = 100;
#ifdef PRODUCT_RK3568
    constexpr int MAX_VOLUME = 255;
    constexpr int MIN_VOLUME = 0;
    constexpr int OVER_MAX_VOLUME = 256;
    constexpr int BELOW_MIN_VOLUME = -1;
#else
    constexpr int MAX_VOLUME = 127;
    constexpr int MIN_VOLUME = 40;
    constexpr int OVER_MAX_VOLUME = 128;
    constexpr int BELOW_MIN_VOLUME = 39;
#endif

    class AudioAdmInterfaceTest : public testing::Test {
    public:
        static void SetUpTestCase(void);
        static void TearDownTestCase(void);
        void SetUp();
        void TearDown();
};

void AudioAdmInterfaceTest::SetUpTestCase(void) {}

void AudioAdmInterfaceTest::TearDownTestCase(void) {}

void AudioAdmInterfaceTest::SetUp(void) {}

void AudioAdmInterfaceTest::TearDown(void) {}

/**
* @tc.name  AudioControlDispatch_001
* @tc.desc  Test the ADM ctrl data analysis function,return -1 when setting the incoming parameter cmdid is illegal
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioControlDispatch_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct HdfSBuf *writeBuf = nullptr;
    struct HdfSBuf *writeReply = nullptr;

    struct AudioCtlElemValue writeElemValue = {
        .id.cardServiceName = CARD_SEVICE_NAME.c_str(),
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER,
        .id.itemName = "Mic Left Gain",
        .value[0] = 5,
    };

    service = HdfIoServiceBind(HDF_CONTROL_SERVICE.c_str());
    ASSERT_NE(nullptr, service);
    ASSERT_NE(nullptr, service->dispatcher);

    writeBuf = HdfSbufObtainDefaultSize();
    if (writeBuf == nullptr) {
        HdfIoServiceRecycle(service);
        ASSERT_NE(nullptr, writeBuf);
    }
    ret = WriteEleValueToBuf(writeBuf, writeElemValue);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = service->dispatcher->Dispatch(&service->object, CONTROL_DISP_METHOD_CMD_ILLEGAL, writeBuf, writeReply);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfSbufRecycle(writeBuf);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioControlDispatch_002
* @tc.desc  Test the ADM ctrl data analysis function,return -1 when setting the incoming parameter object is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioControlDispatch_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct HdfSBuf *writeBuf = nullptr;
    struct HdfSBuf *writeReply = nullptr;
    struct HdfObject *objectNull = nullptr;
    struct AudioCtlElemValue writeElemValue = {
        .id.cardServiceName = CARD_SEVICE_NAME.c_str(),
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER,
        .id.itemName = "Mic Left Gain",
        .value[0] = 6,
    };

    service = HdfIoServiceBind(HDF_CONTROL_SERVICE.c_str());
    ASSERT_NE(nullptr, service);
    ASSERT_NE(nullptr, service->dispatcher);

    writeBuf = HdfSbufObtainDefaultSize();
    if (writeBuf == nullptr) {
        HdfIoServiceRecycle(service);
        ASSERT_NE(nullptr, writeBuf);
    }

    ret = WriteEleValueToBuf(writeBuf, writeElemValue);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = service->dispatcher->Dispatch(objectNull, AUDIODRV_CTRL_IOCTRL_ELEM_WRITE, writeBuf, writeReply);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfSbufRecycle(writeBuf);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamDispatch_001
* @tc.desc  Test the ADM stream data analysis function,return -1 when setting the incoming parameter cmdid is illegal
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamDispatch_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct HdfSBuf *sBuf = nullptr;
    struct HdfSBuf *reply = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_CAPTURE_STREAM, .channels = 2, .period = 2048, .rate = 11025,
        .periodCount = 32, .format = AUDIO_FORMAT_PCM_24_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .silenceThreshold = 16385
    };

    service = HdfIoServiceBind(HDF_RENDER_SERVICE.c_str());
    ASSERT_NE(nullptr, service);
    ASSERT_NE(nullptr, service->dispatcher);

    sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == nullptr) {
        HdfIoServiceRecycle(service);
        ASSERT_NE(nullptr, sBuf);
    }
    ret = WriteHwParamsToBuf(sBuf, hwParams);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = service->dispatcher->Dispatch(&service->object, STREAM_DISP_METHOD_CMD_ILLEGAL, sBuf, reply);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfSbufRecycle(sBuf);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamDispatch_002
* @tc.desc  Test the ADM stream data analysis function,return -1 when setting the incoming parameter object is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamDispatch_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct HdfSBuf *sBuf = nullptr;
    struct HdfSBuf *reply = nullptr;
    struct HdfObject *objectNull = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_CAPTURE_STREAM, .channels = 2, .period = 2048, .rate = 11025,
        .periodCount = 32, .format = AUDIO_FORMAT_PCM_24_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .silenceThreshold = 16385
    };

    service = HdfIoServiceBind(HDF_RENDER_SERVICE.c_str());
    ASSERT_NE(nullptr, service);
    ASSERT_NE(nullptr, service->dispatcher);

    sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == nullptr) {
        HdfIoServiceRecycle(service);
        ASSERT_NE(nullptr, sBuf);
    }
    ret = WriteHwParamsToBuf(sBuf, hwParams);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = service->dispatcher->Dispatch(objectNull, AUDIO_DRV_PCM_IOCTRL_HW_PARAMS, sBuf, reply);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfSbufRecycle(sBuf);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioControlHostElemWriteRead001
* @tc.desc  Test the ADM ctrl function,return 0 when setting gain's value is in the range(value=5)
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioControlHostElemWriteRead001, TestSize.Level1)
{
    int32_t ret = -1;
    int32_t expectValue = 5;
    struct HdfIoService *service = nullptr;
    service = HdfIoServiceBind(HDF_CONTROL_SERVICE.c_str());
    ASSERT_NE(nullptr, service);
    ASSERT_NE(nullptr, service->dispatcher);
    struct AudioCtlElemValue elemValue = {
        .id.cardServiceName = CARD_SEVICE_NAME.c_str(),
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER,
        .id.itemName = "Mic Left Gain",
        .value[0] = 5,
    };
    ret = WriteCtrlInfo(service, elemValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = ReadCtrlInfo(service, elemValue.id, expectValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioControlHostElemWriteRead002
* @tc.desc  Test the ADM ctrl function,return 0 when setting gain's value is min value
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioControlHostElemWriteRead002, TestSize.Level1)
{
    int32_t ret = -1;
    int32_t expectValue = MIN_GAIN_VALUE;
    struct HdfIoService *service = nullptr;
    service = HdfIoServiceBind(HDF_CONTROL_SERVICE.c_str());
    ASSERT_NE(nullptr, service);
    ASSERT_NE(nullptr, service->dispatcher);
    struct AudioCtlElemValue elemValue = {
        .id.cardServiceName = CARD_SEVICE_NAME.c_str(),
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER,
        .id.itemName = "Mic Left Gain",
        .value[0] = MIN_GAIN_VALUE,
    };
    ret = WriteCtrlInfo(service, elemValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = ReadCtrlInfo(service, elemValue.id, expectValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioControlHostElemWriteRead003
* @tc.desc  Test the ADM ctrl function,return 0 when setting gain's value is max value
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioControlHostElemWriteRead003, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    int32_t expectValue = MAX_GAIN_VALUE;
    service = HdfIoServiceBind(HDF_CONTROL_SERVICE.c_str());
    ASSERT_NE(nullptr, service);
    ASSERT_NE(nullptr, service->dispatcher);
    struct AudioCtlElemValue elemValue = {
        .id.cardServiceName = CARD_SEVICE_NAME.c_str(),
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER,
        .id.itemName = "Mic Left Gain",
        .value[0] = MAX_GAIN_VALUE,
    };
    ret = WriteCtrlInfo(service, elemValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = ReadCtrlInfo(service, elemValue.id, expectValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioControlHostElemWriteRead004
* @tc.desc  Test the ADM ctrl function,return -1 when setting gain's value is out of the range(value=16)
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioControlHostElemWriteRead004, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    service = HdfIoServiceBind(HDF_CONTROL_SERVICE.c_str());
    ASSERT_NE(nullptr, service);
    ASSERT_NE(nullptr, service->dispatcher);
    struct AudioCtlElemValue elemValue = {
        .id.cardServiceName = CARD_SEVICE_NAME.c_str(),
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER,
        .id.itemName = "Mic Left Gain",
        .value[0] = ERROR_GAIN_VALUE,
    };
    ret = WriteCtrlInfo(service, elemValue);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioControlHostElemWriteread005
* @tc.desc  Test the ADM ctrl function,return 0 when setting channelmode is "AUDIO_CHANNEL_NORMAL"
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioControlHostElemWriteread005, TestSize.Level1)
{
    int32_t ret = -1;
    int32_t expectValue = AUDIO_CHANNEL_NORMAL;
    struct HdfIoService *service = nullptr;
    service = HdfIoServiceBind(HDF_CONTROL_SERVICE.c_str());
    ASSERT_NE(nullptr, service);
    ASSERT_NE(nullptr, service->dispatcher);
    struct AudioCtlElemValue elemValue = {
        .id.cardServiceName = CARD_SEVICE_NAME.c_str(),
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER,
        .id.itemName = "Render Channel Mode",
        .value[0] = AUDIO_CHANNEL_NORMAL,
    };
    ret = WriteCtrlInfo(service, elemValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = ReadCtrlInfo(service, elemValue.id, expectValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioControlHostElemWriteread006
* @tc.desc  Test the ADM ctrl function,return 0 when setting channelmode is "AUDIO_CHANNEL_BOTH_LEFT"
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioControlHostElemWriteread006, TestSize.Level1)
{
    int32_t ret = -1;
    int32_t expectValue = AUDIO_CHANNEL_BOTH_LEFT;
    struct HdfIoService *service = nullptr;
    service = HdfIoServiceBind(HDF_CONTROL_SERVICE.c_str());
    ASSERT_NE(nullptr, service);
    ASSERT_NE(nullptr, service->dispatcher);
    struct AudioCtlElemValue elemValue = {
        .id.cardServiceName = CARD_SEVICE_NAME.c_str(),
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER,
        .id.itemName = "Render Channel Mode",
        .value[0] = AUDIO_CHANNEL_BOTH_LEFT,
    };
    ret = WriteCtrlInfo(service, elemValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = ReadCtrlInfo(service, elemValue.id, expectValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioControlHostElemWriteread007
* @tc.desc  Test the ADM ctrl function,return 0 when setting channelmode is "AUDIO_CHANNEL_BOTH_RIGHT"
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioControlHostElemWriteread007, TestSize.Level1)
{
    int32_t ret = -1;
    int32_t expectValue = AUDIO_CHANNEL_BOTH_RIGHT;
    struct HdfIoService *service = nullptr;
    service = HdfIoServiceBind(HDF_CONTROL_SERVICE.c_str());
    ASSERT_NE(nullptr, service);
    ASSERT_NE(nullptr, service->dispatcher);
    struct AudioCtlElemValue elemValue = {
        .id.cardServiceName = CARD_SEVICE_NAME.c_str(),
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER,
        .id.itemName = "Render Channel Mode",
        .value[0] = AUDIO_CHANNEL_BOTH_RIGHT,
    };
    ret = WriteCtrlInfo(service, elemValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = ReadCtrlInfo(service, elemValue.id, expectValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioControlHostElemWriteread008
* @tc.desc  Test the ADM ctrl function,return 0 when setting channelmode is "AUDIO_CHANNEL_EXCHANGE"
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioControlHostElemWriteread008, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    service = HdfIoServiceBind(HDF_CONTROL_SERVICE.c_str());
    ASSERT_NE(nullptr, service);
    ASSERT_NE(nullptr, service->dispatcher);
    struct AudioCtlElemValue elemValue = {
        .id.cardServiceName = CARD_SEVICE_NAME.c_str(),
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER,
        .id.itemName = "Render Channel Mode",
        .value[0] = AUDIO_CHANNEL_EXCHANGE,
    };
    ret = WriteCtrlInfo(service, elemValue);
#ifdef PRODUCT_RK3568
    EXPECT_EQ(HDF_FAILURE, ret);
#else
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = ReadCtrlInfo(service, elemValue.id, AUDIO_CHANNEL_EXCHANGE);
    EXPECT_EQ(HDF_SUCCESS, ret);
#endif
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioControlHostElemWriteread009
* @tc.desc  Test the ADM ctrl function,return 0 when setting channelmode is "AUDIO_CHANNEL_MIX"
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioControlHostElemWriteread009, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    service = HdfIoServiceBind(HDF_CONTROL_SERVICE.c_str());
    ASSERT_NE(nullptr, service);
    ASSERT_NE(nullptr, service->dispatcher);
    struct AudioCtlElemValue elemValue = {
        .id.cardServiceName = CARD_SEVICE_NAME.c_str(),
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER,
        .id.itemName = "Render Channel Mode",
        .value[0] = AUDIO_CHANNEL_MIX,
    };
    ret = WriteCtrlInfo(service, elemValue);
#ifdef PRODUCT_RK3568
        EXPECT_EQ(HDF_FAILURE, ret);
#else
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = ReadCtrlInfo(service, elemValue.id, AUDIO_CHANNEL_MIX);
    EXPECT_EQ(HDF_SUCCESS, ret);
#endif
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioControlHostElemWriteread010
* @tc.desc  Test the ADM ctrl function,return 0 when setting channelmode is "AUDIO_CHANNEL_LEFT_MUTE"
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioControlHostElemWriteread010, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    service = HdfIoServiceBind(HDF_CONTROL_SERVICE.c_str());
    ASSERT_NE(nullptr, service);
    ASSERT_NE(nullptr, service->dispatcher);
    struct AudioCtlElemValue elemValue = {
        .id.cardServiceName = CARD_SEVICE_NAME.c_str(),
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER,
        .id.itemName = "Render Channel Mode",
        .value[0] = AUDIO_CHANNEL_LEFT_MUTE,
    };
    ret = WriteCtrlInfo(service, elemValue);
#ifdef PRODUCT_RK3568
        EXPECT_EQ(HDF_FAILURE, ret);
#else
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = ReadCtrlInfo(service, elemValue.id, AUDIO_CHANNEL_LEFT_MUTE);
    EXPECT_EQ(HDF_SUCCESS, ret);
#endif
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioControlHostElemWriteread011
* @tc.desc  Test the ADM ctrl function,return 0 when setting channelmode is "AUDIO_CHANNEL_RIGHT_MUTE"
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioControlHostElemWriteread011, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    service = HdfIoServiceBind(HDF_CONTROL_SERVICE.c_str());
    ASSERT_NE(nullptr, service);
    ASSERT_NE(nullptr, service->dispatcher);
    struct AudioCtlElemValue elemValue = {
        .id.cardServiceName = CARD_SEVICE_NAME.c_str(),
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER,
        .id.itemName = "Render Channel Mode",
        .value[0] = AUDIO_CHANNEL_RIGHT_MUTE,
    };
    ret = WriteCtrlInfo(service, elemValue);
#ifdef PRODUCT_RK3568
    EXPECT_EQ(HDF_FAILURE, ret);
#else
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = ReadCtrlInfo(service, elemValue.id, AUDIO_CHANNEL_RIGHT_MUTE);
    EXPECT_EQ(HDF_SUCCESS, ret);
#endif
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioControlHostElemWriteread012
* @tc.desc  Test the ADM ctrl function,return 0 when setting channelmode is "AUDIO_CHANNEL_BOTH_MUTE"
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioControlHostElemWriteread012, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    service = HdfIoServiceBind(HDF_CONTROL_SERVICE.c_str());
    ASSERT_NE(nullptr, service);
    ASSERT_NE(nullptr, service->dispatcher);
    struct AudioCtlElemValue elemValue = {
        .id.cardServiceName = CARD_SEVICE_NAME.c_str(),
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER,
        .id.itemName = "Render Channel Mode",
        .value[0] = AUDIO_CHANNEL_BOTH_MUTE,
    };
    ret = WriteCtrlInfo(service, elemValue);
#ifdef PRODUCT_RK3568
    EXPECT_EQ(HDF_FAILURE, ret);
#else
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = ReadCtrlInfo(service, elemValue.id, AUDIO_CHANNEL_BOTH_MUTE);
    EXPECT_EQ(HDF_SUCCESS, ret);
#endif
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioControlHostElemWriteread013
* @tc.desc  Test the ADM ctrl function,return 0 when setting channelmode is "CHANEL_MODE_ILLEGAL"
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioControlHostElemWriteread013, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct AudioCtlElemValue elemValue = {
        .id.cardServiceName = CARD_SEVICE_NAME.c_str(),
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER,
        .id.itemName = "Render Channel Mode",
        .value[0] = CHANEL_MODE_ILLEGAL,
    };
    service = HdfIoServiceBind(HDF_CONTROL_SERVICE.c_str());
    ASSERT_NE(nullptr, service);
    ASSERT_NE(nullptr, service->dispatcher);
    ret = WriteCtrlInfo(service, elemValue);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioControlHostElemWriteRead014
* @tc.desc  Test the ADM ctrl function,return 0 when getting gainthreshold
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioControlHostElemWriteRead014, TestSize.Level1)
{
    int32_t ret = -1;
    int32_t expectMinValue = MIN_GAIN_VALUE;
    int32_t expectMaxValue = MAX_GAIN_VALUE;
    struct HdfIoService *service = nullptr;
    struct HdfSBuf *readBuf = nullptr;
    struct HdfSBuf *readReply = nullptr;
    struct AudioCtlElemId id = {
        .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .iface = AUDIODRV_CTL_ELEM_IFACE_MIXER,
        .itemName = "Mic Left Gain",
    };
    struct AudioCtlElemValue readElemValue = {};
    service = HdfIoServiceBind(HDF_CONTROL_SERVICE.c_str());
    ASSERT_NE(nullptr, service);
    ASSERT_NE(nullptr, service->dispatcher);

    readReply = HdfSbufObtainDefaultSize();
    if (readReply == nullptr) {
        HdfIoServiceRecycle(service);
        ASSERT_NE(nullptr, readReply);
    }
    readBuf = HdfSbufObtainDefaultSize();
    if (readBuf == nullptr) {
        HdfSbufRecycle(readReply);
        HdfIoServiceRecycle(service);
        ASSERT_NE(nullptr, readBuf);
    }
    ret = WriteIdToBuf(readBuf, id);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = service->dispatcher->Dispatch(&service->object, AUDIODRV_CTRL_IOCTRL_ELEM_READ, readBuf, readReply);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufReadInt32(readReply, &readElemValue.value[0]);
    EXPECT_EQ(expectMaxValue, readElemValue.value[0]);
    HdfSbufReadInt32(readReply, &readElemValue.value[1]);
    EXPECT_EQ(expectMinValue, readElemValue.value[1]);

    HdfSbufRecycle(readBuf);
    HdfSbufRecycle(readReply);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioControlHostElemWriteread_015
* @tc.desc  Test the ADM control data,cmdid is AUDIODRV_CTRL_IOCTRL_ELEM_WRITE and AUDIODRV_CTRL_IOCTRL_ELEM_READ.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioControlHostElemWriteread_015, TestSize.Level1)
{
    int32_t ret = -1;
    int32_t expectValue = MIDDLE_VOLUME;
    struct HdfIoService *service = nullptr;
    service = HdfIoServiceBind(HDF_CONTROL_SERVICE.c_str());
    ASSERT_NE(nullptr, service);
    ASSERT_NE(nullptr, service->dispatcher);
    struct AudioCtlElemValue elemValue = {
        .id.cardServiceName = CARD_SEVICE_NAME.c_str(),
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER,
        .id.itemName = "Main Playback Volume",
        .value[0] = MIDDLE_VOLUME,
    };
    ret = WriteCtrlInfo(service, elemValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = ReadCtrlInfo(service, elemValue.id, expectValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfIoServiceRecycle(service);
}

/**
* @tc.name  AudioControlHostElemWriteread_016
* @tc.desc  Test the ADM control data,cmdid is AUDIODRV_CTRL_IOCTRL_ELEM_WRITE and AUDIODRV_CTRL_IOCTRL_ELEM_READ.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioControlHostElemWriteread_016, TestSize.Level1)
{
    int32_t ret = -1;
    int32_t expectValue = MIN_VOLUME;
    struct HdfIoService *service = nullptr;
    service = HdfIoServiceBind(HDF_CONTROL_SERVICE.c_str());
    ASSERT_NE(nullptr, service);
    ASSERT_NE(nullptr, service->dispatcher);
    struct AudioCtlElemValue elemValue = {
        .id.cardServiceName = CARD_SEVICE_NAME.c_str(),
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER,
        .id.itemName = "Main Playback Volume",
        .value[0] = MIN_VOLUME,
    };
    ret = WriteCtrlInfo(service, elemValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = ReadCtrlInfo(service, elemValue.id, expectValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioControlHostElemWriteread_017
* @tc.desc  Test the ADM control data,cmdid is AUDIODRV_CTRL_IOCTRL_ELEM_WRITE and AUDIODRV_CTRL_IOCTRL_ELEM_READ.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioControlHostElemWriteread_017, TestSize.Level1)
{
    int32_t ret = -1;
    int32_t expectValue = MAX_VOLUME;
    struct HdfIoService *service = nullptr;
    service = HdfIoServiceBind(HDF_CONTROL_SERVICE.c_str());
    ASSERT_NE(nullptr, service);
    ASSERT_NE(nullptr, service->dispatcher);
    struct AudioCtlElemValue elemValue = {
        .id.cardServiceName = CARD_SEVICE_NAME.c_str(),
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER,
        .id.itemName = "Main Playback Volume",
        .value[0] = MAX_VOLUME,
    };
    ret = WriteCtrlInfo(service, elemValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = ReadCtrlInfo(service, elemValue.id, expectValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioControlHostElemWriteread_018
* @tc.desc  Test the ADM control data,cmdid is AUDIODRV_CTRL_IOCTRL_ELEM_WRITE and AUDIODRV_CTRL_IOCTRL_ELEM_READ.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioControlHostElemWriteread_018, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct AudioCtlElemValue elemValue = {
        .id.cardServiceName = CARD_SEVICE_NAME.c_str(),
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER,
        .id.itemName = "Main Playback Volume",
        .value[0] = OVER_MAX_VOLUME,
    };
    service = HdfIoServiceBind(HDF_CONTROL_SERVICE.c_str());
    ASSERT_NE(nullptr, service);
    ASSERT_NE(nullptr, service->dispatcher);
    ret = WriteCtrlInfo(service, elemValue);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioControlHostElemWriteread_019
* @tc.desc  Test the ADM control data,cmdid is AUDIODRV_CTRL_IOCTRL_ELEM_WRITE and AUDIODRV_CTRL_IOCTRL_ELEM_READ.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioControlHostElemWriteread_019, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct AudioCtlElemValue elemValue = {
        .id.cardServiceName = CARD_SEVICE_NAME.c_str(),
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER,
        .id.itemName = "Main Playback Volume",
        .value[0] = BELOW_MIN_VOLUME,
    };
    service = HdfIoServiceBind(HDF_CONTROL_SERVICE.c_str());
    ASSERT_NE(nullptr, service);
    ASSERT_NE(nullptr, service->dispatcher);
    ret = WriteCtrlInfo(service, elemValue);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioControlHostElemWriteread_020
* @tc.desc  Test the ADM control data,cmdid is AUDIODRV_CTRL_IOCTRL_ELEM_WRITE and AUDIODRV_CTRL_IOCTRL_ELEM_READ.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioControlHostElemWriteread_020, TestSize.Level1)
{
    int32_t ret = -1;
    int32_t expectValue = 0;
    struct HdfIoService *service = nullptr;
    service = HdfIoServiceBind(HDF_CONTROL_SERVICE.c_str());
    ASSERT_NE(nullptr, service);
    ASSERT_NE(nullptr, service->dispatcher);
    struct AudioCtlElemValue elemValue = {
        .id.cardServiceName = CARD_SEVICE_NAME.c_str(),
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER,
        .id.itemName = "Playback Mute",
        .value[0] = 0,
    };
    ret = WriteCtrlInfo(service, elemValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = ReadCtrlInfo(service, elemValue.id, expectValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioControlHostElemWriteread_021
* @tc.desc  Test the ADM control data,cmdid is AUDIODRV_CTRL_IOCTRL_ELEM_WRITE and AUDIODRV_CTRL_IOCTRL_ELEM_READ.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioControlHostElemWriteread_021, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct AudioCtlElemValue elemValue = {
        .id.cardServiceName = CARD_SEVICE_NAME.c_str(),
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER,
        .id.itemName = "Playback Mute",
        .value[0] = 2,
    };
    service = HdfIoServiceBind(HDF_CONTROL_SERVICE.c_str());
    ASSERT_NE(nullptr, service);
    ASSERT_NE(nullptr, service->dispatcher);
    ret = WriteCtrlInfo(service, elemValue);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamHostHwParams_001
* @tc.desc  Test the ADM render stream data which is issuing hardware parameters that
*           format is AUDIO_FORMAT_PCM_8_BIT、channels is 2、cardServiceName is hdf_audio_codec_dev0.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostHwParams_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_RENDER_STREAM, .channels = 2, .period = 2048, .rate = 11025,
        .periodCount = 8, .format = AUDIO_FORMAT_PCM_8_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .startThreshold = 8190
    };
    ret = WriteHwParams(HDF_RENDER_SERVICE, service, hwParams);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamHostHwParams_002
* @tc.desc  Test the ADM render stream data which is issuing hardware parameters that
*           format is AUDIO_FORMAT_PCM_16_BIT、channels is 2、cardServiceName is hdf_audio_codec_dev0.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostHwParams_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_RENDER_STREAM, .channels = 2, .period = 2048, .rate = 22050,
        .periodCount = 8, .format = AUDIO_FORMAT_PCM_16_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .startThreshold = 8190
    };
    ret = WriteHwParams(HDF_RENDER_SERVICE, service, hwParams);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamHostHwParams_003
* @tc.desc  Test the ADM render stream data which is issuing hardware parameters that
*           format is AUDIO_FORMAT_PCM_24_BIT、channels is 2、cardServiceName is hdf_audio_codec_dev0.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostHwParams_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_RENDER_STREAM, .channels = 2, .period = 4096, .rate = 24000,
        .periodCount = 4, .format = AUDIO_FORMAT_PCM_24_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .startThreshold = 162140
    };
    ret = WriteHwParams(HDF_RENDER_SERVICE, service, hwParams);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamHostHwParams_004
* @tc.desc  Test the ADM render stream data which is issuing hardware parameters that
*           format is AUDIO_FORMAT_PCM_32_BIT 、channels is 2、cardServiceName is hdf_audio_codec_dev0.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostHwParams_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_RENDER_STREAM, .channels = 2, .period = 2048, .rate = 48190,
        .periodCount = 8, .format = AUDIO_FORMAT_PCM_32_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .startThreshold = 8190
    };
    ret = WriteHwParams(HDF_RENDER_SERVICE, service, hwParams);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamHostHwParams_005
* @tc.desc  Test the ADM render stream data which is issuing hardware parameters that
*           format is AUDIO_FORMAT_AAC_MAIN 、channels is 2、cardServiceName is hdf_audio_codec_dev0.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostHwParams_005, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_RENDER_STREAM, .channels = 2, .period = 2048, .rate = 44100,
        .periodCount = 8, .format = AUDIO_FORMAT_AAC_MAIN, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .startThreshold = 8190
    };
    ret = WriteHwParams(HDF_RENDER_SERVICE, service, hwParams);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamHostHwParams_006
* @tc.desc  Test the ADM render stream data which is issuing hardware parameters that
*           format is AUDIO_FORMAT_AAC_LC 、channels is 2、cardServiceName is hdf_audio_codec_dev0.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostHwParams_006, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_RENDER_STREAM, .channels = 2, .period = 2048, .rate = 8190,
        .periodCount = 8, .format = AUDIO_FORMAT_AAC_LC, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .startThreshold = 8190
    };
    ret = WriteHwParams(HDF_RENDER_SERVICE, service, hwParams);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamHostHwParams_007
* @tc.desc  Test the ADM render stream data which is issuing hardware parameters that
*           format is AUDIO_FORMAT_AAC_LD 、channels is 2、cardServiceName is hdf_audio_codec_dev0.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostHwParams_007, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_RENDER_STREAM, .channels = 2, .period = 2048, .rate = 32000,
        .periodCount = 8, .format = AUDIO_FORMAT_AAC_LD, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .startThreshold = 8190
    };
    ret = WriteHwParams(HDF_RENDER_SERVICE, service, hwParams);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamHostHwParams_008
* @tc.desc  Test the ADM render stream data which is issuing hardware parameters that
*           format is AUDIO_FORMAT_AAC_ELD 、channels is 2、cardServiceName is hdf_audio_codec_dev0.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostHwParams_008, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_RENDER_STREAM, .channels = 2, .period = 2048, .rate = 50000,
        .periodCount = 8, .format = AUDIO_FORMAT_AAC_ELD, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .startThreshold = 8190
    };
    ret = WriteHwParams(HDF_RENDER_SERVICE, service, hwParams);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamHostHwParams_009
* @tc.desc  Test the ADM render stream data which is issuing hardware parameters that
*           format is AUDIO_FORMAT_AAC_HE_V1 、channels is 2、cardServiceName is hdf_audio_codec_dev0.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostHwParams_009, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_RENDER_STREAM, .channels = 2, .period = 2048, .rate = 47250,
        .periodCount = 8, .format = AUDIO_FORMAT_AAC_HE_V1, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .startThreshold = 8190
    };
    ret = WriteHwParams(HDF_RENDER_SERVICE, service, hwParams);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamHostHwParams_010
* @tc.desc  Test the ADM render stream data which is issuing hardware parameters that
*           format is AUDIO_FORMAT_AAC_HE_V2 、channels is 2、cardServiceName is hdf_audio_codec_dev0.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostHwParams_010, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_RENDER_STREAM, .channels = 2, .period = 2048, .rate = 47250,
        .periodCount = 8, .format = AUDIO_FORMAT_AAC_HE_V2, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .startThreshold = 8190
    };
    ret = WriteHwParams(HDF_RENDER_SERVICE, service, hwParams);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamHostHwParams_011
* @tc.desc  Test the ADM render stream data which is issuing hardware parameters that
*           format is AUDIO_FORMAT_PCM_24_BIT 、channels is 2、cardServiceName is hdf_audio_codec_dev0.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostHwParams_011, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_CAPTURE_STREAM, .channels = 2, .period = 4096, .rate = 11025,
        .periodCount = 4, .format = AUDIO_FORMAT_PCM_24_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .silenceThreshold = 16384
    };
    ret = WriteHwParams(HDF_CAPTURE_SERVICE, service, hwParams);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamHostHwParams_012
* @tc.desc  Test the ADM render stream data which is issuing hardware parameters that
*           format is AUDIO_FORMAT_PCM_24_BIT 、channels is 1、cardServiceName is hdf_audio_codec_dev0.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostHwParams_012, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_RENDER_STREAM, .channels = 1, .period = 2048, .rate = 24000,
        .periodCount = 4, .format = AUDIO_FORMAT_PCM_24_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .startThreshold = 16384
    };
    ret = WriteHwParams(HDF_RENDER_SERVICE, service, hwParams);
#ifdef PRODUCT_RK3568
    EXPECT_EQ(HDF_FAILURE, ret);
#else
    EXPECT_EQ(HDF_SUCCESS, ret);
#endif
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamHostHwParams_013
* @tc.desc  Test the ADM render stream data which is issuing hardware parameters that
*           format is AUDIO_FORMAT_PCM_8_BIT 、channels is 8、cardServiceName is hdf_audio_codec_dev0.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostHwParams_013, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_RENDER_STREAM, .channels = 8, .period = 2048, .rate = 48000,
        .periodCount = 8, .format = AUDIO_FORMAT_PCM_8_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .startThreshold = 32766
    };
    ret = WriteHwParams(HDF_RENDER_SERVICE, service, hwParams);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamHostHwParams_014
* @tc.desc  Test the ADM render stream data which is issuing hardware parameters that
*           format is AUDIO_FORMAT_PCM_8_BIT 、channels is 8、cardServiceName is hdf_audio_codec_dev0.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostHwParams_014, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_RENDER_STREAM, .channels = 2, .period = 2047, .rate = 48000,
        .periodCount = 8, .format = AUDIO_FORMAT_PCM_8_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .startThreshold = 32766
    };
    ret = WriteHwParams(HDF_RENDER_SERVICE, service, hwParams);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamHostHwParams_015
* @tc.desc  Test the ADM render stream data which is issuing hardware parameters that
*           format is AUDIO_FORMAT_PCM_8_BIT 、channels is 8、cardServiceName is hdf_audio_codec_dev0.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostHwParams_015, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_RENDER_STREAM, .channels = 2, .period = 8192, .rate = 48000,
        .periodCount = 8, .format = AUDIO_FORMAT_PCM_8_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .startThreshold = 32766
    };
    ret = WriteHwParams(HDF_RENDER_SERVICE, service, hwParams);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamHostHwParams_016
* @tc.desc  Test the ADM render stream data which is issuing hardware parameters that
*           format is AUDIO_FORMAT_PCM_8_BIT 、channels is 8、cardServiceName is hdf_audio_codec_dev0.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostHwParams_016, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_RENDER_STREAM, .channels = 8, .period = 2048, .rate = 24000,
        .periodCount = 7, .format = AUDIO_FORMAT_PCM_24_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .startThreshold = 16384
    };
    ret = WriteHwParams(HDF_RENDER_SERVICE, service, hwParams);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamHostHwParams_017
* @tc.desc  Test the ADM render stream data which is issuing hardware parameters that
*           format is AUDIO_FORMAT_PCM_8_BIT 、channels is 8、cardServiceName is hdf_audio_codec_dev0.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostHwParams_017, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_RENDER_STREAM, .channels = 2, .period = 8193, .rate = 24000,
        .periodCount = 33, .format = AUDIO_FORMAT_PCM_24_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .startThreshold = 16384
    };
    ret = WriteHwParams(HDF_RENDER_SERVICE, service, hwParams);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamHostHwParams_018
* @tc.desc  Test the ADM render stream data which is issuing hardware parameters that
*           format is AUDIO_FORMAT_PCM_8_BIT 、channels is 8、cardServiceName is hdf_audio_codec_dev0.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostHwParams_018, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_RENDER_STREAM, .channels = 2, .period = 2048, .rate = 24000,
        .periodCount = 8, .format = AUDIO_FORMAT_PCM_24_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .startThreshold = 8193
    };
    ret = WriteHwParams(HDF_RENDER_SERVICE, service, hwParams);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamHostHwParams_019
* @tc.desc  Test the ADM render stream data which is issuing hardware parameters that
*           format is AUDIO_FORMAT_PCM_8_BIT 、channels is 8、cardServiceName is hdf_audio_codec_dev0.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostHwParams_019, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_RENDER_STREAM, .channels = 2, .period = 2048, .rate = 24000,
        .periodCount = 8, .format = AUDIO_FORMAT_PCM_24_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .startThreshold = 0
    };
    ret = WriteHwParams(HDF_RENDER_SERVICE, service, hwParams);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamHostHwParams_020
* @tc.desc  Test the ADM render stream data which is issuing hardware parameters that
*           format is AUDIO_FORMAT_PCM_24_BIT 、channels is 2、cardServiceName is hdf_audio_codec_dev0.
*           silenceThreshold is Less than minimum.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostHwParams_020, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_CAPTURE_STREAM, .channels = 2, .period = 4096, .rate = 11025,
        .periodCount = 4, .format = AUDIO_FORMAT_PCM_24_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .silenceThreshold = 4095
    };
    ret = WriteHwParams(HDF_CAPTURE_SERVICE, service, hwParams);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamHostHwParams_021
* @tc.desc  Test the ADM render stream data which is issuing hardware parameters that
*           format is AUDIO_FORMAT_PCM_24_BIT 、channels is 2、cardServiceName is hdf_audio_codec_dev0.
*           silenceThreshold is Greater than maximum.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostHwParams_021, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_CAPTURE_STREAM, .channels = 2, .period = 4096, .rate = 11025,
        .periodCount = 32, .format = AUDIO_FORMAT_PCM_24_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .silenceThreshold = 16385
    };
    ret = WriteHwParams(HDF_CAPTURE_SERVICE, service, hwParams);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamHostWrite_001
* @tc.desc  Test the ADM control data,cmdid is AUDIO_DRV_PCM_IOCTRL_WRITE.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostWrite_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct HdfSBuf *sBufT = nullptr;
    struct HdfSBuf *sBufTStop = nullptr;
    struct HdfSBuf *reply = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_RENDER_STREAM, .channels = 2, .period = 4096, .rate = 11025,
        .periodCount = 4, .format = AUDIO_FORMAT_PCM_24_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .silenceThreshold = 16384
    };

    ret = WriteFrameToSBuf(sBufT, AUDIO_FILE);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = WriteHwParams(HDF_RENDER_SERVICE, service, hwParams);
    if (ret < 0) {
        HdfSbufRecycle(sBufT);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_RENDER_PREPARE, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_WRITE, sBufT, reply);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = WriteToSBuf(sBufTStop);
    if (ret < 0) {
        HdfIoServiceRecycle(service);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_RENDER_STOP, sBufTStop, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBufT);
    HdfSbufRecycle(sBufTStop);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamHostRead_001
* @tc.desc  Test the ADM control data,cmdid is AUDIO_DRV_PCM_IOCTRL_READ.
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostRead_001, TestSize.Level1)
{
    int32_t tryNumReply = 100;
    uint32_t buffStatus = 0;
    uint32_t readSize = 0;
    struct HdfIoService *service = nullptr;
    struct HdfSBuf *sBufTStop = nullptr;
    struct AudioXferi transfer;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_CAPTURE_STREAM, .channels = 2, .period = 4096, .rate = 11025,
        .periodCount = 8, .format = AUDIO_FORMAT_PCM_24_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .silenceThreshold = 16384
    };
    int32_t ret = WriteHwParams(HDF_CAPTURE_SERVICE, service, hwParams);
    ASSERT_EQ(HDF_SUCCESS, ret);
    struct HdfSBuf *reply = HdfSbufTypedObtainCapacity(SBUF_RAW, (AUDIO_SIZE_FRAME + AUDIO_REPLY_EXTEND));
    ASSERT_NE(nullptr, reply);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_CAPTURE_PREPARE, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_CAPTURE_START, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    do {
        ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_READ, nullptr, reply);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_GE(HdfSbufReadUint32(reply, &buffStatus), HDF_SUCCESS);
        if ((int32_t)buffStatus != CIR_BUFF_NORMAL) {
            int32_t ms = buffStatus >= 0 ? buffStatus : WAITE_TIME;
            tryNumReply--;
            HdfSbufFlush(reply);
            usleep(ms*US_TO_MS);
            continue;
        }
        break;
    } while (tryNumReply > 0);
    EXPECT_GE(tryNumReply, 0);
    ret = HdfSbufReadBuffer(reply, (const void **) & (transfer.buf), &readSize);
    EXPECT_NE(transfer.buf, nullptr);
    EXPECT_NE(readSize, (uint32_t)0);
    if ((ret = WriteToSBuf(sBufTStop)) < 0) {
        HdfSbufRecycle(reply);
        HdfIoServiceRecycle(service);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_RENDER_STOP, sBufTStop, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(reply);
    HdfSbufRecycle(sBufTStop);
    HdfIoServiceRecycle(service);
}

/**
* @tc.name  AudioStreamHostRenderPrepare_001
* @tc.desc  Test the ADM stream function,return 0 when calling prepare function(render service)
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostRenderPrepare_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct HdfSBuf *sBufTStop = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_RENDER_STREAM, .channels = 2, .period = 4096, .rate = 11025,
        .periodCount = 8, .format = AUDIO_FORMAT_PCM_24_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .silenceThreshold = 16384
    };
    ret = WriteHwParams(HDF_RENDER_SERVICE, service, hwParams);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_RENDER_PREPARE, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = WriteToSBuf(sBufTStop);
    if (ret < 0) {
        HdfIoServiceRecycle(service);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_RENDER_STOP, sBufTStop, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBufTStop);
    HdfIoServiceRecycle(service);
}

/**
* @tc.name  AudioStreamHostCapturePrepare_001
* @tc.desc  Test the ADM stream function,return 0 when calling prepare function(capture service)
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostCapturePrepare_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct HdfSBuf *sBufTStop = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_CAPTURE_STREAM, .channels = 2, .period = 4096, .rate = 11025,
        .periodCount = 8, .format = AUDIO_FORMAT_PCM_24_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .silenceThreshold = 16384
    };
    ret = WriteHwParams(HDF_CAPTURE_SERVICE, service, hwParams);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_CAPTURE_PREPARE, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = WriteToSBuf(sBufTStop);
    if (ret < 0) {
        HdfIoServiceRecycle(service);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_CAPTURE_STOP, sBufTStop, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBufTStop);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  StreamHostRenderStart_001
* @tc.desc  Test the ADM stream function,return 0 when calling start function(render service)
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, StreamHostRenderStart_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct HdfSBuf *sBufTStop = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_RENDER_STREAM, .channels = 2, .period = 4096, .rate = 11025,
        .periodCount = 8, .format = AUDIO_FORMAT_PCM_24_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .silenceThreshold = 16384
    };
    ret = WriteHwParams(HDF_RENDER_SERVICE, service, hwParams);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_RENDER_PREPARE, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_RENDER_START, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = WriteToSBuf(sBufTStop);
    if (ret < 0) {
        HdfIoServiceRecycle(service);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_RENDER_STOP, sBufTStop, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBufTStop);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  StreamHostCaptureStart_001
* @tc.desc  Test the ADM stream function,return 0 when calling start function(capture service)
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, StreamHostCaptureStart_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct HdfSBuf *sBufTStop = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_CAPTURE_STREAM, .channels = 2, .period = 4096, .rate = 11025,
        .periodCount = 8, .format = AUDIO_FORMAT_PCM_24_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .silenceThreshold = 16384
    };
    ret = WriteHwParams(HDF_CAPTURE_SERVICE, service, hwParams);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_CAPTURE_PREPARE, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_CAPTURE_START, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = WriteToSBuf(sBufTStop);
    if (ret < 0) {
        HdfIoServiceRecycle(service);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_CAPTURE_STOP, sBufTStop, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBufTStop);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamHostRenderStop_001
* @tc.desc  Test the ADM ctrl function,return 0 when calling stop function(render service)
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostRenderStop_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct HdfSBuf *sBufTStop = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_RENDER_STREAM, .channels = 2, .period = 4096, .rate = 44100,
        .periodCount = 8, .format = AUDIO_FORMAT_PCM_24_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .silenceThreshold = 16384
    };
    ret = WriteHwParams(HDF_RENDER_SERVICE, service, hwParams);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_RENDER_PREPARE, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = WriteToSBuf(sBufTStop);
    if (ret < 0) {
        HdfIoServiceRecycle(service);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_RENDER_STOP, sBufTStop, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBufTStop);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamHostCaptureStop_001
* @tc.desc  Test the ADM ctrl function,return 0 when calling stop function(capture service)
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostCaptureStop_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct HdfSBuf *sBufTStop = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_CAPTURE_STREAM, .channels = 2, .period = 4096, .rate = 44100,
        .periodCount = 8, .format = AUDIO_FORMAT_PCM_24_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .silenceThreshold = 16384
    };
    ret = WriteHwParams(HDF_CAPTURE_SERVICE, service, hwParams);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_CAPTURE_PREPARE, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = WriteToSBuf(sBufTStop);
    if (ret < 0) {
        HdfIoServiceRecycle(service);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_CAPTURE_STOP, sBufTStop, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBufTStop);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamHostRenderPause_001
* @tc.desc  Test the ADM ctrl function,return 0 when calling pause function(render service)
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostRenderPause_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct HdfSBuf *sBufTStop = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_RENDER_STREAM, .channels = 2, .period = 4096, .rate = 11025,
        .periodCount = 8, .format = AUDIO_FORMAT_PCM_24_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .silenceThreshold = 16384
    };
    ret = WriteHwParams(HDF_RENDER_SERVICE, service, hwParams);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_RENDER_PREPARE, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_RENDER_START, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_RENDER_PAUSE, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = WriteToSBuf(sBufTStop);
    if (ret < 0) {
        HdfIoServiceRecycle(service);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_RENDER_STOP, sBufTStop, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBufTStop);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamHostCapturePause_001
* @tc.desc  Test the ADM ctrl function,return 0 when calling pause function(capture service)
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostCapturePause_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct HdfSBuf *sBufTStop = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_CAPTURE_STREAM, .channels = 2, .period = 4096, .rate = 11025,
        .periodCount = 8, .format = AUDIO_FORMAT_PCM_24_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .silenceThreshold = 16384
    };
    ret = WriteHwParams(HDF_CAPTURE_SERVICE, service, hwParams);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_CAPTURE_PREPARE, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_CAPTURE_START, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_CAPTURE_PAUSE, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = WriteToSBuf(sBufTStop);
    if (ret < 0) {
        HdfIoServiceRecycle(service);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_CAPTURE_STOP, sBufTStop, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBufTStop);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamHostRenderResume_001
* @tc.desc  Test the ADM ctrl function,return 0 when calling resume function(render service)
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostRenderResume_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct HdfSBuf *sBufTStop = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_RENDER_STREAM, .channels = 2, .period = 4096, .rate = 11025,
        .periodCount = 8, .format = AUDIO_FORMAT_PCM_24_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .silenceThreshold = 16384
    };
    ret = WriteHwParams(HDF_RENDER_SERVICE, service, hwParams);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_RENDER_PREPARE, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_RENDER_START, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_RENDER_PAUSE, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_RENDER_RESUME, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = WriteToSBuf(sBufTStop);
    if (ret < 0) {
        HdfIoServiceRecycle(service);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_RENDER_STOP, sBufTStop, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBufTStop);
    HdfIoServiceRecycle(service);
}
/**
* @tc.name  AudioStreamHostCaptureResume_001
* @tc.desc  Test the ADM ctrl function,return 0 when calling resume function(capture service)
* @tc.type: FUNC
*/
HWTEST_F(AudioAdmInterfaceTest, AudioStreamHostCaptureResume_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct HdfIoService *service = nullptr;
    struct HdfSBuf *sBufTStop = nullptr;
    struct AudioPcmHwParams hwParams {
        .streamType = AUDIO_CAPTURE_STREAM, .channels = 2, .period = 4096, .rate = 11025,
        .periodCount = 8, .format = AUDIO_FORMAT_PCM_24_BIT, .cardServiceName = CARD_SEVICE_NAME.c_str(),
        .isBigEndian = 0, .isSignedData = 1, .silenceThreshold = 16384
    };
    ret = WriteHwParams(HDF_CAPTURE_SERVICE, service, hwParams);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_CAPTURE_PREPARE, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_CAPTURE_START, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_CAPTURE_PAUSE, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_CAPTURE_RESUME, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = WriteToSBuf(sBufTStop);
    if (ret < 0) {
        HdfIoServiceRecycle(service);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_CAPTURE_STOP, sBufTStop, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = service->dispatcher->Dispatch(&service->object, AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE, nullptr, nullptr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBufTStop);
    HdfIoServiceRecycle(service);
}
}
