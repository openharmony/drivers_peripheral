/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "hdf_audio_events.h"
#include "hdf_io_service_if.h"
#include "hdf_remote_adapter_if.h"
#include "hdf_service_status.h"
#include "ioservstat_listener.h"
#include "servstat_listener_hdi.h"
#include "svcmgr_ioservice.h"
#include "audio_events.h"
#include "audio_hdi_common.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
const string CODEC_SERVICE_NAME = "hdf_audio_codec_primary_dev0";
constexpr int BUFFER_SIZE_BIT = 16 * 1024;
constexpr uint64_t FILE_SIZE_BYTE = 64;
constexpr uint64_t FILE_SIZE_BIT = FILE_SIZE_BYTE * 1024;
uint32_t g_reportCount = 0;
static void AudioThresholdReportReceived(struct ServiceStatusListener *listener, struct ServiceStatus *svcStatus);
class AudioThresholdReportTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static struct ISvcMgrIoservice *servmgr;
    static struct ServiceStatusListener *listener;
    static TestAudioManager *manager;
};

TestAudioManager *AudioThresholdReportTest::manager = nullptr;
struct ISvcMgrIoservice *AudioThresholdReportTest::servmgr = nullptr;
struct ServiceStatusListener *AudioThresholdReportTest::listener = nullptr;
using THREAD_FUNC = void *(*)(void *);
void AudioThresholdReportTest::SetUpTestCase(void)
{
    (void)HdfRemoteGetCallingPid();
    ASSERT_NE(nullptr, GetAudioManagerFuncs());
    manager = getAudioManager();
    ASSERT_NE(nullptr, manager);
    servmgr = SvcMgrIoserviceGet();
    ASSERT_NE(nullptr, servmgr);
    listener = IoServiceStatusListenerNewInstance();
    ASSERT_NE(nullptr, listener);

    listener->callback = AudioThresholdReportReceived;
    int status = servmgr->RegisterServiceStatusListener(servmgr, listener, DEVICE_CLASS_AUDIO);
    ASSERT_EQ(HDF_SUCCESS, status);
}

void AudioThresholdReportTest::TearDownTestCase(void)
{
    if (manager != nullptr) {
        (void)manager->ReleaseAudioManagerObject(manager);
        manager = nullptr;
    }
    (void)servmgr->UnregisterServiceStatusListener(servmgr, listener);
    (void)HdiServiceStatusListenerFree(listener);
    listener = nullptr;
    (void)SvcMgrIoserviceRelease(servmgr);
    servmgr = nullptr;
}

void AudioThresholdReportTest::SetUp(void) {}

void AudioThresholdReportTest::TearDown(void) {}

void AudioThresholdReportReceived(struct ServiceStatusListener *listener, struct ServiceStatus *svcStatus)
{
    if (listener == nullptr || svcStatus == nullptr) {
        return;
    }
    struct AudioEvent thresholdReportEvent = {};
    if (!strcmp(svcStatus->serviceName, CODEC_SERVICE_NAME.c_str())) {
        AudioPnpMsgReadValue(svcStatus->info, "EVENT_TYPE", &(thresholdReportEvent.eventType));
        AudioPnpMsgReadValue(svcStatus->info, "DEVICE_TYPE", &(thresholdReportEvent.deviceType));
    }
    if (thresholdReportEvent.eventType == HDF_AUDIO_CAPTURE_THRESHOLD &&
        thresholdReportEvent.deviceType == HDF_AUDIO_PRIMARY_DEVICE) {
        g_reportCount++;
    }
}

/**
* @tc.name  AudioThresholdCaptureReport_001
* @tc.desc  test Threshold Reporting function ,Start recording can be reported.
* @tc.type: FUNC
*/
HWTEST_F(AudioThresholdReportTest, AudioThresholdCaptureReport_001, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t replyBytes = 0;
    uint64_t requestBytes = BUFFER_SIZE_BIT;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    g_reportCount = 0;
    uint32_t expectReportCount = 1;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Start((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    char *frame = (char *)calloc(1, BUFFER_SIZE_BIT);
    EXPECT_NE(nullptr, frame);
    ret = capture->CaptureFrame(capture, frame, requestBytes, &replyBytes);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(expectReportCount, g_reportCount);
    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}
/**
* @tc.name  AudioThresholdCaptureReport_002
* @tc.desc  test Threshold Reporting function is normal,when Recording.
* @tc.type: FUNC
*/
HWTEST_F(AudioThresholdReportTest, AudioThresholdCaptureReport_002, TestSize.Level1)
{
    int32_t ret = -1;
    g_reportCount =0;
    ASSERT_NE(nullptr, manager);
    uint32_t expectReportCount = FILE_SIZE_BIT / BUFFER_SIZE_BIT + 1;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC,
        .path = AUDIO_CAPTURE_FILE.c_str(), .fileSize = FILE_SIZE_BYTE
    };

    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)RecordAudio, &audiopara);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = ThreadRelease(audiopara);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(expectReportCount, g_reportCount);
}
/**
* @tc.name  AudioThresholdCaptureReport_003
* @tc.desc  test Threshold Reporting function,No threshold reporting when no recording.
* @tc.type: FUNC
*/
HWTEST_F(AudioThresholdReportTest, AudioThresholdCaptureReport_003, TestSize.Level1)
{
    g_reportCount = 0;
    int32_t ret = -1;
    uint64_t requestBytes = 0;
    uint64_t replyBytes = 0;
    uint32_t expectReportCount = 0;
    AudioPortPin pins = PIN_OUT_SPEAKER;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    char *frame = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, pins, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Start((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = RenderFramePrepare(AUDIO_FILE, frame, requestBytes);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->RenderFrame(render, frame, requestBytes, &replyBytes);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    render->control.Stop((AudioHandle)render);
    EXPECT_EQ(expectReportCount, g_reportCount);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}
}
