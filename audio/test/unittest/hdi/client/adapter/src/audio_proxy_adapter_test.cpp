/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "audio_proxy_common_fun_test.h"
#include "audio_proxy_internal.h"

using namespace std;
using namespace comfun;
using namespace testing::ext;
namespace {
class AudioProxyAdapterTest : public testing::Test {
public:
    struct AudioManager *managerFuncs = nullptr;
    struct AudioManager *(*getAudioManager)(void) = NULL;
    struct AudioAdapterDescriptor *descs = nullptr;
    struct AudioAdapterDescriptor *desc = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioCapture *capture = nullptr;
    void *clientHandle = nullptr;
    struct AudioDeviceDescriptor devDescRender = {};
    struct AudioSampleAttributes attrsRender = {};
    struct AudioDeviceDescriptor devDescCapture = {};
    struct AudioSampleAttributes attrsCapture = {};
    virtual void SetUp();
    virtual void TearDown();
};

void AudioProxyAdapterTest::SetUp()
{
    clientHandle = GetDynamicLibHandle(RESOLVED_PATH);
    ASSERT_NE(clientHandle, nullptr);
    getAudioManager = (struct AudioManager *(*)())(dlsym(clientHandle, FUNCTION_NAME.c_str()));
    ASSERT_NE(getAudioManager, nullptr);
    managerFuncs = getAudioManager();
    ASSERT_NE(managerFuncs, nullptr);
    int32_t size = 0;
    ASSERT_EQ(HDF_SUCCESS, managerFuncs->GetAllAdapters(managerFuncs, &descs, &size));
    desc = &descs[0];
    ASSERT_EQ(HDF_SUCCESS, managerFuncs->LoadAdapter(managerFuncs, desc, &adapter));
    ASSERT_NE(adapter, nullptr);
    ASSERT_EQ(HDF_SUCCESS, InitDevDesc(devDescRender));
    ASSERT_EQ(HDF_SUCCESS, InitAttrs(attrsRender));
    ASSERT_EQ(HDF_SUCCESS, adapter->CreateRender(adapter, &devDescRender, &attrsRender, &render));

    ASSERT_EQ(HDF_SUCCESS, InitDevDescCapture(devDescCapture));
    ASSERT_EQ(HDF_SUCCESS, InitAttrsCapture(attrsCapture));
    ASSERT_EQ(HDF_SUCCESS, adapter->CreateCapture(adapter, &devDescCapture, &attrsCapture, &capture));
}

void AudioProxyAdapterTest::TearDown()
{
    if (adapter != nullptr) {
        adapter->DestroyRender(adapter, render);
        render = nullptr;
        adapter->DestroyCapture(adapter, capture);
        capture = nullptr;
    }
    if (managerFuncs != nullptr) {
        managerFuncs->UnloadAdapter(managerFuncs, adapter);
        adapter = nullptr;
        managerFuncs->ReleaseAudioManagerObject(managerFuncs);
        managerFuncs = nullptr;
    }
    if (clientHandle != nullptr) {
        dlclose(clientHandle);
        clientHandle = nullptr;
    }
}

HWTEST_F(AudioProxyAdapterTest, AdapterInitAllPorts_001, TestSize.Level1)
{
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterInitAllPorts(nullptr));
}

HWTEST_F(AudioProxyAdapterTest, AdapterInitAllPorts_002, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    const char *tempPtr = hwAdapter->adapterDescriptor.adapterName;
    hwAdapter->adapterDescriptor.adapterName = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterInitAllPorts(adapter));
    hwAdapter->adapterDescriptor.adapterName = tempPtr;
}

HWTEST_F(AudioProxyAdapterTest, AdapterInitAllPorts_003, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    struct AudioPort *ports = hwAdapter->adapterDescriptor.ports;
    hwAdapter->adapterDescriptor.ports = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, AudioProxyAdapterInitAllPorts(adapter));
    hwAdapter->adapterDescriptor.ports = ports;
    ports = nullptr;
}

HWTEST_F(AudioProxyAdapterTest, AdapterInitAllPorts_004, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    uint32_t portNum = hwAdapter->adapterDescriptor.portNum;
    hwAdapter->adapterDescriptor.portNum = 0;
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, AudioProxyAdapterInitAllPorts(adapter));
    hwAdapter->adapterDescriptor.portNum = portNum;
}

HWTEST_F(AudioProxyAdapterTest, AdapterInitAllPorts_005, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, AudioProxyAdapterInitAllPorts(adapter));
}

HWTEST_F(AudioProxyAdapterTest, AdapterCreateRender_001, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    struct AudioRender *render = nullptr;
    const struct AudioDeviceDescriptor *descTemp = nullptr;
    const struct AudioSampleAttributes *attrsTemp = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterCreateRender(nullptr, descTemp, attrsTemp, &render));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterCreateRender(adapter, nullptr, attrsTemp, &render));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterCreateRender(adapter, descTemp, nullptr, &render));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterCreateRender(adapter, descTemp, attrsTemp, nullptr));
}

HWTEST_F(AudioProxyAdapterTest, AdapterCreateRender_002, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    struct HdfRemoteService *proxyRemoteHandle = hwAdapter->proxyRemoteHandle;
    hwAdapter->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterCreateRender(adapter, &devDescRender, &attrsRender,
                                                                         &render));
    hwAdapter->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyAdapterTest, AdapterDestroyRender_001, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    struct AudioRender render;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterDestroyRender(nullptr, &render));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterDestroyRender(adapter, nullptr));
}

HWTEST_F(AudioProxyAdapterTest, AdapterDestroyRender_002, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterDestroyRender(adapter, render));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyAdapterTest, AdapterDestroyRender_003, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, AudioProxyAdapterDestroyRender(adapter, render));
}

HWTEST_F(AudioProxyAdapterTest, AdapterCreateCapture_001, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    struct AudioCapture *capture = nullptr;
    const struct AudioDeviceDescriptor *descTemp = nullptr;
    const struct AudioSampleAttributes *attrsTemp = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterCreateCapture(nullptr, descTemp, attrsTemp, &capture));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterCreateCapture(adapter, nullptr, attrsTemp, &capture));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterCreateCapture(adapter, descTemp, nullptr, &capture));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterCreateCapture(adapter, descTemp, attrsTemp, nullptr));
}

HWTEST_F(AudioProxyAdapterTest, AdapterCreateCapture_002, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    struct HdfRemoteService *proxyRemoteHandle = hwAdapter->proxyRemoteHandle;
    hwAdapter->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterCreateCapture(adapter, &devDescCapture, &attrsCapture,
                                                                          &capture));
    hwAdapter->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyAdapterTest, AdapterDestroyCapture_001, TestSize.Level1)
{
    struct AudioAdapter adapter;
    struct AudioCapture capture;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterDestroyCapture(nullptr, &capture));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterDestroyCapture(&adapter, nullptr));
}

HWTEST_F(AudioProxyAdapterTest, AdapterDestroyCapture_002, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterDestroyCapture(adapter, capture));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyAdapterTest, AdapterDestroyCapture_003, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, AudioProxyAdapterDestroyCapture(adapter, capture));
}

HWTEST_F(AudioProxyAdapterTest, AdapterGetPortCapability_001, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    const struct AudioPort *port = nullptr;
    struct AudioPortCapability capability;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterGetPortCapability(nullptr, port, &capability));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterGetPortCapability(adapter, nullptr, &capability));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterGetPortCapability(adapter, port, nullptr));
}

HWTEST_F(AudioProxyAdapterTest, AdapterGetPortCapability_002, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    struct AudioPort port = {
        .dir = PORT_OUT,
        .portId = 0,
        .portName = "AOP",
    };
    struct AudioPortCapability capability;
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    struct HdfRemoteService *proxyRemoteHandle = hwAdapter->proxyRemoteHandle;
    hwAdapter->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, AudioProxyAdapterGetPortCapability(adapter, &port, &capability));
    hwAdapter->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyAdapterTest, AdapterGetPortCapability_003, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    struct AudioPort port = {
        .dir = PORT_OUT,
        .portId = 0,
        .portName = "AOP",
    };
    struct AudioPortCapability capability;
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    struct AudioPortAndCapability *hwAdapterPortCapabilitys = hwAdapter->portCapabilitys;
    hwAdapter->portCapabilitys = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, AudioProxyAdapterGetPortCapability(adapter, &port, &capability));
    hwAdapter->portCapabilitys = hwAdapterPortCapabilitys;
}

HWTEST_F(AudioProxyAdapterTest, AdapterGetPortCapability_004, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    struct AudioPort port = {
        .dir = PORT_OUT,
        .portId = 0,
        .portName = "AOP",
    };
    struct AudioPortCapability capability;
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    int32_t portNum = hwAdapter->adapterDescriptor.portNum;
    hwAdapter->adapterDescriptor.portNum = 0;
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, AudioProxyAdapterGetPortCapability(adapter, &port, &capability));
    hwAdapter->adapterDescriptor.portNum = portNum;
}

HWTEST_F(AudioProxyAdapterTest, AdapterSetPassthroughMode_001, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    struct AudioPort port = {
        .dir = PORT_OUT,
        .portId = 0,
        .portName = "AOP",
    };
    int32_t ret = AudioProxyAdapterSetPassthroughMode(nullptr, &port, PORT_PASSTHROUGH_LPCM);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    ret = AudioProxyAdapterSetPassthroughMode(adapter, nullptr, PORT_PASSTHROUGH_LPCM);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    port.portName = nullptr;
    ret = AudioProxyAdapterSetPassthroughMode(adapter, &port, PORT_PASSTHROUGH_LPCM);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
}

HWTEST_F(AudioProxyAdapterTest, AdapterSetPassthroughMode_002, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    struct AudioPort port;
    port.dir = PORT_IN;
    port.portName = nullptr;
    AudioPortPassthroughMode mode = PORT_PASSTHROUGH_LPCM;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterSetPassthroughMode(adapter, &port, mode));
}

HWTEST_F(AudioProxyAdapterTest, AdapterSetPassthroughMode_003, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    int32_t ret = AudioProxyAdapterInitAllPorts(adapter);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    struct AudioPort port;
    port.dir = PORT_OUT;
    port.portId = 0;
    port.portName = "AOP";
    ret = AudioProxyAdapterSetPassthroughMode(adapter, &port, PORT_PASSTHROUGH_LPCM);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
}

HWTEST_F(AudioProxyAdapterTest, AdapterSetPassthroughMode_004, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    struct AudioPort port;
    port.dir = PORT_OUT;
    port.portId = 1;
    port.portName = "abc";
    int32_t ret = AudioProxyAdapterSetPassthroughMode(adapter, &port, PORT_PASSTHROUGH_LPCM);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
}

HWTEST_F(AudioProxyAdapterTest, AdapterSetPassthroughMode_005, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    struct AudioPort port;
    port.dir = PORT_OUT;
    port.portId = 1;
    port.portName = "AOP";
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    struct HdfRemoteService *proxyRemoteHandle = hwAdapter->proxyRemoteHandle;
    hwAdapter->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, AudioProxyAdapterSetPassthroughMode(adapter, &port, PORT_PASSTHROUGH_LPCM));
    hwAdapter->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyAdapterTest, AdapterGetPassthroughMode_001, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    struct AudioPort port;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterGetPassthroughMode(nullptr, &port, nullptr));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterGetPassthroughMode(adapter, nullptr, nullptr));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterGetPassthroughMode(adapter, &port, nullptr));
    port.portName = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterGetPassthroughMode(adapter, &port, nullptr));
}

HWTEST_F(AudioProxyAdapterTest, AdapterGetPassthroughMode_002, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    struct AudioPort port;
    port.dir = PORT_IN;
    port.portId = 1;
    port.portName = "abc";
    AudioPortPassthroughMode mode;
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, AudioProxyAdapterGetPassthroughMode(adapter, &port, &mode));
}

HWTEST_F(AudioProxyAdapterTest, AdapterGetPassthroughMode_003, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    struct AudioPort *port = new AudioPort;
    port->dir = PORT_OUT;
    port->portId = 0;
    port->portName = "AOP";
    AudioPortPassthroughMode mode;
    EXPECT_EQ(AUDIO_HAL_SUCCESS, AudioProxyAdapterInitAllPorts(adapter));
    EXPECT_EQ(AUDIO_HAL_SUCCESS, AudioProxyAdapterGetPassthroughMode(adapter, port, &mode));
    delete port;
    port = nullptr;
}

HWTEST_F(AudioProxyAdapterTest, AdapterGetPassthroughMode_004, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    struct AudioPort port;
    port.dir = PORT_OUT;
    port.portId = 1;
    port.portName = "abc";
    AudioPortPassthroughMode mode = PORT_PASSTHROUGH_LPCM;
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, AudioProxyAdapterGetPassthroughMode(adapter, &port, &mode));
}

HWTEST_F(AudioProxyAdapterTest, AdapterGetPassthroughMode_005, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    struct AudioPort port;
    port.dir = PORT_OUT;
    port.portId = 1;
    port.portName = "AOP";
    AudioPortPassthroughMode mode = PORT_PASSTHROUGH_LPCM;
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    struct HdfRemoteService *proxyRemoteHandle = hwAdapter->proxyRemoteHandle;
    hwAdapter->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, AudioProxyAdapterGetPassthroughMode(adapter, &port, &mode));
    hwAdapter->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyAdapterTest, AdapterSetExtraParams_001, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    enum AudioExtParamKey key = AUDIO_EXT_PARAM_KEY_NONE;
    const char *condition = nullptr;
    char value[AUDIO_ADAPTER_BUF_TEST];
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterSetExtraParams(nullptr, key, condition, value));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterSetExtraParams(adapter, key, condition, nullptr));
}

HWTEST_F(AudioProxyAdapterTest, AdapterSetExtraParams_002, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    enum AudioExtParamKey key = AUDIO_EXT_PARAM_KEY_NONE;
    const char *condition = nullptr;
    char value[AUDIO_ADAPTER_BUF_TEST];
    struct AudioHwAdapter *hwAdapter = reinterpret_cast<struct AudioHwAdapter *>(adapter);
    struct HdfRemoteService *proxyRemoteHandle = hwAdapter->proxyRemoteHandle;
    hwAdapter->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, AudioProxyAdapterSetExtraParams(adapter, key, condition, value));
    hwAdapter->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyAdapterTest, AdapterGetExtraParams_001, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    enum AudioExtParamKey key = AUDIO_EXT_PARAM_KEY_NONE;
    char condition[AUDIO_ADAPTER_BUF_TEST];
    char value[AUDIO_ADAPTER_BUF_TEST];
    int32_t length = AUDIO_ADAPTER_BUF_TEST;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterGetExtraParams(nullptr, key, condition, value, length));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterGetExtraParams(adapter, key, condition, nullptr, length));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyAdapterGetExtraParams(adapter, key, condition, value, 0));
}

HWTEST_F(AudioProxyAdapterTest, AdapterGetExtraParams_002, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    enum AudioExtParamKey key = AUDIO_EXT_PARAM_KEY_NONE;
    char condition[AUDIO_ADAPTER_BUF_TEST];
    char value[AUDIO_ADAPTER_BUF_TEST];
    int32_t length = AUDIO_ADAPTER_BUF_TEST;
    struct AudioHwAdapter *hwAdapter = reinterpret_cast<struct AudioHwAdapter *>(adapter);
    struct HdfRemoteService *proxyRemoteHandle = hwAdapter->proxyRemoteHandle;
    hwAdapter->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, AudioProxyAdapterGetExtraParams(adapter, key, condition, value, length));
    hwAdapter->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyAdapterTest, AdapterSetMicMute_001, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    bool mute = false;
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, AudioProxyAdapterSetMicMute(adapter, mute));
}

HWTEST_F(AudioProxyAdapterTest, AdapterGetMicMute_001, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    bool mute = false;
    EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, AudioProxyAdapterGetMicMute(adapter, &mute));
}
}
