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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "audio_proxy_common_fun_test.h"
#include "audio_proxy_internal.h"

using namespace std;
using namespace commonfun;
using namespace testing::ext;
namespace {
class AudioProxyAdapterTest : public testing::Test {
public:
    struct AudioManager *managerFuncs = nullptr;
    struct AudioAdapterDescriptor *descs = nullptr;
    struct AudioAdapterDescriptor *desc = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioDeviceDescriptor devDescRender = {};
    struct AudioSampleAttributes attrsRender = {};
    struct AudioDeviceDescriptor devDescCapture = {};
    struct AudioSampleAttributes attrsCapture = {};
    virtual void SetUp();
    virtual void TearDown();
};

void AudioProxyAdapterTest::SetUp()
{
    managerFuncs = GetAudioManagerFuncs();
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
}

HWTEST_F(AudioProxyAdapterTest, AdapterGetPortCapability_001, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    const struct AudioPort *port = nullptr;
    struct AudioPortCapability capability;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, adapter->GetPortCapability(nullptr, port, &capability));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, adapter->GetPortCapability(adapter, nullptr, &capability));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, adapter->GetPortCapability(adapter, port, nullptr));
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
    EXPECT_EQ(HDF_FAILURE, adapter->GetPortCapability(adapter, &port, &capability));
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
    EXPECT_EQ(HDF_FAILURE, adapter->GetPortCapability(adapter, &port, &capability));
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
    EXPECT_EQ(HDF_FAILURE, adapter->GetPortCapability(adapter, &port, &capability));
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
    int32_t ret = adapter->SetPassthroughMode(nullptr, &port, PORT_PASSTHROUGH_LPCM);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    ret = adapter->SetPassthroughMode(adapter, nullptr, PORT_PASSTHROUGH_LPCM);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    port.portName = nullptr;
    ret = adapter->SetPassthroughMode(adapter, &port, PORT_PASSTHROUGH_LPCM);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}

HWTEST_F(AudioProxyAdapterTest, AdapterSetPassthroughMode_002, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    struct AudioPort port;
    port.dir = PORT_IN;
    port.portName = nullptr;
    AudioPortPassthroughMode mode = PORT_PASSTHROUGH_LPCM;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, adapter->SetPassthroughMode(adapter, &port, mode));
}

HWTEST_F(AudioProxyAdapterTest, AdapterSetPassthroughMode_003, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    int32_t ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    struct AudioPort port;
    port.dir = PORT_OUT;
    port.portId = 0;
    port.portName = "AOP";
    ret = adapter->SetPassthroughMode(adapter, &port, PORT_PASSTHROUGH_LPCM);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
}

HWTEST_F(AudioProxyAdapterTest, AdapterSetPassthroughMode_004, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    struct AudioPort port;
    port.dir = PORT_OUT;
    port.portId = 1;
    port.portName = "abc";
    int32_t ret = adapter->SetPassthroughMode(adapter, &port, PORT_PASSTHROUGH_LPCM);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioProxyAdapterTest, AdapterGetPassthroughMode_001, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    struct AudioPort port;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, adapter->GetPassthroughMode(nullptr, &port, nullptr));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, adapter->GetPassthroughMode(adapter, nullptr, nullptr));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, adapter->GetPassthroughMode(adapter, &port, nullptr));
    port.portName = nullptr;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, adapter->GetPassthroughMode(adapter, &port, nullptr));
}

HWTEST_F(AudioProxyAdapterTest, AdapterGetPassthroughMode_002, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    struct AudioPort port;
    port.dir = PORT_IN;
    port.portId = 1;
    port.portName = "abc";
    AudioPortPassthroughMode mode;
    EXPECT_EQ(HDF_FAILURE, adapter->GetPassthroughMode(adapter, &port, &mode));
}

HWTEST_F(AudioProxyAdapterTest, AdapterGetPassthroughMode_003, TestSize.Level1)
{
    ASSERT_NE(adapter, nullptr);
    struct AudioPort *port = new AudioPort;
    port->dir = PORT_OUT;
    port->portId = 0;
    port->portName = "AOP";
    AudioPortPassthroughMode mode;
    EXPECT_EQ(HDF_SUCCESS, adapter->InitAllPorts(adapter));
    EXPECT_EQ(HDF_FAILURE, adapter->GetPassthroughMode(adapter, port, &mode));
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
    EXPECT_EQ(HDF_FAILURE, adapter->GetPassthroughMode(adapter, &port, &mode));
}
}
