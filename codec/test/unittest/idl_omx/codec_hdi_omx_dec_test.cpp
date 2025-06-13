/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <hdf_log.h>
#include <securec.h>
#include <servmgr_hdi.h>
#include <vector>
#include "codec_function_utils.h"
#include "v4_0/codec_callback_service.h"

#define ERR_COUNT (-1)
#define ERR_COUNT_2 (10000)

using namespace std;
using namespace testing::ext;
using OHOS::sptr;
using OHOS::HDI::Base::NativeBuffer;
using namespace OHOS::HDI::Codec::V4_0;
using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace OHOS::HDI::Display::Composer::V1_0;

namespace {
constexpr CodecType TYPE = CodecType::VIDEO_DECODER;
constexpr AvCodecRole ROLE = MEDIA_ROLETYPE_VIDEO_AVC;
static sptr<ICodecComponent> g_component = nullptr;
static sptr<ICodecCallback> g_callback = nullptr;
static sptr<ICodecComponentManager> g_manager = nullptr;
static OHOS::HDI::Codec::V4_0::CodecVersionType g_version;
static std::string g_compName = "";

class CodecHdiOmxDecTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        g_manager = ICodecComponentManager::Get();
        int32_t count = 0;
        auto ret = g_manager->GetComponentNum(count);
        ASSERT_EQ(ret, HDF_SUCCESS);
        if (count <= 0) {
            return;
        }

        std::vector<CodecCompCapability> capList;
        auto err = g_manager->GetComponentCapabilityList(capList, count);
        ASSERT_TRUE(err == HDF_SUCCESS);
        for (auto cap : capList) {
            if (cap.type == TYPE && cap.role == ROLE) {
                g_compName = cap.compName;
                break;
            }
        }
    }

    static void TearDownTestCase()
    {
        g_manager = nullptr;
    }

    void SetUp()
    {
        ASSERT_TRUE(g_manager != nullptr && !g_compName.empty());
        g_callback = new CodecCallbackService();
        ASSERT_TRUE(g_callback != nullptr);
        auto ret = g_manager->CreateComponent(g_component, componentId_, g_compName.data(), APP_DATA, g_callback);
        ASSERT_EQ(ret, HDF_SUCCESS);

        struct CompVerInfo verInfo;
        ret = g_component->GetComponentVersion(verInfo);
        ASSERT_EQ(ret, HDF_SUCCESS);
        g_version = verInfo.compVersion;

        func_ = new FunctionUtil(g_version);
        ASSERT_TRUE(func_ != nullptr);
    }

    void TearDown()
    {
        std::vector<int8_t> cmdData;
        if (g_component != nullptr) {
            g_component->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_LOADED, cmdData);
        }
        if (g_manager != nullptr && g_component != nullptr) {
            g_manager->DestroyComponent(componentId_);
        }
        g_component = nullptr;
        g_callback = nullptr;
        func_ = nullptr;
    }

public:
    uint32_t componentId_ = 0;
    sptr<FunctionUtil> func_ = nullptr;
    const static uint32_t outputIndex = static_cast<uint32_t>(PortIndex::INDEX_OUTPUT);
};

HWTEST_F(CodecHdiOmxDecTest, HdfCodecHdiEmptyAndFillBufferTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    std::vector<int8_t> cmdData;
    auto ret = g_component->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);

    std::vector<int8_t> inParam, outParam;
    ret = g_component->GetParameter(OMX_IndexMax, inParam, outParam);
    ASSERT_TRUE(ret != HDF_SUCCESS);
    OMX_PARAM_PORTDEFINITIONTYPE param;
    func_->GetPortParameter(g_component, PortIndex::INDEX_INPUT, param);
    auto err = func_->UseBufferOnPort(g_component, PortIndex::INDEX_INPUT, param.nBufferCountActual,
        param.nBufferSize);
    ASSERT_TRUE(err);

    err = func_->InitBufferHandleParameter(g_component, param, outputIndex, CODEC_BUFFER_TYPE_HANDLE);
    ASSERT_TRUE(err);
    ret = func_->GetPortParameter(g_component, PortIndex::INDEX_OUTPUT, param);
    ASSERT_EQ(ret, HDF_SUCCESS);
    err = func_->UseHandleBuffer(g_component, PortIndex::INDEX_OUTPUT, param.nBufferCountActual, param.nBufferSize);
    ASSERT_TRUE(err);

    ret = g_component->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_EXECUTING, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
    err = func_->WaitState(g_component, CODEC_STATE_EXECUTING);
    ASSERT_TRUE(err);

    func_->FillAndEmptyAllBuffer(g_component, CODEC_BUFFER_TYPE_HANDLE);
    ret = g_component->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
    err = func_->WaitState(g_component, CODEC_STATE_IDLE);
    ASSERT_TRUE(err);
    ret = g_component->SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_LOADED, cmdData);
    ASSERT_EQ(ret, HDF_SUCCESS);
    err = func_->WaitState(g_component, CODEC_STATE_IDLE);
    ASSERT_TRUE(err);

    err = func_->FreeBufferOnPort(g_component, PortIndex::INDEX_INPUT);
    ASSERT_TRUE(err);
    err = func_->FreeBufferOnPort(g_component, PortIndex::INDEX_OUTPUT);
    ASSERT_TRUE(err);
    err = func_->WaitState(g_component, CODEC_STATE_LOADED);
    ASSERT_TRUE(err);
}

HWTEST_F(CodecHdiOmxDecTest, HdfCodecHdiGetComponentCapabilityListTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_component != nullptr);
    int32_t count = ERR_COUNT_2;
    std::vector<CodecCompCapability> capList;
    auto err = g_manager->GetComponentCapabilityList(capList, count);
    count = ERR_COUNT;
    err = g_manager->GetComponentCapabilityList(capList, count);
    ASSERT_TRUE(err != HDF_SUCCESS);
}
}  // namespace