/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <gtest/gtest-param-test.h>
#include <numeric>
#include "zencoder_tester.h"
#include "zdecoder_tester.h"
#include "command_parse.h"

namespace Vendor::ZCodec {

using namespace testing::ext;
using namespace std;
using namespace OHOS::HDI::Codec::Zcodec;

class ZCodecHdiEncBufferTest : public testing::TestWithParam<bool> {
public:
    static void SetUpTestCase()
    {
        ASSERT_TRUE(CreateFakeYuv(INPUT_FILE_PATH, width, height, 4));
    }

    static void TearDownTestCase()
    {
    }

    void SetUp()
    {
    }

    void TearDown()
    {
    }

    static bool CreateFakeYuv(const string& dstPath, uint32_t w, uint32_t h, uint32_t frameCnt)
    {
        ofstream ofs(dstPath, ios::binary);
        if (!ofs.is_open()) {
            CODEC_LOGE("cannot create %s", dstPath.c_str());
            return false;
        }
        vector<char> line(w);
        std::iota(line.begin(), line.end(), 0);
        for (uint32_t n = 0; n < frameCnt; n++) {
            for (uint32_t i = 0; i < h; i++) {
                ofs.write(line.data(), line.size());
            }
            for (uint32_t i = 0; i < h / 2; i++) { // 2: yuvsp ratio
                ofs.write(line.data(), line.size());
            }
        }
        return true;
    }
public:
    bool isPassthrough = false;
    static constexpr uint32_t width = 176;
    static constexpr uint32_t height = 144;
    static constexpr char INPUT_FILE_PATH[] = "/data/test/media/176x144.yuv";

};

/**
 * @tc.name: ZCodecHdiTest_H264_buffer_test_001
 * @tc.desc: H264 encode and decode end-to-end test
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncBufferTest, ZCodecHdiTest_H264_buffer_test_001, TestSize.Level1)
{
    // Step 1: Encode YUV to H264 bitstream
    CommandOpt encOpt = {
        .inputFile = INPUT_FILE_PATH,
        .w = width,
        .h = height,
        .protocol = CodeType::H264,
        .pixfmt = OHOS::GRAPHIC_PIXEL_FMT_YCBCR_420_SP,
        .isPassthrough = GetParam(),
        .enableDump = 1,
    };
    TestZEncoder encTester(encOpt);
    encTester.RunOnThread();
    encTester.WaitDone();
    ASSERT_TRUE(encTester.IsSuccess());

    // Step 2: Get encoded output file path and use it as decoder input
    string encOutputFile = encOpt.GetDumpOutputFile(1, 1);
    ASSERT_FALSE(encOutputFile.empty());

    // Step 3: Decode the H264 bitstream
    CommandOpt decOpt = {
        .isEncoder = false,
        .inputFile = encOutputFile,
        .w = width,
        .h = height,
        .protocol = CodeType::H264,
        .isPassthrough = GetParam(),
    };
    decOpt.Print();
    TestZDecoder decTester(decOpt);
    decTester.RunOnThread();
    decTester.WaitDone();
    ASSERT_TRUE(decTester.IsSuccess());
}

/**
 * @tc.name: ZCodecHdiTest_H264_buffer_test_multi_001
 * @tc.desc: try to run H264 zencoder in multiple instances
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncBufferTest, ZCodecHdiTest_H264_buffer_test_multi_001, TestSize.Level1)
{
    CommandOpt opt = {
        .inputFile = INPUT_FILE_PATH,
        .w = width,
        .h = height,
        .protocol = CodeType::H264,
        .pixfmt = OHOS::GRAPHIC_PIXEL_FMT_YCBCR_420_SP,
        .isPassthrough = GetParam(),
        .instanceNum = 4
    };
    TestZEncoder tester(opt);
    tester.RunOnThread();
    tester.WaitDone();
    ASSERT_TRUE(tester.IsSuccess());
}

/**
 * @tc.name: ZCodecHdiTest_H265_buffer_test_001
 * @tc.desc: try to run H264 zencoder
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncBufferTest, ZCodecHdiTest_H265_buffer_test_001, TestSize.Level1)
{
    CommandOpt encOpt = {
        .inputFile = INPUT_FILE_PATH,
        .w = width,
        .h = height,
        .protocol = CodeType::H265,
        .pixfmt = OHOS::GRAPHIC_PIXEL_FMT_YCBCR_420_SP,
        .isPassthrough = GetParam(),
        .enableDump = 1,
    };
    TestZEncoder tester(encOpt);
    tester.RunOnThread();
    tester.WaitDone();
    ASSERT_TRUE(tester.IsSuccess());

    // Step 2: Get encoded output file path and use it as decoder input
    string encOutputFile = encOpt.GetDumpOutputFile(1, 1);
    ASSERT_FALSE(encOutputFile.empty());

    // Step 3: Decode the H265 bitstream
    CommandOpt decOpt = {
        .isEncoder = false,
        .inputFile = encOutputFile,
        .w = width,
        .h = height,
        .protocol = CodeType::H265,
        .isPassthrough = GetParam(),
    };
    decOpt.Print();
    TestZDecoder decTester(decOpt);
    decTester.RunOnThread();
    decTester.WaitDone();
    ASSERT_TRUE(decTester.IsSuccess());
}

/**
 * @tc.name: ZCodecHdiTest_H265_buffer_test_multi_001
 * @tc.desc: try to run H264 zencoder in multiple instances
 * @tc.type: FUNC
 */
HWTEST_P(ZCodecHdiEncBufferTest, ZCodecHdiTest_H265_buffer_test_multi_001, TestSize.Level1)
{
    CommandOpt opt = {
        .inputFile = INPUT_FILE_PATH,
        .w = width,
        .h = height,
        .protocol = CodeType::H265,
        .pixfmt = OHOS::GRAPHIC_PIXEL_FMT_YCBCR_420_SP,
        .isPassthrough = GetParam(),
        .instanceNum = 4
    };
    TestZEncoder tester(opt);
    tester.RunOnThread();
    tester.WaitDone();
    ASSERT_TRUE(tester.IsSuccess());
}


INSTANTIATE_TEST_SUITE_P(
    ZCodecHdiEncBufferTest,
    ZCodecHdiEncBufferTest,
    testing::Values(false, true));

}