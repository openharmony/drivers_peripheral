/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "mjpeg_decoder.h"
#include "test_utils.h"
#include <chrono>
#include <cmath>
#include <future>
#include <gtest/gtest.h>

constexpr uint32_t MAX_DECODE_TIME_MS_PERF = 1000;

using namespace OHOS::Camera;

// ==================== FfmpegMjpegDecoder Tests ====================

std::shared_ptr<FfmpegMjpegDecoder> g_ffmpegDecoder = nullptr;

class FfmpegMjpegDecoderTest : public ::testing::Test {
protected:
    static void SetUpTestCase(void)
    {
        std::cout << "==========[test log] FfmpegMjpegDecoderTest SetUpTestCase" << std::endl;
        g_ffmpegDecoder = std::make_shared<FfmpegMjpegDecoder>();
        if (!g_ffmpegDecoder->IsAvailable()) {
            std::cout << "==========[test log] FFmpeg decoder not available, skip tests" << std::endl;
        }
    }

    static void TearDownTestCase(void)
    {
        std::cout << "==========[test log] FfmpegMjpegDecoderTest TearDownTestCase" << std::endl;
        g_ffmpegDecoder.reset();
    }
};

/**
  * @tc.name: MJPEG Decoder
  * @tc.desc: Decode with valid MJPEG data using FFmpeg, expected success.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(FfmpegMjpegDecoderTest, camera_mjpeg_0001)
{
    if (!g_ffmpegDecoder->IsAvailable()) {
        GTEST_SKIP() << "FFmpeg decoder not available" << std::endl;
    }

    std::cout << "==========[test log] 1. Generate test MJPEG data." << std::endl;
    auto mjpegData = GenerateTestMJPEG(DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT);
    EXPECT_FALSE(mjpegData.empty()) << "Failed to generate test JPEG";

    std::cout << "==========[test log] 2. Allocate output buffer." << std::endl;
    std::vector<uint8_t> output(NV21BufferSize(DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT));

    std::cout << "==========[test log] 3. Execute decode." << std::endl;
    bool result = g_ffmpegDecoder->Decode(
        {mjpegData.data(), mjpegData.size(), DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT, output.data(), output.size()});

    std::cout << "==========[test log] 4. Verify decode result." << std::endl;
    EXPECT_TRUE(result);
    if (result) {
        EXPECT_FALSE(IsAllZeros(output));
    }
}

/**
  * @tc.name: MJPEG Decoder
  * @tc.desc: Decode with invalid MJPEG data using FFmpeg, expected failure.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(FfmpegMjpegDecoderTest, camera_mjpeg_0002)
{
    if (!g_ffmpegDecoder->IsAvailable()) {
        GTEST_SKIP() << "FFmpeg decoder not available" << std::endl;
    }

    std::cout << "==========[test log] 1. Prepare invalid MJPEG data." << std::endl;
    std::vector<uint8_t> invalidData = {0x00, 0x01, 0x02, 0x03};
    std::vector<uint8_t> output(NV21BufferSize(DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT));

    std::cout << "==========[test log] 2. Execute decode with invalid data." << std::endl;
    bool result = g_ffmpegDecoder->Decode(
        {invalidData.data(), invalidData.size(), DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT,
         output.data(), output.size()});

    std::cout << "==========[test log] 3. Verify decode result." << std::endl;
    EXPECT_FALSE(result);
}

/**
  * @tc.name: MJPEG Decoder
  * @tc.desc: Decode with empty data using FFmpeg, expected failure.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(FfmpegMjpegDecoderTest, camera_mjpeg_0003)
{
    if (!g_ffmpegDecoder->IsAvailable()) {
        GTEST_SKIP() << "FFmpeg decoder not available" << std::endl;
    }

    std::cout << "==========[test log] 1. Prepare empty data." << std::endl;
    std::vector<uint8_t> output(NV21BufferSize(DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT));

    std::cout << "==========[test log] 2. Execute decode with empty data." << std::endl;
    bool result = g_ffmpegDecoder->Decode(
        {nullptr, 0, DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT, output.data(), output.size()});

    std::cout << "==========[test log] 3. Verify decode result." << std::endl;
    EXPECT_FALSE(result);
}

/**
  * @tc.name: MJPEG Decoder
  * @tc.desc: Decode with null output buffer using FFmpeg, expected failure.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(FfmpegMjpegDecoderTest, camera_mjpeg_0004)
{
    if (!g_ffmpegDecoder->IsAvailable()) {
        GTEST_SKIP() << "FFmpeg decoder not available" << std::endl;
    }

    std::cout << "==========[test log] 1. Generate test MJPEG data." << std::endl;
    auto mjpegData = GenerateTestMJPEG(DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT);
    EXPECT_FALSE(mjpegData.empty()) << "Failed to generate test JPEG";

    std::cout << "==========[test log] 2. Execute decode with null output buffer." << std::endl;
    bool result = g_ffmpegDecoder->Decode({
        mjpegData.data(), mjpegData.size(),
        DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT,
        nullptr, 1000
    });

    std::cout << "==========[test log] 3. Verify decode result." << std::endl;
    EXPECT_FALSE(result);
}

/**
  * @tc.name: MJPEG Decoder
  * @tc.desc: Verify FFmpeg decoder IsAvailable returns true.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(FfmpegMjpegDecoderTest, camera_mjpeg_0005)
{
    if (!g_ffmpegDecoder->IsAvailable()) {
        GTEST_SKIP() << "FFmpeg decoder not available" << std::endl;
    }

    std::cout << "==========[test log] 1. Verify decoder is available." << std::endl;
    EXPECT_TRUE(g_ffmpegDecoder->IsAvailable()) << "Decoder should be available";

    std::cout << "==========[test log] 2. Generate test MJPEG data (QCIF resolution)." << std::endl;
    auto mjpegData = GenerateTestMJPEG(QCIF_IMAGE_WIDTH, QCIF_IMAGE_HEIGHT);
    EXPECT_FALSE(mjpegData.empty()) << "Failed to generate test JPEG";

    std::cout << "==========[test log] 3. Allocate output buffer." << std::endl;
    std::vector<uint8_t> output(NV21BufferSize(QCIF_IMAGE_WIDTH, QCIF_IMAGE_HEIGHT));

    std::cout << "==========[test log] 4. Execute decode." << std::endl;
    bool result = g_ffmpegDecoder->Decode(
        {mjpegData.data(), mjpegData.size(), QCIF_IMAGE_WIDTH, QCIF_IMAGE_HEIGHT, output.data(), output.size()});

    std::cout << "==========[test log] 5. Verify decode result." << std::endl;
    EXPECT_TRUE(result) << "Decoder should successfully decode valid MJPEG data";
    EXPECT_FALSE(IsAllZeros(output)) << "Decoded output should not be all zeros";
}

/**
  * @tc.name: MJPEG Decoder
  * @tc.desc: Verify FFmpeg decoder GetName returns correct name.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(FfmpegMjpegDecoderTest, camera_mjpeg_0006)
{
    if (!g_ffmpegDecoder->IsAvailable()) {
        GTEST_SKIP() << "FFmpeg decoder not available" << std::endl;
    }

    std::cout << "==========[test log] 1. Verify decoder name." << std::endl;
    EXPECT_STREQ(g_ffmpegDecoder->GetName(), "FFmpeg");
}

/**
  * @tc.name: MJPEG Decoder
  * @tc.desc: Decode multiple times with same decoder instance, expected success.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(FfmpegMjpegDecoderTest, camera_mjpeg_0007)
{
    if (!g_ffmpegDecoder->IsAvailable()) {
        GTEST_SKIP() << "FFmpeg decoder not available" << std::endl;
    }

    std::cout << "==========[test log] 1. Generate test MJPEG data." << std::endl;
    auto mjpegData = GenerateTestMJPEG(DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT);
    EXPECT_FALSE(mjpegData.empty()) << "Failed to generate test JPEG";

    std::cout << "==========[test log] 2. Allocate output buffer." << std::endl;
    std::vector<uint8_t> output(NV21BufferSize(DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT));

    std::cout << "==========[test log] 3. First decode." << std::endl;
    bool result1 = g_ffmpegDecoder->Decode(
        {mjpegData.data(), mjpegData.size(), DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT, output.data(), output.size()});
    EXPECT_TRUE(result1);

    std::cout << "==========[test log] 4. Second decode (reuse decoder)." << std::endl;
    bool result2 = g_ffmpegDecoder->Decode(
        {mjpegData.data(), mjpegData.size(), DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT, output.data(), output.size()});
    EXPECT_TRUE(result2);
}

// ==================== LibyuvMjpegDecoder Tests ====================

std::shared_ptr<LibyuvMjpegDecoder> g_libyuvDecoder = nullptr;

class LibyuvMjpegDecoderTest : public ::testing::Test {
protected:
    static void SetUpTestCase(void)
    {
        std::cout << "==========[test log] LibyuvMjpegDecoderTest SetUpTestCase" << std::endl;
        g_libyuvDecoder = std::make_shared<LibyuvMjpegDecoder>();
        if (!g_libyuvDecoder->IsAvailable()) {
            std::cout << "==========[test log] Libyuv decoder not available, skip tests" << std::endl;
        }
    }

    static void TearDownTestCase(void)
    {
        std::cout << "==========[test log] LibyuvMjpegDecoderTest TearDownTestCase" << std::endl;
        g_libyuvDecoder.reset();
    }
};

/**
  * @tc.name: MJPEG Decoder
  * @tc.desc: Decode with valid MJPEG data using Libyuv, expected success.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(LibyuvMjpegDecoderTest, camera_mjpeg_0008)
{
    if (!g_libyuvDecoder->IsAvailable()) {
        GTEST_SKIP() << "Libyuv decoder not available" << std::endl;
    }

    std::cout << "==========[test log] 1. Generate test MJPEG data." << std::endl;
    auto mjpegData = GenerateTestMJPEG(DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT);
    EXPECT_FALSE(mjpegData.empty()) << "Failed to generate test JPEG";

    std::cout << "==========[test log] 2. Allocate output buffer." << std::endl;
    std::vector<uint8_t> output(NV21BufferSize(DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT));

    std::cout << "==========[test log] 3. Execute decode." << std::endl;
    bool result = g_libyuvDecoder->Decode(
        {mjpegData.data(), mjpegData.size(), DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT, output.data(), output.size()});

    std::cout << "==========[test log] 4. Verify decode result." << std::endl;
    EXPECT_TRUE(result);
    if (result) {
        EXPECT_FALSE(IsAllZeros(output));
    }
}

/**
  * @tc.name: MJPEG Decoder
  * @tc.desc: Decode with invalid MJPEG data using Libyuv, expected failure.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(LibyuvMjpegDecoderTest, camera_mjpeg_0009)
{
    if (!g_libyuvDecoder->IsAvailable()) {
        GTEST_SKIP() << "Libyuv decoder not available" << std::endl;
    }

    std::cout << "==========[test log] 1. Prepare invalid MJPEG data." << std::endl;
    std::vector<uint8_t> invalidData = {0x00, 0x01, 0x02, 0x03};
    std::vector<uint8_t> output(NV21BufferSize(DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT));

    std::cout << "==========[test log] 2. Execute decode with invalid data." << std::endl;
    bool result = g_libyuvDecoder->Decode(
        {invalidData.data(), invalidData.size(), DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT,
         output.data(), output.size()});

    std::cout << "==========[test log] 3. Verify decode result." << std::endl;
    EXPECT_FALSE(result);
}

/**
  * @tc.name: MJPEG Decoder
  * @tc.desc: Verify Libyuv decoder GetName returns correct name.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(LibyuvMjpegDecoderTest, camera_mjpeg_0010)
{
    if (!g_libyuvDecoder->IsAvailable()) {
        GTEST_SKIP() << "Libyuv decoder not available" << std::endl;
    }

    std::cout << "==========[test log] 1. Verify decoder name." << std::endl;
    EXPECT_STREQ(g_libyuvDecoder->GetName(), "Libyuv");
}

// ==================== MjpegDecoderFactory Tests ====================

class MjpegDecoderFactoryTest : public ::testing::Test {};

/**
  * @tc.name: MJPEG Decoder
  * @tc.desc: Factory Create returns valid decoder.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(MjpegDecoderFactoryTest, camera_mjpeg_0011)
{
    std::cout << "==========[test log] 1. Create decoder via factory." << std::endl;
    auto decoder = MjpegDecoderFactory::Create();

    std::cout << "==========[test log] 2. Verify decoder is not null." << std::endl;
    EXPECT_NE(decoder, nullptr);

    std::cout << "==========[test log] 3. Verify decoder is available." << std::endl;
    EXPECT_TRUE(decoder->IsAvailable());
}

/**
  * @tc.name: MJPEG Decoder
  * @tc.desc: Factory GetAvailableDecoderName returns valid name.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(MjpegDecoderFactoryTest, camera_mjpeg_0012)
{
    std::cout << "==========[test log] 1. Get available decoder name." << std::endl;
    const char *name = MjpegDecoderFactory::GetAvailableDecoderName();

    std::cout << "==========[test log] 2. Verify decoder name is valid." << std::endl;
    EXPECT_NE(name, nullptr);
    EXPECT_STRNE(name, "None");

    bool validName = (strcmp(name, "Libyuv") == 0 || strcmp(name, "FFmpeg") == 0);
    EXPECT_TRUE(validName) << "Unexpected decoder name: " << name;
}

/**
  * @tc.name: MJPEG Decoder
  * @tc.desc: Factory created decoder can decode multiple times.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(MjpegDecoderFactoryTest, camera_mjpeg_0013)
{
    std::cout << "==========[test log] 1. Create decoder via factory." << std::endl;
    auto decoder = MjpegDecoderFactory::Create();
    ASSERT_NE(decoder, nullptr);

    std::cout << "==========[test log] 2. Generate test MJPEG data." << std::endl;
    auto mjpegData = GenerateTestMJPEG(DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT);
    if (mjpegData.empty()) {
        GTEST_SKIP() << "Test file not available" << std::endl;
    }

    std::cout << "==========[test log] 3. Allocate output buffer." << std::endl;
    std::vector<uint8_t> output(NV21BufferSize(DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT));

    std::cout << "==========[test log] 4. First decode." << std::endl;
    bool result1 = decoder->Decode(
        {mjpegData.data(), mjpegData.size(), DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT, output.data(), output.size()});
    EXPECT_TRUE(result1);

    std::cout << "==========[test log] 5. Second decode (reuse decoder)." << std::endl;
    bool result2 = decoder->Decode(
        {mjpegData.data(), mjpegData.size(), DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT, output.data(), output.size()});
    EXPECT_TRUE(result2);
}

// ==================== Performance Benchmark Tests ====================

std::shared_ptr<FfmpegMjpegDecoder> g_benchmarkDecoder = nullptr;
std::vector<uint8_t> g_benchmarkMjpegData;
std::vector<uint8_t> g_benchmarkOutput;

class MjpegDecoderBenchmarkTest : public ::testing::Test {
protected:
    static void SetUpTestCase(void)
    {
        std::cout << "==========[test log] MjpegDecoderBenchmarkTest SetUpTestCase" << std::endl;
        g_benchmarkDecoder = std::make_shared<FfmpegMjpegDecoder>();
        if (!g_benchmarkDecoder->IsAvailable()) {
            std::cout << "==========[test log] FFmpeg decoder not available for benchmarks" << std::endl;
            return;
        }
        g_benchmarkMjpegData = GenerateTestMJPEG(DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT);
        if (g_benchmarkMjpegData.empty()) {
            std::cout << "==========[test log] Test file not available, skipping benchmark" << std::endl;
            return;
        }
        g_benchmarkOutput.resize(NV21BufferSize(DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT));
    }

    static void TearDownTestCase(void)
    {
        std::cout << "==========[test log] MjpegDecoderBenchmarkTest TearDownTestCase" << std::endl;
        g_benchmarkDecoder.reset();
    }
};

/**
  * @tc.name: MJPEG Decoder
  * @tc.desc: Libyuv decode performance benchmark.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(MjpegDecoderBenchmarkTest, camera_mjpeg_0014)
{
    auto decoder = std::make_shared<LibyuvMjpegDecoder>();
    if (!decoder->IsAvailable()) {
        GTEST_SKIP() << "Libyuv decoder not available" << std::endl;
    }

    std::cout << "==========[test log] 1. Start performance test." << std::endl;
    const int iterations = 10;
    auto start = std::chrono::high_resolution_clock::now();

    std::cout << "==========[test log] 2. Execute decode " << iterations << " times." << std::endl;
    for (int i = 0; i < iterations; i++) {
        bool result = decoder->Decode(
            {g_benchmarkMjpegData.data(), g_benchmarkMjpegData.size(), DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT,
             g_benchmarkOutput.data(), g_benchmarkOutput.size()});
        EXPECT_TRUE(result);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout << "==========[test log] Libyuv decode " << iterations << " frames in " << duration.count() << " ms ("
              << duration.count() / iterations << " ms/frame)" << std::endl;

    EXPECT_LT(duration.count(), MAX_DECODE_TIME_MS_PERF);
}

// ==================== Cross-Decoder Consistency Tests ====================

class MjpegDecodeResultTest : public ::testing::Test {};

/**
  * @tc.name: MJPEG Decoder
  * @tc.desc: Verify FFmpeg and Libyuv decoder output consistency.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(MjpegDecodeResultTest, camera_mjpeg_0015)
{
    auto ffmpegDecoder = std::make_shared<FfmpegMjpegDecoder>();
    auto libyuvDecoder = std::make_shared<LibyuvMjpegDecoder>();

    bool ffmpegAvailable = ffmpegDecoder->IsAvailable();
    bool libyuvAvailable = libyuvDecoder->IsAvailable();
    if (!ffmpegAvailable || !libyuvAvailable) {
        GTEST_SKIP() << "Both decoders must be available for consistency test" << std::endl;
    }

    std::cout << "==========[test log] 1. Generate test MJPEG data." << std::endl;
    auto mjpegData = GenerateTestMJPEG(DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT);
    if (mjpegData.empty()) {
        GTEST_SKIP() << "Test file not available" << std::endl;
    }

    std::vector<uint8_t> outputFfmpeg(NV21BufferSize(DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT));
    std::vector<uint8_t> outputLibyuv(NV21BufferSize(DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT));

    std::cout << "==========[test log] 2. FFmpeg decode." << std::endl;
    bool result1 = ffmpegDecoder->Decode(
        {mjpegData.data(), mjpegData.size(), DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT,
         outputFfmpeg.data(), outputFfmpeg.size()});
    EXPECT_TRUE(result1);

    std::cout << "==========[test log] 3. Libyuv decode." << std::endl;
    bool result2 = libyuvDecoder->Decode(
        {mjpegData.data(), mjpegData.size(), DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT,
         outputLibyuv.data(), outputLibyuv.size()});
    EXPECT_TRUE(result2);

    if (result1 && result2) {
        std::cout << "==========[test log] 4. Compare decoder outputs." << std::endl;
        bool consistent = CompareYUVData(outputFfmpeg.data(), outputLibyuv.data(), outputFfmpeg.size(), 5, 1);
        EXPECT_TRUE(consistent) << "Decoder outputs differ significantly";
    }
}

// ==================== Edge Cases ====================

std::shared_ptr<IMjpegDecoder> g_edgeCaseDecoder = nullptr;

class MjpegDecoderEdgeCaseTest : public ::testing::Test {
protected:
    static void SetUpTestCase(void)
    {
        std::cout << "==========[test log] MjpegDecoderEdgeCaseTest SetUpTestCase" << std::endl;
        g_edgeCaseDecoder = MjpegDecoderFactory::Create();
    }

    static void TearDownTestCase(void)
    {
        std::cout << "==========[test log] MjpegDecoderEdgeCaseTest TearDownTestCase" << std::endl;
        g_edgeCaseDecoder.reset();
    }
};

/**
  * @tc.name: MJPEG Decoder
  * @tc.desc: Decode with extreme small resolution (QCIF), expected success.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(MjpegDecoderEdgeCaseTest, camera_mjpeg_0016)
{
    if (!g_edgeCaseDecoder->IsAvailable()) {
        GTEST_SKIP() << "No decoder available" << std::endl;
    }

    std::cout << "==========[test log] 1. Generate test MJPEG data (QCIF resolution)." << std::endl;
    auto mjpegData = GenerateTestMJPEG(QCIF_IMAGE_WIDTH, QCIF_IMAGE_HEIGHT);
    if (mjpegData.empty()) {
        GTEST_SKIP() << "QCIF test file not available" << std::endl;
    }

    std::cout << "==========[test log] 2. Allocate output buffer." << std::endl;
    std::vector<uint8_t> output(NV21BufferSize(QCIF_IMAGE_WIDTH, QCIF_IMAGE_HEIGHT));

    std::cout << "==========[test log] 3. Execute decode." << std::endl;
    bool result = g_edgeCaseDecoder->Decode(
        {mjpegData.data(), mjpegData.size(), QCIF_IMAGE_WIDTH, QCIF_IMAGE_HEIGHT, output.data(), output.size()});

    std::cout << "==========[test log] 4. Verify decode result." << std::endl;
    EXPECT_TRUE(result);
}

/**
  * @tc.name: MJPEG Decoder
  * @tc.desc: Decode with large resolution (720P), expected success.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(MjpegDecoderEdgeCaseTest, camera_mjpeg_0017)
{
    if (!g_edgeCaseDecoder->IsAvailable()) {
        GTEST_SKIP() << "No decoder available" << std::endl;
    }

    std::cout << "==========[test log] 1. Generate test MJPEG data (720P resolution)." << std::endl;
    auto mjpegData = GenerateTestMJPEG(HD720P_IMAGE_WIDTH, HD720P_IMAGE_HEIGHT);
    if (mjpegData.empty()) {
        GTEST_SKIP() << "720P test file not available" << std::endl;
    }

    std::cout << "==========[test log] 2. Allocate output buffer." << std::endl;
    std::vector<uint8_t> output(NV21BufferSize(HD720P_IMAGE_WIDTH, HD720P_IMAGE_HEIGHT));

    std::cout << "==========[test log] 3. Execute decode." << std::endl;
    bool result = g_edgeCaseDecoder->Decode(
        {mjpegData.data(), mjpegData.size(), HD720P_IMAGE_WIDTH, HD720P_IMAGE_HEIGHT, output.data(), output.size()});

    std::cout << "==========[test log] 4. Verify decode result." << std::endl;
    EXPECT_TRUE(result);
}

// ==================== Multi-thread Safety Tests ====================

std::shared_ptr<IMjpegDecoder> g_threadSafetyDecoder = nullptr;

class MjpegDecoderThreadSafetyTest : public ::testing::Test {
protected:
    static void SetUpTestCase(void)
    {
        std::cout << "==========[test log] MjpegDecoderThreadSafetyTest SetUpTestCase" << std::endl;
    }

    static void TearDownTestCase(void)
    {
        std::cout << "==========[test log] MjpegDecoderThreadSafetyTest TearDownTestCase" << std::endl;
    }
};

/**
  * @tc.name: MJPEG Decoder
  * @tc.desc: Verify decoder thread safety with concurrent decode requests.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(MjpegDecoderThreadSafetyTest, camera_mjpeg_0018)
{
    std::cout << "==========[test log] 1. Create multiple decoder instances." << std::endl;
    const int numThreads = 4;
    std::vector<std::shared_ptr<IMjpegDecoder>> decoders;

    for (int i = 0; i < numThreads; i++) {
        decoders.push_back(MjpegDecoderFactory::Create());
    }

    std::cout << "==========[test log] 2. Generate test MJPEG data." << std::endl;
    auto mjpegData = GenerateTestMJPEG(DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT);
    if (mjpegData.empty()) {
        GTEST_SKIP() << "Test file not available" << std::endl;
    }

    std::cout << "==========[test log] 3. Execute concurrent decode." << std::endl;
    std::vector<std::future<bool>> futures;
    for (int i = 0; i < numThreads; i++) {
        futures.push_back(std::async(std::launch::async, [decoder = decoders[i], &mjpegData]() {
            std::vector<uint8_t> output(NV21BufferSize(DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT));
            return decoder->Decode(
                {mjpegData.data(), mjpegData.size(), DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT,
                 output.data(), output.size()});
        }));
    }

    std::cout << "==========[test log] 4. Verify all decode results." << std::endl;
    for (int i = 0; i < numThreads; i++) {
        EXPECT_TRUE(futures[i].get()) << "Thread " << i << " decode failed";
    }
}
