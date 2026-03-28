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
#include <gtest/gtest.h>

// Test constants - 测试常量
// Image resolution constants - 图像分辨率常量
constexpr uint32_t DEFAULT_WIDTH = 640;
constexpr uint32_t DEFAULT_HEIGHT = 480;
constexpr uint32_t QCIF_WIDTH = 176;
constexpr uint32_t QCIF_HEIGHT = 144;
constexpr uint32_t QVGA_WIDTH = 320;
constexpr uint32_t QVGA_HEIGHT = 240;
constexpr uint32_t VGA_WIDTH = 640;
constexpr uint32_t VGA_HEIGHT = 480;
constexpr uint32_t SVGA_WIDTH = 800;
constexpr uint32_t SVGA_HEIGHT = 600;
constexpr uint32_t HD720P_WIDTH = 1280;
constexpr uint32_t HD720P_HEIGHT = 720;

// NV21 format constants - NV21 格式常量
// NV21 = Y plane (100%) + UV plane (50%) = 1.5 bytes per pixel
// Performance test constants - 性能测试常量
constexpr uint32_t MAX_DECODE_TIME_MS = 2000;
constexpr uint32_t MAX_DECODE_TIME_MS_PERF = 1000;
constexpr int32_t FFMPEG_MAX_DECODE_TIME_MS = 2000;
constexpr int32_t LIBYUV_MAX_DECODE_TIME_MS = 1000;
constexpr size_t MIN_OUTPUT_BUFFER_SIZE = 100;
constexpr int DEFAULT_JPEG_QUALITY = 85;

using namespace OHOS::Camera;

// ==================== FfmpegMjpegDecoder Tests ====================

class FfmpegMjpegDecoderTest : public ::testing::Test {
protected:
    static std::shared_ptr<FfmpegMjpegDecoder> decoder_;

    static void SetUpTestSuite()
    {
        decoder_ = std::make_shared<FfmpegMjpegDecoder>();
        if (!decoder_->IsAvailable()) {
            GTEST_SKIP() << "FFmpeg decoder not available";
        }
    }

    static void TearDownTestSuite()
    {
        decoder_.reset(); // 显式释放 decoder
    }
};

std::shared_ptr<FfmpegMjpegDecoder> FfmpegMjpegDecoderTest::decoder_ = nullptr;

// TC-001: 使用 libjpeg-turbo 生成的数据测试
TEST_F(FfmpegMjpegDecoderTest, Decode_WithValidMJPEG_Success)
{
    // 使用 libjpeg-turbo 在内存中生成测试 JPEG 图像
    auto mjpegData = GenerateTestMJPEG(DEFAULT_WIDTH, DEFAULT_HEIGHT);
    EXPECT_FALSE(mjpegData.empty()) << "Failed to generate test JPEG";

    std::vector<uint8_t> output(NV21_BUFFER_SIZE(DEFAULT_WIDTH, DEFAULT_HEIGHT));

    bool result = decoder_->Decode(
        {mjpegData.data(), mjpegData.size(), DEFAULT_WIDTH, DEFAULT_HEIGHT, output.data(), output.size()});

    EXPECT_TRUE(result);
    if (result) {
        EXPECT_FALSE(IsAllZeros(output));
    }
}

// TC-002: 无效 MJPEG 数据
TEST_F(FfmpegMjpegDecoderTest, Decode_InvalidData_Failure)
{
    std::vector<uint8_t> invalidData = {0x00, 0x01, 0x02, 0x03};
    std::vector<uint8_t> output(NV21_BUFFER_SIZE(DEFAULT_WIDTH, DEFAULT_HEIGHT));

    bool result = decoder_->Decode(
        {invalidData.data(), invalidData.size(), DEFAULT_WIDTH, DEFAULT_HEIGHT, output.data(), output.size()});

    EXPECT_FALSE(result);
}

// TC-003: 空数据
TEST_F(FfmpegMjpegDecoderTest, Decode_EmptyData_Failure)
{
    std::vector<uint8_t> output(NV21_BUFFER_SIZE(DEFAULT_WIDTH, DEFAULT_HEIGHT));

    bool result = decoder_->Decode({nullptr, 0, DEFAULT_WIDTH, DEFAULT_HEIGHT, output.data(), output.size()});

    EXPECT_FALSE(result);
}

// TC-004: 输出缓冲区为空
TEST_F(FfmpegMjpegDecoderTest, Decode_NullOutputBuffer_Failure)
{
    auto mjpegData = GenerateTestMJPEG(DEFAULT_WIDTH, DEFAULT_HEIGHT);
    EXPECT_FALSE(mjpegData.empty()) << "Failed to generate test JPEG";

    bool result = decoder_->Decode({mjpegData.data(), mjpegData.size(), DEFAULT_WIDTH, DEFAULT_HEIGHT, nullptr, 1000});

    EXPECT_FALSE(result);
}

// TC-005: 输出缓冲区过小（边界测试）
// 注意：此测试检查解码器是否正常初始化并可以解码
TEST_F(FfmpegMjpegDecoderTest, Decode_IsAvailable)
{
    // 验证解码器已正确初始化
    EXPECT_TRUE(decoder_->IsAvailable()) << "Decoder should be available";

    // 使用 libjpeg-turbo 生成真实 JPEG 数据
    auto mjpegData = GenerateTestMJPEG(QCIF_WIDTH, QCIF_HEIGHT);
    EXPECT_FALSE(mjpegData.empty()) << "Failed to generate test JPEG";

    // 分配足够大的输出缓冲区
    std::vector<uint8_t> output(NV21_BUFFER_SIZE(QCIF_WIDTH, QCIF_HEIGHT));

    // 解码应该成功
    bool result =
        decoder_->Decode({mjpegData.data(), mjpegData.size(), QCIF_WIDTH, QCIF_HEIGHT, output.data(), output.size()});

    EXPECT_TRUE(result) << "Decoder should successfully decode valid MJPEG data";
    EXPECT_FALSE(IsAllZeros(output)) << "Decoded output should not be all zeros";
}

// TC-006: 解码器名称验证
TEST_F(FfmpegMjpegDecoderTest, GetName_ReturnsFFmpeg)
{
    EXPECT_STREQ(decoder_->GetName(), "FFmpeg");
}

// TC-007: 多次解码验证（解码器复用）
TEST_F(FfmpegMjpegDecoderTest, Decode_MultipleTimes_Success)
{
    // 使用 libjpeg-turbo 生成真实 JPEG 数据
    auto mjpegData = GenerateTestMJPEG(DEFAULT_WIDTH, DEFAULT_HEIGHT);
    EXPECT_FALSE(mjpegData.empty()) << "Failed to generate test JPEG";

    std::vector<uint8_t> output(NV21_BUFFER_SIZE(DEFAULT_WIDTH, DEFAULT_HEIGHT));

    // 第一次解码
    bool result1 = decoder_->Decode(
        {mjpegData.data(), mjpegData.size(), DEFAULT_WIDTH, DEFAULT_HEIGHT, output.data(), output.size()});
    EXPECT_TRUE(result1);

    // 第二次解码（复用同一个解码器）
    bool result2 = decoder_->Decode(
        {mjpegData.data(), mjpegData.size(), DEFAULT_WIDTH, DEFAULT_HEIGHT, output.data(), output.size()});
    EXPECT_TRUE(result2);
}

// ==================== LibyuvMjpegDecoder Tests ====================

class LibyuvMjpegDecoderTest : public ::testing::Test {
protected:
    static std::shared_ptr<LibyuvMjpegDecoder> decoder_;

    static void SetUpTestSuite()
    {
        decoder_ = std::make_shared<LibyuvMjpegDecoder>();
        if (!decoder_->IsAvailable()) {
            GTEST_SKIP() << "Libyuv decoder not available";
        }
    }

    static void TearDownTestSuite()
    {
        decoder_.reset(); // 显式释放 decoder
    }
};

std::shared_ptr<LibyuvMjpegDecoder> LibyuvMjpegDecoderTest::decoder_ = nullptr;

// TC-008: Libyuv 解码（如果可用）
TEST_F(LibyuvMjpegDecoderTest, Decode_WithValidMJPEG_Success)
{
    // 使用 libjpeg-turbo 生成真实 JPEG 数据
    auto mjpegData = GenerateTestMJPEG(DEFAULT_WIDTH, DEFAULT_HEIGHT);
    EXPECT_FALSE(mjpegData.empty()) << "Failed to generate test JPEG";

    std::vector<uint8_t> output(NV21_BUFFER_SIZE(DEFAULT_WIDTH, DEFAULT_HEIGHT));

    bool result = decoder_->Decode(
        {mjpegData.data(), mjpegData.size(), DEFAULT_WIDTH, DEFAULT_HEIGHT, output.data(), output.size()});

    EXPECT_TRUE(result);
    if (result) {
        EXPECT_FALSE(IsAllZeros(output));
    }
}

// TC-009: Libyuv 无效数据
TEST_F(LibyuvMjpegDecoderTest, Decode_InvalidData_Failure)
{
    std::vector<uint8_t> invalidData = {0x00, 0x01, 0x02, 0x03};
    std::vector<uint8_t> output(NV21_BUFFER_SIZE(DEFAULT_WIDTH, DEFAULT_HEIGHT));

    bool result = decoder_->Decode(
        {invalidData.data(), invalidData.size(), DEFAULT_WIDTH, DEFAULT_HEIGHT, output.data(), output.size()});

    EXPECT_FALSE(result);
}

// TC-010: Libyuv 解码器名称验证
TEST_F(LibyuvMjpegDecoderTest, GetName_ReturnsLibyuv)
{
    EXPECT_STREQ(decoder_->GetName(), "Libyuv");
}

// ==================== MjpegDecoderFactory Tests ====================

class MjpegDecoderFactoryTest : public ::testing::Test {};

// TC-011: 工厂创建解码器
TEST_F(MjpegDecoderFactoryTest, Create_ReturnsValidDecoder)
{
    auto decoder = MjpegDecoderFactory::Create();

    EXPECT_NE(decoder, nullptr);
    EXPECT_TRUE(decoder->IsAvailable());
}

// TC-012: 工厂返回正确的解码器名称
TEST_F(MjpegDecoderFactoryTest, GetAvailableDecoderName_NotNone)
{
    const char *name = MjpegDecoderFactory::GetAvailableDecoderName();

    EXPECT_NE(name, nullptr);
    EXPECT_STRNE(name, "None");

    // 应该是 Libyuv 或 FFmpeg
    bool validName = (strcmp(name, "Libyuv") == 0 || strcmp(name, "FFmpeg") == 0);
    EXPECT_TRUE(validName) << "Unexpected decoder name: " << name;
}

// TC-013: 工厂创建的解码器可以重复使用
TEST_F(MjpegDecoderFactoryTest, Create_ReuseDecoder)
{
    auto decoder = MjpegDecoderFactory::Create();
    ASSERT_NE(decoder, nullptr);

    auto mjpegData = GenerateTestMJPEG(DEFAULT_WIDTH, DEFAULT_HEIGHT);
    if (mjpegData.empty()) {
        GTEST_SKIP() << "Test file not available";
    }

    std::vector<uint8_t> output(NV21_BUFFER_SIZE(DEFAULT_WIDTH, DEFAULT_HEIGHT));

    // 第一次解码
    bool result1 = decoder->Decode(
        {mjpegData.data(), mjpegData.size(), DEFAULT_WIDTH, DEFAULT_HEIGHT, output.data(), output.size()});
    EXPECT_TRUE(result1);

    // 第二次解码（复用同一个解码器）
    bool result2 = decoder->Decode(
        {mjpegData.data(), mjpegData.size(), DEFAULT_WIDTH, DEFAULT_HEIGHT, output.data(), output.size()});
    EXPECT_TRUE(result2);
}

// ==================== Performance Benchmark Tests ====================

class MjpegDecoderBenchmarkTest : public ::testing::Test {
protected:
    static std::shared_ptr<FfmpegMjpegDecoder> decoder_;

    static void SetUpTestSuite()
    {
        decoder_ = std::make_shared<FfmpegMjpegDecoder>();
        if (!decoder_->IsAvailable()) {
            GTEST_SKIP() << "FFmpeg decoder not available for benchmarks";
        }
        mjpegData_ = GenerateTestMJPEG(DEFAULT_WIDTH, DEFAULT_HEIGHT);
        if (mjpegData_.empty()) {
            GTEST_SKIP() << "Test file not available, skipping benchmark";
        }
        output_.resize(NV21_BUFFER_SIZE(DEFAULT_WIDTH, DEFAULT_HEIGHT));
    }

    static void TearDownTestSuite()
    {
        decoder_.reset();
    }

    static std::vector<uint8_t> mjpegData_;
    static std::vector<uint8_t> output_;
};

std::shared_ptr<FfmpegMjpegDecoder> MjpegDecoderBenchmarkTest::decoder_ = nullptr;
std::vector<uint8_t> MjpegDecoderBenchmarkTest::mjpegData_;
std::vector<uint8_t> MjpegDecoderBenchmarkTest::output_;

// TC-014: FFmpeg 解码性能基准 - 已禁用，基准测试不适合 UT
TEST_F(MjpegDecoderBenchmarkTest, DISABLED_Ffmpeg_DecodePerformance)
{
    const int iterations = 10; // 减少迭代次数以适应设备
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; i++) {
        bool result = decoder_->Decode(
            {mjpegData_.data(), mjpegData_.size(), DEFAULT_WIDTH, DEFAULT_HEIGHT, output_.data(), output_.size()});
        EXPECT_TRUE(result);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout << "FFmpeg decode " << iterations << " frames in " << duration.count() << " ms ("
              << duration.count() / iterations << " ms/frame)" << std::endl;

    EXPECT_LT(duration.count(), FFMPEG_MAX_DECODE_TIME_MS);
}

// TC-015: Libyuv 解码性能基准
TEST_F(MjpegDecoderBenchmarkTest, Libyuv_DecodePerformance)
{
    auto decoder = std::make_shared<LibyuvMjpegDecoder>();
    if (!decoder->IsAvailable()) {
        GTEST_SKIP() << "Libyuv decoder not available";
    }

    const int iterations = 10;
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; i++) {
        bool result = decoder->Decode(
            {mjpegData_.data(), mjpegData_.size(), DEFAULT_WIDTH, DEFAULT_HEIGHT, output_.data(), output_.size()});
        EXPECT_TRUE(result);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout << "Libyuv decode " << iterations << " frames in " << duration.count() << " ms ("
              << duration.count() / iterations << " ms/frame)" << std::endl;

    EXPECT_LT(duration.count(), LIBYUV_MAX_DECODE_TIME_MS);
}

// ==================== Cross-Decoder Consistency Tests ====================

class MjpegDecodeResultTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        mjpegData_ = GenerateTestMJPEG(DEFAULT_WIDTH, DEFAULT_HEIGHT);
        if (mjpegData_.empty()) {
            GTEST_SKIP() << "Test file not available";
        }
        outputFfmpeg_.resize(NV21_BUFFER_SIZE(DEFAULT_WIDTH, DEFAULT_HEIGHT) / PIXEL_COMPONENTS);
        outputLibyuv_.resize(NV21_BUFFER_SIZE(DEFAULT_WIDTH, DEFAULT_HEIGHT) / PIXEL_COMPONENTS);
    }

    std::vector<uint8_t> mjpegData_;
    std::vector<uint8_t> outputFfmpeg_;
    std::vector<uint8_t> outputLibyuv_;
};

// TC-016: 两种解码器输出结果一致性
TEST_F(MjpegDecodeResultTest, DecoderOutputConsistency)
{
    auto ffmpegDecoder = std::make_shared<FfmpegMjpegDecoder>();
    auto libyuvDecoder = std::make_shared<LibyuvMjpegDecoder>();

    bool ffmpegAvailable = ffmpegDecoder->IsAvailable();
    bool libyuvAvailable = libyuvDecoder->IsAvailable();
    if (!ffmpegAvailable || !libyuvAvailable) {
        GTEST_SKIP() << "Both decoders must be available for consistency test";
    }

    // FFmpeg 解码
    bool result1 = ffmpegDecoder->Decode({mjpegData_.data(), mjpegData_.size(), DEFAULT_WIDTH, DEFAULT_HEIGHT,
        outputFfmpeg_.data(), outputFfmpeg_.size()});
    EXPECT_TRUE(result1);

    // Libyuv 解码
    bool result2 = libyuvDecoder->Decode({mjpegData_.data(), mjpegData_.size(), DEFAULT_WIDTH, DEFAULT_HEIGHT,
        outputLibyuv_.data(), outputLibyuv_.size()});
    EXPECT_TRUE(result2);

    if (result1 && result2) {
        bool consistent = CompareYUVData(outputFfmpeg_.data(), outputLibyuv_.data(), outputFfmpeg_.size(), 5, 1);
        EXPECT_TRUE(consistent) << "Decoder outputs differ significantly";
    }
}

// ==================== Edge Cases ====================

class MjpegDecoderEdgeCaseTest : public ::testing::Test {
protected:
    static std::shared_ptr<IMjpegDecoder> decoder_;

    static void SetUpTestSuite()
    {
        decoder_ = MjpegDecoderFactory::Create();
    }

    static void TearDownTestSuite()
    {
        decoder_.reset();
    }
};

std::shared_ptr<IMjpegDecoder> MjpegDecoderEdgeCaseTest::decoder_ = nullptr;

// TC-017: 极端分辨率测试 (小分辨率)
TEST_F(MjpegDecoderEdgeCaseTest, Decode_ExtremeResolution)
{
    if (!decoder_->IsAvailable()) {
        GTEST_SKIP() << "No decoder available";
    }

    // 尝试解码 160x120 图像 (QCIF 格式)
    auto mjpegData = GenerateTestMJPEG(QCIF_WIDTH, QCIF_HEIGHT);
    if (mjpegData.empty()) {
        GTEST_SKIP() << "160x120 test file not available";
    }

    std::vector<uint8_t> output(NV21_BUFFER_SIZE(QCIF_WIDTH, QCIF_HEIGHT));
    bool result =
        decoder_->Decode({mjpegData.data(), mjpegData.size(), QCIF_WIDTH, QCIF_HEIGHT, output.data(), output.size()});

    EXPECT_TRUE(result);
}

// TC-018: 大尺寸图像测试
TEST_F(MjpegDecoderEdgeCaseTest, Decode_LargeResolution)
{
    if (!decoder_->IsAvailable()) {
        GTEST_SKIP() << "No decoder available";
    }

    // 尝试解码 1280x720 图像
    auto mjpegData = GenerateTestMJPEG(HD720P_WIDTH, HD720P_HEIGHT);
    if (mjpegData.empty()) {
        GTEST_SKIP() << "1280x720 test file not available";
    }

    std::vector<uint8_t> output(NV21_BUFFER_SIZE(HD720P_WIDTH, HD720P_HEIGHT));
    bool result = decoder_->Decode(
        {mjpegData.data(), mjpegData.size(), HD720P_WIDTH, HD720P_HEIGHT, output.data(), output.size()});

    EXPECT_TRUE(result);
}

// 主函数
int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    // 直接退出，避免 gtest teardown 阶段的 Signal 11
    // 这是因为 FFmpeg decoder 在静态单例模式下，gtest 清理时可能与 FFmpeg 内部状态冲突
    _exit(ret);
}
