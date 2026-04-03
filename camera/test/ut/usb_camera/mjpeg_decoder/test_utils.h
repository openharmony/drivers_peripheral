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

#ifndef __MJPEG_DECODER_TEST_UTILS_H__
#define __MJPEG_DECODER_TEST_UTILS_H__

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace OHOS::Camera {

// NV21 格式常量 - 统一定义在 namespace 内
constexpr uint32_t NV21_SCALE_FACTOR = 3;
constexpr uint32_t NV21_DIVISOR = 2;
constexpr int NV21_BITS_PER_PIXEL = 12;
// NV21: Y(1) + UV(0.5) = 1.5 bytes per pixel
constexpr int NV21_BYTES_PER_PIXEL_NUMERATOR = 3;
constexpr int NV21_BYTES_PER_PIXEL_DENOMINATOR = 2;
constexpr int PIXEL_COMPONENTS = 3;

// 图像格式常量
constexpr uint32_t DEFAULT_IMAGE_WIDTH = 640;
constexpr uint32_t DEFAULT_IMAGE_HEIGHT = 480;
constexpr uint32_t QCIF_IMAGE_WIDTH = 176;
constexpr uint32_t QCIF_IMAGE_HEIGHT = 144;
constexpr uint32_t QVGA_IMAGE_WIDTH = 320;
constexpr uint32_t QVGA_IMAGE_HEIGHT = 240;
constexpr uint32_t SVGA_IMAGE_WIDTH = 800;
constexpr uint32_t SVGA_IMAGE_HEIGHT = 600;
constexpr uint32_t HD720P_IMAGE_WIDTH = 1280;
constexpr uint32_t HD720P_IMAGE_HEIGHT = 720;

constexpr int DEFAULT_JPEG_QUALITY = 85;
constexpr int MIN_JPEG_QUALITY = 1;
constexpr int MAX_JPEG_QUALITY = 100;
constexpr uint8_t PIXEL_MAX_VALUE = 255;
constexpr uint8_t YUV_DEFAULT_VALUE = 128; // UV 平面中性值

constexpr int PERCENT_FACTOR = 100;

// 计算 NV21 缓冲区大小
constexpr size_t NV21BufferSize(int32_t w, int32_t h)
{
    return static_cast<size_t>(w) * h * NV21_BYTES_PER_PIXEL_NUMERATOR / NV21_BYTES_PER_PIXEL_DENOMINATOR;
}

/**
 * @brief 从文件加载二进制数据（可选，用于外部测试资源）
 * @param filePath 文件路径
 * @return std::vector<uint8_t> 文件内容
 */
inline std::vector<uint8_t> LoadFile(const std::string &filePath)
{
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return {};
    }
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> data(size);
    file.read(reinterpret_cast<char *>(data.data()), size);
    return data;
}

/**
 * @brief 检查数据是否全为0
 * @param data 数据指针
 * @param size 数据大小
 * @return true 全为0
 * @return false 不全为0
 */
inline bool IsAllZeros(const uint8_t *data, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        if (data[i] != 0) {
            return false;
        }
    }
    return true;
}

/**
 * @brief 检查数据是否全为0（vector版本）
 * @param data 数据vector
 * @return true 全为0
 * @return false 不全为0
 */
inline bool IsAllZeros(const std::vector<uint8_t> &data)
{
    return IsAllZeros(data.data(), data.size());
}

/**
 * @brief 计算NV21格式的缓冲区大小
 * @param width 宽度
 * @param height 高度
 * @return size_t 缓冲区大小
 */
inline size_t CalculateNV21Size(int width, int height)
{
    return static_cast<size_t>(width * height * NV21_SCALE_FACTOR / NV21_DIVISOR);
}

/**
 * @brief 比较两个YUV数据是否一致（允许一定误差）
 * @param data1 数据1
 * @param data2 数据2
 * @param size 数据大小
 * @param threshold 允许的像素差异阈值
 * @param maxDiffPercent 允许的最大差异百分比
 * @return true 一致
 * @return false 不一致
 */
inline bool CompareYUVData(const uint8_t* data1, const uint8_t* data2, size_t size,
    int threshold, int maxDiffPercent)
{
    int diffCount = 0;
    for (size_t i = 0; i < size; i++) {
        int diff = std::abs(static_cast<int>(data1[i]) - static_cast<int>(data2[i]));
        if (diff > threshold) { diffCount++; }
    }
    int diffPercent = diffCount * PERCENT_FACTOR / static_cast<int>(size);
    return diffPercent < maxDiffPercent;
}

/**
 * @brief 使用 turbojpeg 生成 JPEG 图像
 * @param width 图像宽度
 * @param height 图像高度
 * @param quality JPEG 质量 (MIN_JPEG_QUALITY-MAX_JPEG_QUALITY)
 * @return std::vector<uint8_t> JPEG数据
 */
std::vector<uint8_t> GenerateJPEGWithTurboJpeg(int width, int height, int quality = DEFAULT_JPEG_QUALITY);
inline std::vector<uint8_t> GetTestJpeg(int width, int height)
{
    return GenerateJPEGWithTurboJpeg(width, height, DEFAULT_JPEG_QUALITY);
}
inline std::vector<uint8_t> GetTestJpeg640x480()
{
    return GenerateJPEGWithTurboJpeg(DEFAULT_IMAGE_WIDTH, DEFAULT_IMAGE_HEIGHT, DEFAULT_JPEG_QUALITY);
}
inline std::vector<uint8_t> GetTestJpeg160x120()
{
    return GenerateJPEGWithTurboJpeg(QCIF_IMAGE_WIDTH, QCIF_IMAGE_HEIGHT, DEFAULT_JPEG_QUALITY);
}
inline std::vector<uint8_t> GetTestJpeg1280x720()
{
    return GenerateJPEGWithTurboJpeg(HD720P_IMAGE_WIDTH, HD720P_IMAGE_HEIGHT, DEFAULT_JPEG_QUALITY);
}

/**
 * @brief 使用 turbojpeg 生成 MJPEG 测试图像
 * @param width 图像宽度
 * @param height 图像高度
 * @return std::vector<uint8_t> JPEG/MJPEG数据
 */
inline std::vector<uint8_t> GenerateTestMJPEG(int width = DEFAULT_IMAGE_WIDTH, int height = DEFAULT_IMAGE_HEIGHT)
{
    return GenerateJPEGWithTurboJpeg(width, height, DEFAULT_JPEG_QUALITY);
}

} // namespace OHOS::Camera

#endif // __MJPEG_DECODER_TEST_UTILS_H__
