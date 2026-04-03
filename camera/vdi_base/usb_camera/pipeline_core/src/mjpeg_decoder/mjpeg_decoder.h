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

#ifndef __MJPEG_DECODER_H__
#define __MJPEG_DECODER_H__

#include <cstddef>
#include <memory>
#include <mutex>
#include <vector>

// 前向声明 FFmpeg 结构 (避免在此处包含 FFmpeg 头文件)
struct AVFrame;
struct SwsContext;
struct AVCodecContext;
struct AVPacket;

namespace OHOS::Camera {

/**
 * @brief MJPEG 解码器统一接口
 */
class IMjpegDecoder {
public:
    virtual ~IMjpegDecoder() = default;

    /**
     * @brief 解码参数结构体 - 避免函数参数过多
     */
    struct DecodeParams {
        const uint8_t *mjpegData;
        size_t size;
        int width;
        int height;
        uint8_t *outputBuffer;
        size_t outputSize;
    };

    /**
     * @brief 解码 MJPEG 数据到 YUV (NV21 格式)
     * @param params 解码参数
     * @return true 解码成功，false 失败
     */
    virtual bool Decode(const DecodeParams &params) = 0;

    /**
     * @brief 获取解码器名称
     * @return const char* 解码器名称 ("FFmpeg" / "Libyuv")
     */
    virtual const char *GetName() const = 0;

    /**
     * @brief 检查解码器是否可用
     * @return true 可用，false 不可用
     */
    virtual bool IsAvailable() const = 0;
};

/**
 * @brief FFmpeg 后端实现
 */
class FfmpegMjpegDecoder : public IMjpegDecoder {
public:
    FfmpegMjpegDecoder();
    ~FfmpegMjpegDecoder() override;

    bool Decode(const DecodeParams &params) override;

    const char *GetName() const override
    {
        return "FFmpeg";
    }
    bool IsAvailable() const override
    {
        return isInitialized_;
    }

private:
    struct Impl;
    Impl *pimpl_;
    bool isInitialized_ = false;
};

/**
 * @brief Libyuv 后端实现 (动态加载)
 */
class LibyuvMjpegDecoder : public IMjpegDecoder {
public:
    LibyuvMjpegDecoder();
    ~LibyuvMjpegDecoder() override;

    bool Decode(const DecodeParams &params) override;

    const char *GetName() const override
    {
        return "Libyuv";
    }
    bool IsAvailable() const override;

private:
    struct Impl;
    Impl *pimpl_;
};

/**
 * @brief 解码器工厂 - 自动选择可用后端
 *
 * 选择策略:
 * 1. 优先尝试 Libyuv (性能更好)
 * 2. Fallback 到 FFmpeg (兼容性更好)
 */
class MjpegDecoderFactory {
public:
    /**
     * @brief 创建并返回可用的解码器实例
     * @return std::shared_ptr<IMjpegDecoder> 解码器实例
     *
     * @note 返回的实例可重复使用，建议静态缓存
     */
    static std::shared_ptr<IMjpegDecoder> Create();

    /**
     * @brief 获取当前可用的解码器名称
     * @return const char* "Libyuv" / "FFmpeg" / "None"
     */
    static const char *GetAvailableDecoderName();
};

} // namespace OHOS::Camera

#endif // __MJPEG_DECODER_H__
