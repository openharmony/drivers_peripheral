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
#include <ashmem.h>
#include <dlfcn.h>
#include <osal_mem.h>
#include <securec.h>
#include <cstdio>
#include <unistd.h>
#include "codec_jpeg_callback.h"
#include "hdf_log.h"

#define HDF_LOG_TAG codec_jpeg_decoder

using namespace OHOS::HDI::Codec::Image::V1_0;
using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace OHOS::HDI::Display::Composer::V1_0;

constexpr uint32_t MAX_WAIT = 1000 * 10;  // wait 100ms
static std::shared_ptr<JpegDecoder> decoder;
static volatile bool g_isDone;
JpegDecoder::JpegDecoder()
{
    hdiDecoder_ = ICodecImageJpeg::Get();
    hdiBuffer_ = IDisplayBuffer::Get();
    helper_ = new CodecJpegHelper();
}

JpegDecoder::~JpegDecoder()
{
    hdiDecoder_ = nullptr;
    hdiBuffer_ = nullptr;
    if (helper_ != nullptr) {
        delete helper_;
        helper_ = nullptr;
    }
    if (ioOut_.is_open()) {
        ioOut_.close();
    }
    if (ioIn_.is_open()) {
        ioIn_.close();
    }
    callback_ = nullptr;
}

static std::string GetArrayStr(const std::vector<uint32_t> &vec, std::string &arrayStr)
{
    arrayStr = ("[");
    int ret = 0;
    for (size_t i = 0; i < vec.size(); i++) {
        char value[32] = {0};
        ret = sprintf_s(value, sizeof(value) - 1, "0x0%X, ", vec[i]);
        if (ret < 0) {
            HDF_LOGE("sprintf_s value failed, error [%{public}d]", ret);
            break;
        }
        arrayStr += value;
    }
    arrayStr += "]";
    return arrayStr;
}

static void PrintCapability(const CodecImageCapability &cap, int32_t index)
{
    std::string arrayStr("");
    HDF_LOGI("----------------- Image capability [%{public}d] -------------------", index + 1);
    HDF_LOGI("name:[%{public}s]", cap.name.c_str());
    HDF_LOGI("role:[%{public}d]", cap.role);
    HDF_LOGI("type:[%{public}d]", cap.type);
    HDF_LOGI("maxSample:[%{public}d]", cap.maxSample);
    HDF_LOGI("maxWidth:[%{public}d]", cap.maxWidth);
    HDF_LOGI("maxHeight:[%{public}d]", cap.maxHeight);
    HDF_LOGI("minWidth:[%{public}d]", cap.minWidth);
    HDF_LOGI("minHeight:[%{public}d]", cap.minHeight);
    HDF_LOGI("maxInst:[%{public}d]", cap.maxInst);
    HDF_LOGI("isSoftwareCodec:[%{public}d]", cap.isSoftwareCodec);
    HDF_LOGI("supportPixFmts:%{public}s", GetArrayStr(cap.supportPixFmts, arrayStr).c_str());
    HDF_LOGI("-------------------------------------------------------------------");
}

int32_t JpegDecoder::Init()
{
    if (hdiDecoder_ == nullptr || hdiBuffer_ == nullptr) {
        HDF_LOGE("hdiDecoder_ or hdiBuffer_ is null !");
        return HDF_FAILURE;
    }
    std::vector<CodecImageCapability> capList;
    auto ret = hdiDecoder_->GetImageCapability(capList);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("GetImageCapability failed, err [%{public}d] !", ret);
        return HDF_FAILURE;
    }
    for (size_t i = 0; i < capList.size(); i++) {
        PrintCapability(capList[i], i);
    }
    callback_ = new CodecJpegCallbackService(decoder);
    return hdiDecoder_->JpegInit();
}

int32_t JpegDecoder::DeInit()
{
    return hdiDecoder_->JpegDeInit();
}

int32_t JpegDecoder::OnEvent(int32_t error)
{
    HDF_LOGI("enter callback , ret [%{public}d] !", error);
    if (error != HDF_SUCCESS) {
        HDF_LOGE("hardware decode error, should to decode by software !");
    }
    // write decode result
    if (error == HDF_SUCCESS) {
        BufferHandle *outHandle = outBuffer_.buffer->GetBufferHandle();
        hdiBuffer_->Mmap(*outHandle);
        ioOut_.write(reinterpret_cast<char *>(outHandle->virAddr), outHandle->size);
        ioOut_.flush();
        hdiBuffer_->Unmap(*outHandle);
        hdiBuffer_->FreeMem(*outHandle);
    }
    HDF_LOGI("decode and write output buffer succ !");

    // freeInBuffer
    auto ret = hdiDecoder_->FreeInBuffer(inBuffer_);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("FreeInBuffer failed, err [%{public}d] !", ret);
    }
    g_isDone = true;
    return ret;
}

int32_t JpegDecoder::PrepareData(std::string fileInput, std::string fileOutput)
{
    HDF_LOGI("start read jpeg image data !");

    ioIn_.open(fileInput, std::ios_base::binary);
    ioOut_.open(fileOutput, std::ios_base::binary | std::ios_base::trunc);

    ioIn_.seekg(0, ioIn_.end);
    bufferLen_ = ioIn_.tellg();
    ioIn_.seekg(0, ioIn_.beg);

    HDF_LOGE("bufferLen_ is [%{public}d]!", bufferLen_);
    std::unique_ptr<char[]> jpegBuffer = std::make_unique<char[]>(bufferLen_);
    if (jpegBuffer == nullptr) {
        HDF_LOGE("make_unique jpegBuffer failed !");
        return HDF_FAILURE;
    }
    ioIn_.read(jpegBuffer.get(), bufferLen_);

    HDF_LOGI("start parse jpeg header data !");
    bool err = helper_->DessambleJpeg(reinterpret_cast<int8_t *>(jpegBuffer.get()), bufferLen_,
        decInfo_, compressBuffer_, compDataLen_);
    if (!err) {
        HDF_LOGE("DecodeJpegHeader failed !");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t JpegDecoder::AllocBuffer(uint32_t width, uint32_t height)
{
    // alloc inBuffer
    auto ret = hdiDecoder_->AllocateInBuffer(inBuffer_, compDataLen_);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("AllocateInBuffer failed, err [%{public}d] !", ret);
        return HDF_FAILURE;
    }
    // alloc outBuffer
    AllocInfo alloc = {.width = AlignUp(width),
                       .height = height,
                       .usage =  HBM_USE_CPU_READ | HBM_USE_CPU_WRITE | HBM_USE_MEM_DMA,
                       .format = PIXEL_FMT_YCBCR_420_SP};

    BufferHandle *handle = nullptr;
    ret = hdiBuffer_->AllocMem(alloc, handle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("AllocMem failed, err [%{public}d] !", ret);
        return HDF_FAILURE;
    }

    outBuffer_.buffer = new NativeBuffer(handle);
    outBuffer_.fenceFd = -1;
    return HDF_SUCCESS;
}

int32_t JpegDecoder::Decode(CommandOpt opt)
{
    auto ret = PrepareData(opt.fileInput, opt.fileOutput);
    if (ret != HDF_SUCCESS) {
        return HDF_FAILURE;
    }

    ret = decoder->AllocBuffer(opt.width, opt.height);
    if (ret != HDF_SUCCESS) {
        return HDF_FAILURE;
    }

    HDF_LOGI("write jpeg data to inBuffer !");
    BufferHandle *bufferHandle = inBuffer_.buffer->GetBufferHandle();
    hdiBuffer_->Mmap(*bufferHandle);
    auto res  = memcpy_s(bufferHandle->virAddr, compDataLen_, compressBuffer_.get(), compDataLen_);
    if (res != 0) {
        HDF_LOGE("memcpy_s failed, err [%{public}d] !", res);
        return HDF_FAILURE;
    }
    hdiBuffer_->Unmap(*bufferHandle);

    HDF_LOGI("start jpeg decoding !");
    auto err = hdiDecoder_->DoJpegDecode(inBuffer_, outBuffer_, callback_, decInfo_);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("DoJpegDecode failed, err [%{public}d] !", err);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int main(int argc, char *argv[])
{
    CommandOpt opt;
    CommandParse parse;
    if (!parse.Parse(argc, argv, opt)) {
        return HDF_FAILURE;
    }
    decoder = std::make_shared<JpegDecoder>();
    auto ret = decoder->Init();
    if (ret != HDF_SUCCESS) {
        (void)decoder->DeInit();
        decoder = nullptr;
        return HDF_FAILURE;
    }

    ret = decoder->Decode(opt);
    if (ret != HDF_SUCCESS) {
        (void)decoder->DeInit();
        decoder = nullptr;
        return HDF_FAILURE;
    }
    while (!g_isDone) {
        usleep(MAX_WAIT);
    }
    ret = decoder->DeInit();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("DeInit failed, err [%{public}d] !", ret);
    }
    decoder = nullptr;
    return 0;
}
