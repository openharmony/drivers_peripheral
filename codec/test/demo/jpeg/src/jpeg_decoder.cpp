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
#include <sys/mman.h> 
#include "codec_log_wrapper.h"
#include "jpeg_decoder.h"

using namespace OHOS::HDI::Codec::Image::V2_1;
using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace OHOS::HDI::Display::Composer::V1_0;

static std::shared_ptr<JpegDecoder> decoder;
JpegDecoder::JpegDecoder()
{
    hdiJpeg_ = ICodecImage::Get();
    hdiBuffer_ = IDisplayBuffer::Get();
    helper_ = new CodecJpegHelper();
}

JpegDecoder::~JpegDecoder()
{
    hdiJpeg_ = nullptr;
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
}

static std::string GetArrayStr(const std::vector<uint32_t> &vec, std::string &arrayStr)
{
    arrayStr = ("[");
    for (size_t i = 0; i < vec.size(); i++) {
        char value[32] = {0};
        int ret = sprintf_s(value, sizeof(value) - 1, "0x0%X, ", vec[i]);
        if (ret < 0) {
            CODEC_LOGE("sprintf_s value failed, error [%{public}d]", ret);
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
    CODEC_LOGI("----------------- Image capability [%{public}d] -------------------", index + 1);
    CODEC_LOGI("name:[%{public}s]", cap.name.c_str());
    CODEC_LOGI("role:[%{public}d]", cap.role);
    CODEC_LOGI("type:[%{public}d]", cap.type);
    CODEC_LOGI("maxSample:[%{public}d]", cap.maxSample);
    CODEC_LOGI("maxWidth:[%{public}d]", cap.maxWidth);
    CODEC_LOGI("maxHeight:[%{public}d]", cap.maxHeight);
    CODEC_LOGI("minWidth:[%{public}d]", cap.minWidth);
    CODEC_LOGI("minHeight:[%{public}d]", cap.minHeight);
    CODEC_LOGI("maxInst:[%{public}d]", cap.maxInst);
    CODEC_LOGI("isSoftwareCodec:[%{public}d]", cap.isSoftwareCodec);
    CODEC_LOGI("supportPixFmts:%{public}s", GetArrayStr(cap.supportPixFmts, arrayStr).c_str());
    CODEC_LOGI("-------------------------------------------------------------------");
}

int32_t JpegDecoder::Init()
{
    if (hdiJpeg_ == nullptr || hdiBuffer_ == nullptr) {
        CODEC_LOGE("hdiJpeg_ or hdiBuffer_ is null !");
        return HDF_FAILURE;
    }
    std::vector<CodecImageCapability> capList;
    auto ret = hdiJpeg_->GetImageCapability(capList);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("GetImageCapability failed, err [%{public}d] !", ret);
        return HDF_FAILURE;
    }
    for (size_t i = 0; i < capList.size(); i++) {
        PrintCapability(capList[i], i);
    }
    return hdiJpeg_->Init(CODEC_IMAGE_JPEG);
}

int32_t JpegDecoder::DeInit()
{
    if (hdiJpeg_ == nullptr) {
        return HDF_FAILURE;
    }
    return hdiJpeg_->DeInit(CODEC_IMAGE_JPEG);
}

int32_t JpegDecoder::OnEvent(int32_t error)
{
    CODEC_LOGI("enter callback , ret [%{public}d] !", error);
    if (error != HDF_SUCCESS) {
        CODEC_LOGE("hardware decode error, should to decode by software !");
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
    CODEC_LOGI("decode and write output buffer succ !");

    // freeInBuffer
    auto ret = hdiJpeg_->FreeInBuffer(inBuffer_);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("FreeInBuffer failed, err [%{public}d] !", ret);
    }
    return ret;
}

int32_t JpegDecoder::PrepareData(std::string fileInput, std::string fileOutput)
{
    CODEC_LOGI("start read jpeg image data !");

    ioIn_.open(fileInput, std::ios_base::binary);
    ioOut_.open(fileOutput, std::ios_base::binary | std::ios_base::trunc);

    ioIn_.seekg(0, ioIn_.end);
    bufferLen_ = ioIn_.tellg();
    ioIn_.seekg(0, ioIn_.beg);

    CODEC_LOGI("bufferLen_ is [%{public}d]!", bufferLen_);
    jpegBuffer_ = std::make_unique<char[]>(bufferLen_);
    if (jpegBuffer_ == nullptr) {
        CODEC_LOGE("make_unique jpegBuffer_ failed !");
        return HDF_FAILURE;
    }
    ioIn_.read(jpegBuffer_.get(), bufferLen_);

    CODEC_LOGI("start parse jpeg header data !");
    bool err = helper_->DessambleJpeg(reinterpret_cast<int8_t *>(jpegBuffer_.get()), bufferLen_,
        decInfo_, compressBuffer_, compDataLen_, dataStart_);
    if (!err) {
        CODEC_LOGE("DecodeJpegHeader failed !");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t JpegDecoder::AllocBuffer(uint32_t width, uint32_t height)
{
    // alloc inBuffer
    auto ret = hdiJpeg_->AllocateInBuffer(inBuffer_, compDataLen_, CODEC_IMAGE_JPEG);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("AllocateInBuffer failed, err [%{public}d] !", ret);
        return HDF_FAILURE;
    }
    // alloc outBuffer
    AllocInfo alloc = {.width = AlignUp(width),
                       .height = height,
                       .usage =  HBM_USE_CPU_READ | HBM_USE_CPU_WRITE | HBM_USE_MEM_DMA,
                       .format = PIXEL_FMT_YCRCB_420_SP};

    BufferHandle *handle = nullptr;
    ret = hdiBuffer_->AllocMem(alloc, handle);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("AllocMem failed, err [%{public}d] !", ret);
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

    CODEC_LOGI("write jpeg data to inBuffer !");
    BufferHandle *bufferHandle = inBuffer_.buffer->GetBufferHandle();
    bufferHandle->virAddr = mmap(nullptr, bufferHandle->size, PROT_READ | PROT_WRITE,
                                 MAP_SHARED, bufferHandle->fd, 0);
    if (bufferHandle->virAddr == MAP_FAILED) {
        CODEC_LOGE("failed to map input buffer");
        return false;
    }
    auto res  = memcpy_s(bufferHandle->virAddr, compDataLen_, compressBuffer_.get(), compDataLen_);
    if (res != 0) {
        CODEC_LOGE("memcpy_s failed, err [%{public}d] !", res);
        return HDF_FAILURE;
    }
    munmap(bufferHandle->virAddr, bufferHandle->size);

    CODEC_LOGI("start jpeg decoding !");
    decInfo_.sampleSize = 1;
    decInfo_.compressPos = 0;
    ret = hdiJpeg_->DoJpegDecode(inBuffer_, outBuffer_, decInfo_);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("DoJpegDecode failed, err [%{public}d] !", ret);
        return HDF_FAILURE;
    }
    
    // write decode result
    BufferHandle *outHandle = outBuffer_.buffer->Move();
    hdiBuffer_->Mmap(*outHandle);
    ioOut_.write(reinterpret_cast<char *>(outHandle->virAddr), outHandle->size);
    ioOut_.flush();
    hdiBuffer_->Unmap(*outHandle);
    hdiBuffer_->FreeMem(*outHandle);
    CODEC_LOGI("decode and write output buffer succ !");

    // freeInBuffer
    ret = hdiJpeg_->FreeInBuffer(inBuffer_);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("FreeInBuffer failed, err [%{public}d] !", ret);
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

    ret = decoder->DeInit();
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("DeInit failed, err [%{public}d] !", ret);
    }
    decoder = nullptr;
    return 0;
}
