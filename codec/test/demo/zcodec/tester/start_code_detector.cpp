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
#include "start_code_detector.h"
#include <memory>
#include <algorithm>
#include "codec_log_wrapper.h"
using namespace std;

namespace OHOS::HDI::Codec::Zcodec {

std::shared_ptr<StartCodeDetector> StartCodeDetector::Create(CodeProtocol type)
{
    switch (type) {
        case H264:
            return make_shared<StartCodeDetectorH264>();
        case H265:
            return make_shared<StartCodeDetectorH265>();
        default:
            return nullptr;
    }
}

size_t StartCodeDetector::SetSource(const std::string &path)
{
    CODEC_LOGI("input path %{public}s", path.c_str());
    ifstream ifs(path, ios::binary);
    if (!ifs.is_open()) {
        CODEC_LOGE("cannot open %{public}s", path.c_str());
        return 0;
    }
    size_t fileSize = GetFileSizeInBytes(ifs);
    CODEC_LOGI("fileSize %{public}zu", fileSize);
    unique_ptr<uint8_t[]> buf = make_unique<uint8_t[]>(fileSize);
    ifs.read(reinterpret_cast<char *>(buf.get()), static_cast<std::streamsize>(fileSize));
    return SetSource(buf.get(), fileSize);
}

size_t StartCodeDetector::SetSource(const uint8_t* pStart, size_t bufSize)
{
    if (pStart == nullptr) {
        CODEC_LOGI("pStart == nullptr");
        return 0;
    }
    list<tuple<size_t, uint8_t, uint8_t>> posOfFile;
    size_t pos = 0;
    while (pos < bufSize) {
        auto pFound = search(pStart + pos, pStart + bufSize, begin(START_CODE), end(START_CODE));
        pos = distance(pStart, pFound);
        if (pos == bufSize || pos + START_CODE_LEN >= bufSize) { // 没找到或找到的起始码正好在文件末尾
            CODEC_LOGI("pos == bufSize || pos + START_CODE_LEN >= bufSize");
            break;
        }
        posOfFile.emplace_back(pos, pStart[pos + START_CODE_LEN], pStart[pos + START_CODE_LEN + 1]);
        pos += START_CODE_LEN;
    }
    for (auto it = posOfFile.begin(); it != posOfFile.end(); ++it) {
        auto nex = next(it);
        NALUInfo nal {
            .startPos = get<0>(*it),
            .endPos = (nex == posOfFile.end()) ? (bufSize) : (get<0>(*nex)),
            .nalType = GetNalType(get<1>(*it), get<2>(*it)),
        };
        SaveVivid(nal, pStart);
        nals_.push_back(nal);
    }
    BuildSampleList();
    return samples_.size();
}

void StartCodeDetector::SaveVivid(NALUInfo& nal, const uint8_t *pStart)
{
    if (!IsPrefixSEI(nal.nalType)) {
        return;
    }
    const uint8_t *nalStart = pStart + nal.startPos;
    if (*(nalStart + 5) == 0x04 &&  // 5: offset of last_payload_type_byte, 0x04: itu_t_t35
        *(nalStart + 7) == 0x26 &&  // 7: offset of itu_t_t35_country_code, 0x26: value in spec
        *(nalStart + 8) == 0x00 &&  // 8: offset of terminal_provide_code, 0x00: value in spec
        *(nalStart + 9) == 0x04 &&  // 9: offset of terminal_provide_code, 0x04: value in spec
        *(nalStart + 10) == 0x00 && // 10: offset of terminal_provide_oriented_code, 0x00: value in spec
        *(nalStart + 11) == 0x05) { // 11: offset of terminal_provide_oriented_code, 0x05: value in spec
        nal.vividSei = vector<uint8_t>(pStart + nal.startPos, pStart + nal.endPos);
    }
}

void StartCodeDetector::BuildSampleList()
{
    CODEC_LOGI("nals_.size %{public}zu", nals_.size());
    shared_ptr<Sample> sample;
    for (auto& nal : nals_) {
        if (sample == nullptr) {
            sample = make_shared<Sample>();
            sample->startPos = nal.startPos;
            sample->isCsd = false;
            sample->isIdr = false;
        }
        sample->endPos = nal.endPos;
        if (!sample->s.empty()) {
            sample->s += "+";
        }
        sample->s += to_string(nal.nalType);
        if (!nal.vividSei.empty()) {
            sample->vividSei = std::move(nal.vividSei);
        }

        bool isPPS = IsPPS(nal.nalType);
        bool isVCL = IsVCL(nal.nalType);
        bool isIDR = IsIDR(nal.nalType);
        if (isPPS || isVCL) {  // should cut here and build one sample
            if (isPPS) {
                sample->isCsd = true;
                csdIdxList_.push_back(samples_.size());
            }
            if (isIDR) {
                sample->isIdr = true;
                idrIdxList_.push_back(samples_.size());
            }
            sample->idx = samples_.size();
            samples_.push_back(*sample);
            sample.reset();
        }
    }
}

size_t StartCodeDetector::GetFileSizeInBytes(ifstream &ifs)
{
    ifs.seekg(0, ifstream::end);
    auto len = ifs.tellg();
    ifs.seekg(0, ifstream::beg);
    return static_cast<size_t>(len);
}

bool StartCodeDetector::SeekTo(size_t sampleIdx)
{
    if (sampleIdx >= samples_.size()) {
        return false;
    }

    auto idrIter = find_if(idrIdxList_.rbegin(), idrIdxList_.rend(), [sampleIdx](size_t idrIdx) {
        return idrIdx <= sampleIdx;
    });
    if (idrIter == idrIdxList_.rend()) {
        return false;
    }
    size_t idrIdx = *idrIter;

    auto csdIter = find_if(csdIdxList_.rbegin(), csdIdxList_.rend(), [idrIdx](size_t csdIdx) {
        return csdIdx < idrIdx;
    });
    if (csdIter == csdIdxList_.rend()) {
        return false;
    }
    size_t csdIdx = *csdIter;
    waitingCsd_ = csdIdx;
    nextSampleIdx_ = idrIdx;
    CODEC_LOGI("csd idx=%{public}zu, idr idx=%{public}zu, target sample idx=%{public}zu", csdIdx, idrIdx, sampleIdx);
    return true;
}

std::optional<Sample> StartCodeDetector::PeekNextSample()
{
    if (waitingCsd_.has_value()) {
        return samples_[waitingCsd_.value()];
    }
    if (nextSampleIdx_ >= samples_.size()) {
        return std::nullopt;
    }
    return samples_[nextSampleIdx_];
}

void StartCodeDetector::MoveToNext()
{
    if (waitingCsd_.has_value()) {
        waitingCsd_ = nullopt;
        return;
    }
    nextSampleIdx_++;
}

uint8_t StartCodeDetectorH264::GetNalType(uint8_t firstByte, uint8_t)
{
    return firstByte & 0b0001'1111;
}

bool StartCodeDetectorH264::IsPPS(uint8_t nalType)
{
    return nalType == H264NalType::PPS;
}

bool StartCodeDetectorH264::IsVCL(uint8_t nalType)
{
    return nalType >= H264NalType::NON_IDR && nalType <= H264NalType::IDR;
}

bool StartCodeDetectorH264::IsIDR(uint8_t nalType)
{
    return nalType == H264NalType::IDR;
}

uint8_t StartCodeDetectorH265::GetNalType(uint8_t firstByte, uint8_t)
{
    return (firstByte & 0b0111'1110) >> 1;
}

bool StartCodeDetectorH265::IsPPS(uint8_t nalType)
{
    return nalType == H265NalType::HEVC_PPS_NUT;
}

bool StartCodeDetectorH265::IsVCL(uint8_t nalType)
{
    return nalType >= H265NalType::HEVC_TRAIL_N && nalType <= H265NalType::HEVC_CRA_NUT;
}

bool StartCodeDetectorH265::IsIDR(uint8_t nalType)
{
    return nalType == H265NalType::HEVC_IDR_W_RADL ||
           nalType == H265NalType::HEVC_IDR_N_LP ||
           nalType == H265NalType::HEVC_CRA_NUT;
}

bool StartCodeDetectorH265::IsPrefixSEI(uint8_t nalType)
{
    return nalType == H265NalType::HEVC_PREFIX_SEI_NUT;
}

} // namespace OHOS::HDI::Codec::Zcodec