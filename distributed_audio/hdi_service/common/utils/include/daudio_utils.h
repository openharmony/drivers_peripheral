/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_DAUDIO_UTILS_H
#define OHOS_DAUDIO_UTILS_H

#include <fstream>
#include <string>

#include "cJSON.h"

#define AUDIO_MS_PER_SECOND 1000
#define AUDIO_US_PER_SECOND 1000000
#define AUDIO_NS_PER_SECOND ((int64_t)1000000000)
#define AUDIO_MMAP_NOIRQ_INTERVAL 5
#define AUDIO_MMAP_VOIP_INTERVAL  20
#define AUDIO_NORMAL_INTERVAL     20
namespace OHOS {
namespace DistributedHardware {
std::string GetAnonyString(const std::string &value);

std::string GetChangeDevIdMap(int32_t devId);

int32_t GetAudioParamStr(const std::string &params, const std::string &key, std::string &value);

int32_t GetAudioParamInt(const std::string &params, const std::string &key, int32_t &value);

int32_t GetAudioParamUInt(const std::string &params, const std::string &key, uint32_t &value);

int32_t GetAudioParamBool(const std::string &params, const std::string &key, bool &value);

int32_t SetAudioParamStr(std::string &params, const std::string &key, const std::string &value);

int32_t GetDevTypeByDHId(int32_t dhId);

int64_t GetNowTimeUs();

uint32_t CalculateFrameSize(uint32_t sampleRate, uint32_t channelCount,
    int32_t format, uint32_t timeInterval, bool isMMAP);

int32_t CalculateSampleNum(uint32_t sampleRate, uint32_t timems);

int64_t GetCurNano();

int32_t AbsoluteSleep(int64_t nanoTime);

int64_t CalculateOffset(const int64_t frameindex, const int64_t framePeriodNs, const int64_t startTime);

int64_t UpdateTimeOffset(const int64_t frameIndex, const int64_t framePeriodNs, int64_t &startTime);

bool IsOutDurationRange(int64_t startTime, int64_t endTime, int64_t lastStartTime);

void SaveFile(std::string fileName, uint8_t *audioData, int32_t size);

int32_t WrapCJsonItem(const std::initializer_list<std::pair<std::string, std::string>> &keys, std::string &content);

bool CJsonParamCheck(const cJSON *jsonObj, const std::initializer_list<std::string> &keys);

std::string ParseStringFromArgs(const std::string &args, const char *key);

bool CheckIsNum(const std::string &jsonString);
} // DistributedHardware
} // OHOS
#endif