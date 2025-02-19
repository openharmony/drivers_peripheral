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

#ifndef OHOS_DAUDIO_CONSTANTS_H
#define OHOS_DAUDIO_CONSTANTS_H

#include <string>
#include <map>

namespace OHOS {
namespace DistributedHardware {
// Distributed Auido Parameters
const std::string KEY_AUDIOPORT_DIR = "portdir";
const std::string KEY_AUDIOFORMAT = "format";
const std::string KEY_AUDIOCHANNELMASK = "channel";
const std::string KEY_AUDIOSAMPLERATE = "samplerate";

const std::string VALUE_AUDIOPORT_DIR_IN = "portdirin";
const std::string VALUE_AUDIOPORT_DIR_OUT = "portdirout";
const std::string VALUE_AUDIOPORT_DIR_INOUT = "portdirinout";

const std::string DEVICE_TYPE_OUTPUT_DEFAULT = "0";
const std::string DEVICE_TYPE_INPUT_DEFAULT = "1";

const std::string VOLUME_GROUP_ID = "VOLUME_GROUP_ID";
const std::string INTERRUPT_GROUP_ID = "INTERRUPT_GROUP_ID";

// Distributed Auido Parameters
const std::string VOLUME_LEVEL = "VOLUME_LEVEL";
const std::string VOLUME_EVENT_TYPE = "EVENT_TYPE";
const std::string MAX_VOLUME_LEVEL = "MAX_VOLUME_LEVEL";
const std::string MIN_VOLUME_LEVEL = "MIN_VOLUME_LEVEL";
const std::string STREAM_MUTE_STATUS = "STREAM_MUTE_STATUS";

const std::string HDF_EVENT_RESULT_SUCCESS = "DH_SUCCESS";
const std::string HDF_EVENT_INIT_ENGINE_FAILED = "ERR_DH_AUDIO_INIT_ENGINE_FAILED";
const std::string HDF_EVENT_NOTIFY_SINK_FAILED = "ERR_DH_AUDIO_NOTIFY_SINK_FAILED";
const std::string HDF_EVENT_TRANS_SETUP_FAILED = "ERR_DH_AUDIO_TRANS_SETUP_FAILED";
const std::string HDF_EVENT_TRANS_START_FAILED = "ERR_DH_AUDIO_TRANS_START_FAILED";
const std::string HDF_EVENT_RESULT_FAILED = "DH_FAILED";

const std::string HDF_EVENT_RESTART = "restart";
const std::string HDF_EVENT_PAUSE = "pause";

const std::string PRINT_SPK = "spk";
const std::string PRINT_MIC = "mic";
const std::string PRINT_NONE = "none";

constexpr int32_t AUDIO_DEVICE_TYPE_UNKNOWN = 0;
constexpr int32_t AUDIO_DEVICE_TYPE_SPEAKER = 1;
constexpr int32_t AUDIO_DEVICE_TYPE_MIC = 2;

constexpr uint32_t DAUDIO_FADE_NORMALIZATION_FACTOR = 2;
constexpr uint32_t DAUDIO_FADE_POWER_NUM = 2;
constexpr uint32_t DAUDIO_FADE_MAXIMUM_VALUE = 2;

constexpr uint32_t VOLUME_GROUP_ID_DEFAULT = 0;
constexpr uint32_t INTERRUPT_GROUP_ID_DEFAULT = 0;

constexpr uint32_t AUDIO_SAMPLE_RATE_DEFAULT = 4800;
constexpr uint32_t AUDIO_CHANNEL_COUNT_DEFAULT = 2;
constexpr uint32_t AUDIO_FORMAT_DEFAULT = 16;

constexpr int32_t MILLISECOND_PER_SECOND = 1000;
constexpr uint32_t DEFAULT_AUDIO_DATA_SIZE = 3840;
constexpr size_t RENDER_MAX_FRAME_SIZE = 4096;
constexpr int64_t AUDIO_OFFSET_FRAME_NUM = 10;
constexpr int64_t MAX_TIME_INTERVAL_US = 23000;

constexpr uint32_t AUDIO_DEFAULT_MAX_VOLUME_LEVEL = 15;
constexpr uint32_t AUDIO_DEFAULT_MIN_VOLUME_LEVEL = 0;

constexpr int32_t DAUDIO_MAX_ASHMEM_LEN = 100000;
constexpr int32_t DAUDIO_MIN_ASHMEM_LEN = 10;

constexpr const char *AUDIOCATEGORY = "AUDIOCATEGORY";
constexpr const char *KEY_DH_ID = "dhId";
constexpr const char *KEY_STATE = "STATE";
constexpr const char *IS_UPDATEUI = "IS_UPDATEUI";
constexpr const char *VOLUME_CHANAGE = "VOLUME_CHANAGE";
constexpr const char *FIRST_VOLUME_CHANAGE = "FIRST_VOLUME_CHANAGE";
constexpr const char *INTERRUPT_EVENT = "INTERRUPT_EVENT";
constexpr const char *FORCE_TYPE = "FORCE_TYPE";
constexpr const char *HINT_TYPE = "HINT_TYPE";
constexpr const char *RENDER_STATE_CHANGE_EVENT = "RENDER_STATE_CHANGE_EVENT";
constexpr const char *AUDIO_STREAM_TYPE = "AUDIO_STREAM_TYPE";
constexpr int32_t LOW_LATENCY_RENDER_ID = 1 << 1 | 1 << 0;
constexpr int32_t DEFAULT_RENDER_ID = 1;
constexpr int32_t DEFAULT_CAPTURE_ID = 1 << 27 | 1 << 0;
} // DistributeHardware
} // OHOS
#endif // OHOS_DAUDIO_CONSTANTS_H
