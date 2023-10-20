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

#ifndef OHOS_DAUDIO_ERRCODE_H
#define OHOS_DAUDIO_ERRCODE_H

namespace OHOS {
namespace DistributedHardware {
enum DAudioErrorCode {
    DH_SUCCESS = 0,
    // Distributed Audio HDF Error Code
    ERR_DH_AUDIO_HDF_FAIL = -46001,
    ERR_DH_AUDIO_HDF_NULLPTR = -46002,
    ERR_DH_AUDIO_HDF_INVALID_PARAM = -46003,
    ERR_DH_AUDIO_HDF_REPEAT_OPERATION = -46004,
    ERR_DH_AUDIO_HDF_INVALID_OPERATION = -46005,
    ERR_DH_AUDIO_HDF_SET_PARAM_FAIL = -46006,
    ERR_DH_AUDIO_HDF_OPEN_DEVICE_FAIL = -46007,
    ERR_DH_AUDIO_HDF_CLOSE_DEVICE_FAIL = -46008,
    ERR_DH_AUDIO_COMMON_NOT_FOUND_KEY = -46009,
    ERR_DH_AUDIO_HDF_WAIT_TIMEOUT = -46010,

    ERR_DH_AUDIO_HDF_INIT_ENGINE_FAILED = -46011,
    ERR_DH_AUDIO_HDF_NOTIFY_SINK_FAILED = -46012,
    ERR_DH_AUDIO_HDF_TRANS_SETUP_FAILED = -46013,
    ERR_DH_AUDIO_HDF_TRANS_START_FAILED = -46014,
    ERR_DH_AUDIO_HDF_RESULT_FAILED = -46015,
};
} // Distributedaudio
} // OHOS
#endif
