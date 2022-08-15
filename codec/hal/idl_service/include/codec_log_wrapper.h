/*
 * Copyright 2022 Shenzhen Kaihong DID Co., Ltd..
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CODEC_LOG_WRAPPER_H
#define CODEC_LOG_WRAPPER_H
#include <hdf_log.h>
namespace OHOS {
#define HDF_LOG_TAG codec_hdi_omx

#define FILENAME (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)
#ifndef CODEC_DEBUG
#define CODEC_LOGE(fmt, ...) HDF_LOGE("[%{public}s] %{public}s# " fmt, FILENAME, __func__, ##__VA_ARGS__)
#define CODEC_LOGW(fmt, ...) HDF_LOGW("[%{public}s] %{public}s# " fmt, FILENAME, __func__, ##__VA_ARGS__)
#define CODEC_LOGI(fmt, ...) HDF_LOGI("[%{public}s] %{public}s# " fmt, FILENAME, __func__, ##__VA_ARGS__)
#define CODEC_LOGD(fmt, ...) HDF_LOGD("[%{public}s] %{public}s# " fmt, FILENAME, __func__, ##__VA_ARGS__)
#else
constexpr int32_t MAX_BUFFER_LEN = 256;
static FILE *fp = fopen("/data/codec.log", "rw");
static void LOG(const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    std::string stdFromat = fmt;
    do {
        std::size_t pos = stdFormat.find("{public}");
        if (pos == std::string::npos) {
            break;
        }
        stdFormat = stdFormat.erase(pos, strlen("{public}"));
    } while (true);
    char buf[MAX_BUFFER_LEN] = {0};
    if (vsnprintf_s(buf, sizeof(buf), sizeof(buf), stdFormat.c_str(), va) <= 0) {
        va_end(va);
        return;
    }
    va_end(va);
    if (fp != nullptr) {
        fwrite(buf, strlen(buf), 1, fp);
        fflush(fp);
    }
}
#define CODEC_LOGE(fmt, ...) LOG("[%{public}s] %{public}s# " fmt, FILENAME, __func__, ##__VA_ARGS__)
#define CODEC_LOGW(fmt, ...) LOG("[%{public}s] %{public}s# " fmt, FILENAME, __func__, ##__VA_ARGS__)
#define CODEC_LOGI(fmt, ...) LOG("[%{public}s] %{public}s# " fmt, FILENAME, __func__, ##__VA_ARGS__)
#define CODEC_LOGD(fmt, ...) LOG("[%{public}s] %{public}s# " fmt, FILENAME, __func__, ##__VA_ARGS__)
#endif
#define CHECK_AND_RETURN_RET_LOG(cond, ret, fmt, ...) \
do {                                                  \
if (!(cond)) {                                        \
CODEC_LOGE(fmt, ##__VA_ARGS__);                       \
return ret;                                           \
}                                                     \
} while (0)
}  // namespace OHOS
#endif /* CODEC_LOG_WRAPPER_H */