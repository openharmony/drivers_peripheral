/*
 * Copyright (c) 2021-2023 Shenzhen Kaihong DID Co., Ltd..
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

#ifdef __cplusplus
extern "C" {
#endif

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif
#define LOG_DOMAIN 0xD002514

#ifdef HDF_LOG_TAG
#undef HDF_LOG_TAG
#endif

#ifdef LOG_TAG_IMAGE
#define HDF_LOG_TAG codec_hdi_image
#elif LOG_TAG_PASSTHROUGH
#define HDF_LOG_TAG codec_hdi_adapter
#elif LOG_TAG_HDI_SERVER
#define HDF_LOG_TAG codec_hdi_server
#elif LOG_TAG_HDI_CLIENT
#define HDF_LOG_TAG codec_hdi_client
#else
#define HDF_LOG_TAG codec_hdi_omx
#endif

#define FILENAME (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)

#ifndef OHOS_DEBUG
#define DECORATOR_HDFLOG(op, fmt, args...)             \
    do {                                               \
        op("%{public}s() " fmt, __FUNCTION__, ##args); \
    } while (0)
#else
#define DECORATOR_HDFLOG(op, fmt, args...)                                 \
    do {                                                                   \
        op("{%s()-%s:%d} " fmt, __FUNCTION__, FILENAME, __LINE__, ##args); \
    } while (0)
#endif

#define CODEC_LOGE(fmt, ...) DECORATOR_HDFLOG(HDF_LOGE, fmt, ##__VA_ARGS__)
#define CODEC_LOGW(fmt, ...) DECORATOR_HDFLOG(HDF_LOGW, fmt, ##__VA_ARGS__)
#define CODEC_LOGI(fmt, ...) DECORATOR_HDFLOG(HDF_LOGI, fmt, ##__VA_ARGS__)
#define CODEC_LOGV(fmt, ...) DECORATOR_HDFLOG(HDF_LOGV, fmt, ##__VA_ARGS__)
#define CODEC_LOGD(fmt, ...) DECORATOR_HDFLOG(HDF_LOGD, fmt, ##__VA_ARGS__)

#define CHECK_AND_RETURN_RET_LOG(cond, ret, fmt, ...) \
do {                                                  \
    if (!(cond)) {                                    \
        CODEC_LOGE(fmt, ##__VA_ARGS__);               \
        return ret;                                   \
    }                                                 \
} while (0)

#define CHECK_AND_RETURN_RET(cond, ret) \
do {                                \
    if (!(cond)) {                  \
        return ret;                     \
    }                                   \
} while (0)

#ifdef __cplusplus
}
#endif
#endif /* CODEC_LOG_WRAPPER_H */
