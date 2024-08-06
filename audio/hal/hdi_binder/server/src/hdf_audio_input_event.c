/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "hdf_audio_input_event.h"
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>
#include <linux/input.h>
#include "hdf_audio_pnp_server.h"
#include "osal_time.h"
#include "securec.h"
#include "audio_uhdf_log.h"

#define HDF_LOG_TAG             HDF_AUDIO_HAL_HOST
#define INPUT_EVT_MAX_CNT       4
#define WAIT_THREAD_END_TIME_MS 1
static struct pollfd g_fdSets[INPUT_EVT_MAX_CNT];
static int32_t g_inputDevCnt = 0;
static bool g_bRunThread = false;

static int32_t AudioAnalogHeadsetDeviceCheck(struct input_event evt)
{
    struct AudioEvent audioEvent;

    AUDIO_FUNC_LOGI("enter.");
    audioEvent.eventType = (evt.value == 0) ? AUDIO_DEVICE_REMOVE : AUDIO_DEVICE_ADD;
    audioEvent.deviceType = AUDIO_DEVICE_UNKNOWN;
    switch (evt.code) {
        case SW_HEADPHONE_INSERT:
            audioEvent.deviceType = AUDIO_HEADPHONE;
            break;
        case SW_MICROPHONE_INSERT:
            audioEvent.deviceType = AUDIO_HEADSET;
            break;
        case SW_LINEOUT_INSERT:
            audioEvent.deviceType = AUDIO_LINEOUT;
            break;
        default: // SW_JACK_PHYSICAL_INSERT = 0x7, SW_LINEIN_INSERT = 0xd and other.
            AUDIO_FUNC_LOGE("n't surpport code =0x%{public}x\n", evt.code);
            return HDF_FAILURE;
    }
    return AudioPnpUpdateInfoOnly(audioEvent);
}

static void AudioPnpInputCheck(struct input_event evt)
{
    switch (evt.type) {
        case EV_SYN:
            break;
        case EV_SW:
            // The code possible is SW_HEADPHONE_INSERT=2,SW_MICROPHONE_INSERT=4,SW_LINEOUT_INSERT=6
            // or SW_LINEIN_INSERT=13.
            AUDIO_FUNC_LOGD("evt.type = EV_SW5, code =0x%{public}d, value = %{public}d\n", evt.code,
                evt.value);
            (void)AudioAnalogHeadsetDeviceCheck(evt);
            break;
        case EV_KEY:
            // The key on the board or on the analog headset.
            // The code possible is KEY_MEDIA=226,KEY_KP7=0x71(mute),KEY_KP8=0x72(volumn-),
            // KEY_KP9=0x73(vol+) or KEY_KPMINUS=0x74(power).
            if ((evt.code == KEY_MEDIA) || (evt.code == KEY_KP7) || (evt.code == KEY_KP8) || (evt.code == KEY_KP9)) {
                AUDIO_FUNC_LOGD("evt.type = EV_KEY1, code = 0x%{public}x, value = %{public}d.", evt.code, evt.value);
            }
            break;
        case EV_REL: // mouse move event.
        case EV_MSC:
        default:
            break;
    }
}

static int32_t AudioPnpInputPollAndRead(void)
{
    int32_t i;
    int32_t ret;
    int32_t n = g_inputDevCnt;
    struct input_event evt;

    ret = poll(g_fdSets, (nfds_t)n, -1);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("[poll] failed, %{public}d", errno);
        return HDF_FAILURE;
    }

    for (i = 0; i < n; i++) {
        if ((uint32_t)g_fdSets[i].revents & POLLIN) {
            if (read(g_fdSets[i].fd, (void *)&evt, sizeof(evt)) < 0) {
                AUDIO_FUNC_LOGE("[read] failed, %{public}d", errno);
                return HDF_FAILURE;
            }
            AudioPnpInputCheck(evt);
        }
    }

    return HDF_SUCCESS;
}

static int32_t AudioPnpInputOpen(void)
{
    int32_t i;
    int32_t j;
    char *devices[INPUT_EVT_MAX_CNT] = {
        "/dev/input/event1",
        "/dev/input/event2",
        "/dev/input/event3",
        "/dev/input/event4"
    };

    AUDIO_FUNC_LOGI("enter.");
    j = 0;
    for (i = 0; i < INPUT_EVT_MAX_CNT; i++) {
        g_fdSets[j].fd = open(devices[i], O_RDONLY);
        if (g_fdSets[j].fd < 0) {
            AUDIO_FUNC_LOGW("[open] %{public}s failed!", devices[i]);
            continue;
        }
        AUDIO_FUNC_LOGI("[open] %{public}s success!", devices[i]);
        g_fdSets[j].events = POLLIN;
        j++;
    }
    g_inputDevCnt = j;

    return (j == 0) ? HDF_FAILURE : HDF_SUCCESS;
}

static void *AudioPnpInputStart(void *useless)
{
    int ret;
    (void)useless;
    const char *threadName = "pnp_headset";
    pthread_t *threadInstance = (pthread_t *)useless;

    if (pthread_setname_np(*threadInstance, threadName) != 0) {
        AUDIO_FUNC_LOGE("Setname failed!");
        return NULL;
    }

    AUDIO_FUNC_LOGI("audio input start.");
    if (AudioPnpInputOpen() != HDF_SUCCESS) {
        return NULL;
    }

    do {
        ret = AudioPnpInputPollAndRead();
        if (ret != HDF_SUCCESS) {
            AUDIO_FUNC_LOGE("[AudioPnpInputPollAndRead] failed!");
            return NULL;
        }
    } while (g_bRunThread);

    return NULL;
}

int32_t AudioHeadsetPnpInputStartThread(void)
{
    pthread_t thread;
    pthread_attr_t tidsAttr;

    AUDIO_FUNC_LOGI("create audio headset pnp uevent thread");
    g_bRunThread = true;
    pthread_attr_init(&tidsAttr);
    pthread_attr_setdetachstate(&tidsAttr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&thread, &tidsAttr, AudioPnpInputStart, NULL) != 0) {
        AUDIO_FUNC_LOGE("[pthread_create] failed!");
        g_bRunThread = false;
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

void AudioHeadsetPnpInputEndThread(void)
{
    AUDIO_FUNC_LOGI("audio headset pnp uevent thread exit");
    g_bRunThread = false;
    OsalMSleep(WAIT_THREAD_END_TIME_MS);
}
