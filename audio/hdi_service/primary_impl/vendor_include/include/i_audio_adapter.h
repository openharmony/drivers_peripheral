/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

/**
 * @addtogroup Audio
 * @{
 *
 * @brief Defines audio-related APIs, including custom data types and functions for loading drivers,
 * accessing a driver adapter, and rendering and capturing audios.
 *
 * @since 1.0
 * @version 1.0
 */

/**
 * @file i_audio_adapter.h
 *
 * @brief Declares APIs for operations related to the audio adapter.
 *
 * @since 1.0
 * @version 1.0
 */

#ifndef I_AUDIO_ADAPTER_H
#define I_AUDIO_ADAPTER_H

#include "i_audio_types.h"
#include "i_audio_render.h"
#include "i_audio_capture.h"

/**
 * @brief Provides audio adapter capabilities, including initializing ports, creating rendering and capturing tasks,
 * and obtaining the port capability set.
 *
 * @see AudioHwiRender
 * @see AudioHwiCapture
 * @since 1.0
 * @version 1.0
 */
struct AudioHwiAdapter {
    /**
     * @brief Initializes all ports of an audio adapter.
     *
     * Call this function before calling other driver functions to check whether the initialization is complete.
     * If the initialization is not complete, wait for a while (for example, 100 ms) and perform the check again
     * until the port initialization is complete.
     *
     * @param adapter Indicates the pointer to the audio adapter to operate.
     * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise.
     */
    int32_t (*InitAllPorts)(struct AudioHwiAdapter *adapter);

    /**
     * @brief Creates an <b>AudioHwiRender</b> object.
     *
     * @param adapter Indicates the pointer to the audio adapter to operate.
     * @param desc Indicates the pointer to the descriptor of the audio adapter to start.
     * @param attrs Indicates the pointer to the audio sampling attributes to open.
     * @param render Indicates the double pointer to the <b>AudioHwiRender</b> object.
     * @return Returns <b>0</b> if the <b>AudioHwiRender</b> object is created successfully;
     * returns a negative value otherwise.
     * @see GetPortCapability
     * @see DestroyRender
     */
    int32_t (*CreateRender)(struct AudioHwiAdapter *adapter, const struct AudioHwiDeviceDescriptor *desc,
                            const struct AudioHwiSampleAttributes *attrs, struct AudioHwiRender **render);

    /**
     * @brief Destroys an <b>AudioHwiRender</b> object.
     *
     * @attention Do not destroy the object during audio rendering.
     *
     * @param adapter Indicates the pointer to the audio adapter to operate.
     * @param render Indicates the pointer to the <b>AudioHwiRender</b> object to operate.
     * @return Returns <b>0</b> if the <b>AudioHwiRender</b> object is destroyed; returns a negative value otherwise.
     * @see CreateRender
     */
    int32_t (*DestroyRender)(struct AudioHwiAdapter *adapter, struct AudioHwiRender *render);

    /**
     * @brief Creates an <b>AudioHwiCapture</b> object.
     *
     * @param adapter Indicates the pointer to the audio adapter to operate.
     * @param desc Indicates the pointer to the descriptor of the audio adapter to start.
     * @param attrs Indicates the pointer to the audio sampling attributes to open.
     * @param capture Indicates the double pointer to the <b>AudioHwiCapture</b> object.
     * @return Returns <b>0</b> if the <b>AudioHwiCapture</b> object is created successfully;
     * returns a negative value otherwise.
     * @see GetPortCapability
     * @see DestroyCapture
     */
    int32_t (*CreateCapture)(struct AudioHwiAdapter *adapter, const struct AudioHwiDeviceDescriptor *desc,
                             const struct AudioHwiSampleAttributes *attrs, struct AudioHwiCapture **capture);

    /**
     * @brief Destroys an <b>AudioHwiCapture</b> object.
     *
     * @attention Do not destroy the object during audio capturing.
     *
     * @param adapter Indicates the pointer to the audio adapter to operate.
     * @param capture Indicates the pointer to the <b>AudioHwiCapture</b> object to operate.
     * @return Returns <b>0</b> if the <b>AudioHwiCapture</b> object is destroyed; returns a negative value otherwise.
     * @see CreateCapture
     */
    int32_t (*DestroyCapture)(struct AudioHwiAdapter *adapter, struct AudioHwiCapture *capture);

    /**
     * @brief Obtains the capability set of the port driver for the audio adapter.
     *
     * @param adapter Indicates the pointer to the audio adapter to operate.
     * @param port Indicates the pointer to the port.
     * @param capability Indicates the pointer to the capability set to obtain.
     * @return Returns <b>0</b> if the capability set is successfully obtained; returns a negative value otherwise.
     */
    int32_t (*GetPortCapability)(struct AudioHwiAdapter *adapter, const struct AudioHwiPort *port,
                                 struct AudioHwiPortCapability *capability);

    /**
     * @brief Sets the passthrough data transmission mode of the audio port driver.
     *
     * @param adapter Indicates the pointer to the audio adapter to operate.
     * @param port Indicates the pointer to the port.
     * @param mode Indicates the passthrough transmission mode to set.
     * @return Returns <b>0</b> if the setting is successful; returns a negative value otherwise.
     * @see GetPassthroughMode
     */
    int32_t (*SetPassthroughMode)(struct AudioHwiAdapter *adapter, const struct AudioHwiPort *port,
                                  enum AudioHwiPortPassthroughMode mode);

    /**
     * @brief Obtains the passthrough data transmission mode of the audio port driver.
     *
     * @param adapter Indicates the pointer to the audio adapter to operate.
     * @param port Indicates the pointer to the port.
     * @param mode Indicates the pointer to the passthrough transmission mode to obtain.
     * @return Returns <b>0</b> if the mode is successfully obtained; returns a negative value otherwise.
     * @see SetPassthroughMode
     */
    int32_t (*GetPassthroughMode)(struct AudioHwiAdapter *adapter, const struct AudioHwiPort *port,
                                  enum AudioHwiPortPassthroughMode *mode);

    /**
     * @brief Update audio route on several source and sink ports.
     *
     * @param adapter Indicates the pointer to the audio adapter to operate.
     * @param route Indicates route information.
     * @param routeHandle Indicates route handle.
     * @return Returns <b>0</b> if the mode is successfully obtained; returns a negative value otherwise.
     * @see SetPassthroughMode
     */
    int32_t (*UpdateAudioRoute)(struct AudioHwiAdapter *adapter, const struct AudioHwiRoute *route,
        int32_t *routeHandle);

    /**
     * @brief Release an audio route.
     *
     * @param adapter Indicates the pointer to the audio adapter to operate.
     * @param routeHandle Indicates route handle.
     * @return Returns <b>0</b> if the mode is successfully obtained; returns a negative value otherwise.
     * @see SetPassthroughMode
     */
    int32_t (*ReleaseAudioRoute)(struct AudioHwiAdapter *adapter, int32_t routeHandle);

    /**
     * @brief Sets the mute operation for the audio.
     *
     * @param adapter Indicates the pointer to the audio adapter to operate.
     * @param mute Specifies whether to mute the audio. Value <b>true</b> means to mute the audio,
     * and <b>false</b> means the opposite.
     * @return Returns <b>0</b> if the setting is successful; returns a negative value otherwise.
     * @see GetMute
     */
    int32_t (*SetMicMute)(struct AudioHwiAdapter *adapter, bool mute);

    /**
     * @brief Obtains the mute operation set for the audio.
     *
     * @param adapter Indicates the pointer to the audio adapter to operate.
     * @param mute Indicates the pointer to the mute operation set for the audio. Value <b>true</b> means that
     * the audio is muted, and <b>false</b> means the opposite.
     * @return Returns <b>0</b> if the mute operation is obtained; returns a negative value otherwise.
     * @see SetMute
     */
    int32_t (*GetMicMute)(struct AudioHwiAdapter *adapter, bool *mute);

    /**
     * @brief Sets the audio volume for voice call.
     *
     * The volume ranges from 0.0 to 1.0. If the volume level in an audio service ranges from 0 to 15,
     * <b>0.0</b> indicates that the audio is muted, and <b>1.0</b> indicates the maximum volume level (15).
     *
     * @param adapter Indicates the pointer to the audio adapter to operate.
     * @param volume Indicates the volume to set. The value ranges from 0.0 to 1.0.
     * @return Returns <b>0</b> if the setting is successful; returns a negative value otherwise.
     * @see GetVolume
     */
    int32_t (*SetVoiceVolume)(struct AudioHwiAdapter *adapter, float volume);

    /**
     * @brief Sets extra audio parameters.
     *
     * @param adapter Indicates the audio adapter.
     * @param key Indicates what kind of parameter type will be set.
     * @param condition Indicates the specific extend parameter condition of AudioHwiExtParamKey.
     * @param value Indicates the value of the specified condition.
     *
     * The format of condition is <i>key=value</i>. Separate multiple key-value pairs by semicolons (;).
     * When key equals to AudioHwiExtParamKey::AUDIO_EXT_PARAM_KEY_VOLUME, the format of condition must be like this:
     * <i>"EVENT_TYPE=xxx;VOLUME_GROUP_ID=xxx;AUDIO_VOLUME_TYPE=xxx;"</i>
     * EVENT_TYPE indicates sub volume event type: SetVolume = 1; SetMute = 4;
     * VOLUME_GROUP_ID indicates which volume group will be set;
     * AUDIO_VOLUME_TYPE indicates which volume type will be set;
     *
     * @return Returns <b>0</b> if the operation is successful; returns a negative value otherwise.
     */
    int32_t (*SetExtraParams)(struct AudioHwiAdapter *adapter, enum AudioHwiExtParamKey key,
                              const char *condition, const char *value);

    /**
     * @brief Get extra audio parameters.
     *
     * @param adapter Indicates the audio adapter.
     * @param key Indicates what kind of parameter type will be get.
     * @param condition Indicates the specific extend parameter condition of AudioHwiExtParamKey.
     * @param value Indicates the value of the specified condition.
     * @param lenth Indicates the length of the value pointer.
     *
     * The format of condition is <i>key=value</i>. Separate multiple key-value pairs by semicolons (;).
     * When key equals to AudioHwiExtParamKey::AUDIO_EXT_PARAM_KEY_VOLUME, the format of condition must be like this:
     * <i>"EVENT_TYPE=xxx;VOLUME_GROUP_ID=xxx;AUDIO_VOLUME_TYPE=xxx;"</i>
     * EVENT_TYPE indicates sub volume event type: GetVolume = 1; GetMinVolume = 2; GetMaxVolume = 3; IsStreamMute = 4;
     * VOLUME_GROUP_ID indicates which volume group want get;
     * AUDIO_VOLUME_TYPE indicates which volume type want get;
     *
     * @return Returns <b>0</b> if the operation is successful; returns a negative value otherwise.
     */
    int32_t (*GetExtraParams)(struct AudioHwiAdapter *adapter, enum AudioHwiExtParamKey key,
                              const char *condition, char *value, int32_t lenth);

    /**
     * @brief Register extra audio parameters observer.
     *
     * @param adapter Indicates the audio adapter.
     * @param callback Indicates param observer.
     * @param cookie Indicates the pointer to the callback parameters;
     * @return Returns <b>0</b> if the operation is successful; returns a negative value otherwise.
     */
    int32_t (*RegExtraParamObserver)(struct AudioHwiAdapter *adapter, ParamHwiCallback callback, void* cookie);
    /**
     * @brief Get the device status of an adapter.
     *
     * @param adapter Indicates the audio adapter.
     * @param status Indicates the status of device .
     * @return Returns <b>0</b> if the operation is successful; returns a negative value otherwise.
     */
    int32_t (*GetDeviceStatus)(struct AudioHwiAdapter *adapter, struct AudioHwiDeviceStatus *status);
};

#endif /* I_AUDIO_ADAPTER_H */
/** @} */