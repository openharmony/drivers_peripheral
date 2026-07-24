/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef OFF_FIND_VENDOR_LIB_H
#define OFF_FIND_VENDOR_LIB_H

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Define DLI channel descriptors array used in SLE_OP_DLI_CHANNEL_OPEN operation.
 */
typedef enum {
    DLI_CMD,        // DLI Command channel
    DLI_EVT,        // DLI Event channel
    DLI_MAX_CHANNEL // Total channels
} DliChannelsT;

/**
 * SLE vendor lib cmd.
 */
typedef enum {
    /**
     * Set Resvered Power for off find mode,it will be called when findnetwork enable.
     */
    SLE_OP_RESERVERD_POWER_SET,
    /**
     * Establish dli channels. it will be called after SLE_OP_POWER_ON.
     * @param int (*)[DLI_MAX_CHANNEL].
     * @return fd count.
     */
    SLE_OP_DLI_CHANNEL_OPEN,

    /**
     * Close all the dli channels which is opened.
     */
    SLE_OP_DLI_CHANNEL_CLOSE,
    /**
    * Set off find mode.
    * @param int *powerTime.
    */
    SLE_OP_OFF_FIND_MODE_ENABLE,
    /**
    * Disable off find mode.
    */
    SLE_OP_OFF_FIND_MODE_DISABLE,
    /**
    * Enable Leakage Prevention Mode mode.
    */
    SLE_OP_OFF_FIND_POWER_PROTECT_ENABLE,
} OffFindOpcodeT;

/**
 * Nearlink Host/Controller VENDOR Interface
 */
typedef struct {
    /**
     * Set to sizeof(sle_vndor_interface_t)
     */
    size_t size;

    /**
     * Caller will open the interface and pass in the callback routines
     * to the implementation of this interface.
     */
    int (*init)(void);

    /**
     * Vendor specific operations
     */
    int (*op)(int opcode, void* param);

    /**
     * Closes the interface
     */
    void (*close)(void);
} OffFindVendorInterfaceT;

typedef struct {
    size_t size;
    int (*modifyPowerProtect)(int powerTime, int power);
    bool (*isNeedWatcherStart)(std::string chipType);
    uint32_t (*getRegisterTimerDuration)(std::string chipType);
    void (*close)(void);
} OffFindVendorCommInterfaceT;

typedef struct {
    uint16_t event;
    uint16_t len;
    uint16_t offset;
    uint16_t layerSpecific;
    uint8_t data[];
} HC_SLE_HDR;

#ifdef __cplusplus
}
#endif

#endif /* SLE_VENDOR_LIB_H */
