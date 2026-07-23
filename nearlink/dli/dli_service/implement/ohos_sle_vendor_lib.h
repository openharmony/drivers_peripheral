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

#ifndef SLE_VENDOR_LIB_H
#define SLE_VENDOR_LIB_H

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
    DLI_ACB_OUT,    // DLI ACB downstream channel
    DLI_ACB_IN,     // DLI ACB upstream channel
    DLI_MAX_CHANNEL // Total channels
} DliChannelsT;

typedef enum {
    SLE_OP_RESULT_SUCCESS,
    SLE_OP_RESULT_FAIL,
} SleOpResultT;

/**
 * SLE vendor lib cmd.
 */
typedef enum {
    /**
     * Power on the SLE Controller.
     * @return 0 if success.
     */
    SLE_OP_POWER_ON,

    /**
     * Power off the SLE Controller.
     * @return 0 if success.
     */
    SLE_OP_POWER_OFF,

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
     * initialization the SLE Controller. it will be called after SLE_OP_DLI_CHANNEL_OPEN.
     * Controller Must call initCb to notify the host once it has been done.
     */
    SLE_OP_INIT,

    /**
     * Get the LPM idle timeout in milliseconds.
     * @param (uint_32 *)milliseconds, slec will return the value of lpm timer.
     * @return 0 if success.
     */
    SLE_OP_GET_LPM_TIMER,

    /**
     * Enable LPM mode on SLE Controller.
     */
    SLE_OP_LPM_ENABLE,

    /**
     * Disable LPM mode on SLE Controller.
     */
    SLE_OP_LPM_DISABLE,

    /**
     * Wakeup lock the SLEC.
     */
    SLE_OP_WAKEUP_LOCK,

    /**
     * Wakeup unlock the SLEC.
     */
    SLE_OP_WAKEUP_UNLOCK,

    /**
     * transmit event response to vendor lib.
     * @param (void *)buf, struct of HC_SLE_HDR.
     */
    SLE_OP_EVENT_CALLBACK
} SleOpcodeT;

/**
 * initialization callback.
 */
typedef void (*InitCallback)(SleOpResultT result);

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
} SleVendorInterfaceT;

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
