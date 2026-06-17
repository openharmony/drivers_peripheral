/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
 * @addtogroup Input
 * @{
 *
 * @brief Provides driver interfaces for the input service.
 *
 * These driver interfaces can be used to open and close input device files, get input events, query device information,
 * register callback functions, and control the feature status.
 *
 * @since 1.0
 * @version 1.0
 */

 /**
 * @file input_type.h
 *
 * @brief Declares types of input devices as well as the structure and enumeration types used by driver interfaces.
 *
 * @since 1.0
 * @version 1.0
 */

#ifndef INPUT_TYPES_H
#define INPUT_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _UAPI_INPUT_H
#define	INPUT_PROP_MAX    0x1f
#define	INPUT_PROP_CNT    (INPUT_PROP_MAX + 1)
#define	EV_SYN    0x00
#define	EV_KEY    0x01
#define	EV_REL    0x02
#define	EV_ABS    0x03
#define	EV_MAX    0x1f
#define	EV_CNT    (EV_MAX + 1)
#define	ABS_X    0x00
#define	ABS_Y    0x01
#define	ABS_MAX    0x3f
#define	ABS_CNT    (ABS_MAX + 1)
#define	REL_X    0x00
#define	REL_Y    0x01
#define	REL_MAX    0x0f
#define	REL_CNT    (REL_MAX + 1)
#define	KEY_MAX    0x2ff
#define	KEY_CNT    (KEY_MAX + 1)
#define	LED_MAX    0x0f
#define	LED_CNT    (LED_MAX + 1)
#define	MSC_MAX    0x07
#define	MSC_CNT    (MSC_MAX + 1)
#define	SND_MAX    0x07
#define	SND_CNT    (SND_MAX + 1)
#define	SW_MAX    0x0f
#define	SW_CNT    (SW_MAX + 1)
#define	BTN_MOUSE    0x110
#define	BTN_TOUCH    0x14a
#define	SYN_REPORT    0
#endif

/** Maximum number of input devices */
#define MAX_INPUT_DEV_NUM 32
/** Length of chip information */
#define CHIP_INFO_LEN 10
/** Length of the chip name */
#define CHIP_NAME_LEN 10
/** Length of the vendor name */
#define VENDOR_NAME_LEN 10
/** Length of the input device name */
#define DEV_NAME_LEN 64
/** Length of the self-test result name */
#define SELF_TEST_RESULT_LEN 20
/** Name of the input device manager service */
#define DEV_MANAGER_SERVICE_NAME "hdf_input_host"
#ifdef DIV_ROUND_UP
#undef DIV_ROUND_UP
#endif
/** Formula for round-up calculation */
#define DIV_ROUND_UP(nr, d) (((nr) + (d) - 1) / (d))
/** Number of bits contained in a byte */
#define BYTE_HAS_BITS 8
/** Formula for conversion between bits and 64-bit unsigned integers */
#define BITS_TO_UINT64(count)    DIV_ROUND_UP(count, BYTE_HAS_BITS * sizeof(uint64_t))
/** Formula for calculating the maximum number of force feedback commands sent by the input device */
#define HDF_FF_CNT    (0x7f + 1)

/**
 * @brief Enumerates return values.
 */
enum RetStatus {
    INPUT_SUCCESS        = 0,     /**< Success */
    INPUT_FAILURE        = -1,    /**< Failure */
    INPUT_INVALID_PARAM  = -2,    /**< Invalid parameter */
    INPUT_NOMEM          = -3,    /**< Insufficient memory */
    INPUT_NULL_PTR       = -4,    /**< Null pointer */
    INPUT_TIMEOUT        = -5,    /**< Execution timed out */
    INPUT_UNSUPPORTED    = -6,    /**< Unsupported feature */
};

/**
 * @brief Enumerates input device types.
 */
enum InputDevType {
    INDEV_TYPE_TOUCH,               /**< Touchscreen */
    INDEV_TYPE_KEY,                 /**< Physical key */
    INDEV_TYPE_BUTTON,              /**< Virtual button */
    INDEV_TYPE_CROWN,               /**< Watch crown */
    INDEV_TYPE_HID_BEGIN_POS = 33,  /**< HID type start position */
    INDEV_TYPE_ENCODER,             /**< Encoder */
    INDEV_TYPE_MOUSE,               /**< Mouse */
    INDEV_TYPE_KEYBOARD,            /**< Keyboard */
    INDEV_TYPE_ROCKER,              /**< ROCKER */
    INDEV_TYPE_TRACKBALL,           /**< TRACKBALL */
    INDEV_TYPE_TOUCHPAD,            /**< Touchpad */
    INDEV_TYPE_UNKNOWN,             /**< Unknown input device type */
};

/**
 * @brief Enumerates power statuses.
 */
enum PowerStatus {
    INPUT_RESUME,                  /**< Resume status */
    INPUT_SUSPEND,                 /**< Suspend status */
    INPUT_LOW_POWER,               /**< Low-power status */
    INPUT_POWER_STATUS_UNKNOWN,    /**< Unknown power status */
};

/**
 * @brief Enumerates types of capacitance tests.
 */
enum CapacitanceTest {
    BASE_TEST,             /**< Basic capacitance test */
    FULL_TEST,             /**< Full capacitance self-test */
    MMI_TEST,              /**< Man-Machine Interface (MMI) capacitance test */
    RUNNING_TEST,          /**< Running capacitance test */
    TEST_TYPE_UNKNOWN,     /**< Unknown test type */
};

/**
 * @brief Describes the input event data package.
 */
typedef struct {
    uint32_t type;          /**< Type of the input event */
    uint32_t code;          /**< Specific code item of the input event */
    int32_t value;          /**< Value of the input event code item */
    uint64_t timestamp;     /**< Timestamp of the input event */
} InputEventPackage;

/**
 * @brief Defines the data packet structure for hot plug events.
 */
typedef struct {
    uint32_t devIndex;      /**< Device index */
    uint32_t devType;       /**< Device type */
    uint32_t status;        /**< Device status 1: offline 0: online*/
} InputHotPlugEvent;

/**
 * @brief Defines the input device.
 */
typedef struct {
    uint32_t devIndex;      /**< Device index */
    uint32_t devType;       /**< Device type */
} InputDevDesc;

/**
 * @brief Defines the input event callback for the input service.
 */
typedef struct {
    /**
     * @brief Reports input event data by the registered callback.
     *
     * @param pkgs Input event data package.
     * @param count Number of input event data packets.
     * @param devIndex Index of an input device.
     * @since 1.0
     * @version 1.0
     */
    void (*EventPkgCallback)(const InputEventPackage **pkgs, uint32_t count, uint32_t devIndex);
} InputEventCb;

/**
 * @brief Defines the hot plug event callback for the input service.
 */
typedef struct {
    /**
     * @brief Reports hot plug event data by the registered callback.
     *
     * @param event Pointer to the hot plug event data reported by the input driver.
     * @since 1.0
     * @version 1.0
     */
    void (*HotPlugCallback)(const InputHotPlugEvent *event);
} InputHostCb;

/**
  * @brief Defines the input device ability for storing bitmaps that record supported event types.
 *
 * A bit is used to indicate the type of events that can be reported by the input device.
 *
 */
typedef struct {
    uint64_t devProp[BITS_TO_UINT64(INPUT_PROP_CNT)];    /**< Device properties */
    uint64_t eventType[BITS_TO_UINT64(EV_CNT)];          /**< Bitmap for recording the supported event types */
    uint64_t absCode[BITS_TO_UINT64(ABS_CNT)];           /**< Bitmap for recording the supported absolute coordinates */
    uint64_t relCode[BITS_TO_UINT64(REL_CNT)];           /**< Bitmap for recording the supported relative coordinates */
    uint64_t keyCode[BITS_TO_UINT64(KEY_CNT)];           /**< Bitmap for recording the supported keycodes */
    uint64_t ledCode[BITS_TO_UINT64(LED_CNT)];           /**< Bitmap for recording the supported indicators */
    uint64_t miscCode[BITS_TO_UINT64(MSC_CNT)];          /**< Bitmap for recording other supported functions */
    uint64_t soundCode[BITS_TO_UINT64(SND_CNT)];         /**< Bitmap for recording supported sounds or alerts */
    uint64_t forceCode[BITS_TO_UINT64(HDF_FF_CNT)];      /**< Bitmap for recording the supported force functions */
    uint64_t switchCode[BITS_TO_UINT64(SW_CNT)];         /**< Bitmap for recording the supported switch functions */
    uint64_t keyType[BITS_TO_UINT64(KEY_CNT)];           /**< Bitmap for recording the key status */
    uint64_t ledType[BITS_TO_UINT64(LED_CNT)];           /**< Bitmap for recording the LED status */
    uint64_t soundType[BITS_TO_UINT64(SND_CNT)];         /**< Bitmap for recording the sound status */
    uint64_t switchType[BITS_TO_UINT64(SW_CNT)];         /**< Bitmap for recording the switch status */
} InputDevAbility;

/**
 * @brief Defines dimension information of the input device.
 */
typedef struct {
    int32_t axis;        /**< Axis */
    int32_t min;         /**< Minimum value of each coordinate */
    int32_t max;         /**< Maximum value of each coordinate */
    int32_t fuzz;        /**< Resolution of each coordinate */
    int32_t flat;        /**< Reference value of each coordinate */
    int32_t range;       /**< Range */
} InputDimensionInfo;

/**
 * @brief Defines identification information of the input device.
 */
typedef struct {
    uint16_t busType;    /**< Bus type */
    uint16_t vendor;     /**< Vendor ID */
    uint16_t product;    /**< Product ID */
    uint16_t version;    /**< Version */
} InputDevIdentify;

/**
 * @brief Defines input device attributes.
 */
typedef struct {
    char devName[DEV_NAME_LEN];               /**< Device name */
    InputDevIdentify id;                      /**< Device identification information */
    InputDimensionInfo axisInfo[ABS_CNT];     /**< Device dimension information */
} InputDevAttr;

/**
 * @brief Defines basic device information of the input device.
 */
typedef struct {
    uint32_t devIndex;                   /**< Device index */
    uint32_t devType;                    /**< Device type */
    char chipInfo[CHIP_INFO_LEN];        /**< Driver chip information */
    char vendorName[VENDOR_NAME_LEN];    /**< Module vendor name */
    char chipName[CHIP_NAME_LEN];        /**< Driver chip name */
    InputDevAttr attrSet;                /**< Device attributes */
    InputDevAbility abilitySet;          /**< Device abilities */
} InputDeviceInfo;

/**
 * @brief Defines the extra commands.
 */
typedef struct {
    const char *cmdCode;     /**< Command code */
    const char *cmdValue;    /**< Data transmitted in the command */
} InputExtraCmd;

#ifdef __cplusplus
}
#endif
#endif
/** @} */
