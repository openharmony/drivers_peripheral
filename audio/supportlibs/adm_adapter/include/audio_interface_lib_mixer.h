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

#ifndef AUDIO_INTERFACE_LIB_MIXER_H
#define AUDIO_INTERFACE_LIB_MIXER_H

#include <sys/types.h>

#define MIXER_CMD_ID_BASE 200

#define AUDIO_BASE_LEN          32
#define AUDIO_ELEMENT_NUM       64
#define AUDIO_INTEGER_NUM       128
#define AUDIO_ELEM_NAME_LEN     (2 * (AUDIO_BASE_LEN))
#define AUDIO_CARD_SRV_NAME_LEN (2 * (AUDIO_BASE_LEN))
#define RESERVED_BUF_LEN        (8 * (AUDIO_BASE_LEN))

typedef enum {
    PCM_RENDER = 1,
    PCM_CAPTURE = 2,
    PCM_BOTTOM = PCM_RENDER,
} AudioPcmType;

typedef enum {
    /** Card level */
    AUDIO_CTL_ELEM_IFACE_CARD,
    AUDIO_CTL_ELEM_IFACE_PCM,
    AUDIO_CTL_ELEM_IFACE_MIXER = 2, /* virtual mixer control */
    AUDIO_CTL_ELEM_IFACE_LAST = AUDIO_CTL_ELEM_IFACE_MIXER,
} AudioCtlElemIfaceType;

typedef enum {
    AUDIO_CTL_ELEM_TYPE_NONE = 0, /* Invalid type */
    AUDIO_CTL_ELEM_TYPE_BOOLEAN,
    AUDIO_CTL_ELEM_TYPE_INTEGER,
    AUDIO_CTL_ELEM_TYPE_ENUMERATED,
    AUDIO_CTL_ELEM_TYPE_BYTES,
    AUDIO_CTL_ELEM_TYPE_LAST = AUDIO_CTL_ELEM_TYPE_BYTES,
} AudioCtlElemType;

enum AudioControlType {
    AUDIO_CONTROL_MIXER = 1,
    AUDIO_CONTROL_MUX,
    AUDIO_CONTROL_ENUM,
};

typedef enum AudioMixerCtrlCmdList {
    MIXER_CTL_IOCTL_PVERSION = -1,
    MIXER_CTL_IOCTL_ELEM_INFO = MIXER_CMD_ID_BASE,
    MIXER_CTL_IOCTL_ELEM_READ,
    MIXER_CTL_IOCTL_ELEM_WRITE,
    MIXER_CTL_IOCTL_ELEM_LIST,
    MIXER_CTL_IOCTL_ELEM_GET_PROP,
    MIXER_CTL_IOCTL_ELEM_SET_PROP,
    MIXER_CTL_IOCTL_GET_CARDS,
    MIXER_CTL_IOCTL_GET_CHMAP,
    MIXER_CTL_IOCTL_SET_CHMAP,
    MIXER_CTL_IOCTL_BUTT = MIXER_CTL_IOCTL_PVERSION,
} OpCode;

struct HdfIoService;
typedef int32_t (*AudioMixer)(AudioPcmType pcm, OpCode cmd, const struct HdfIoService *service, void *data);

struct AudioMixerOps {
    int32_t cmdId;
    AudioMixer func;
};

struct AudioCardId {
    int32_t index;
    char cardName[AUDIO_CARD_SRV_NAME_LEN];
};

struct SndCardsList {
    uint32_t cardNums;
    void *cardsList; /* AudioCardId Indicates the first link address of the structure type */
};

struct AudioHwCtlElemId {
    char name[AUDIO_ELEM_NAME_LEN]; /* ASCII name of item */
    AudioCtlElemIfaceType iface;
};

struct AudioHwCtlElemIndex {
    struct AudioHwCtlElemId eId;
    uint32_t index; /* index of item */
};

struct AudioCtlElemList {
    const char *cardSrvName;
    uint32_t count;                           /* R: count of all elements */
    uint32_t space;                           /* W: count of element IDs to get */
    struct AudioHwCtlElemId *ctlElemListAddr; /* R: IDs (AudioHwCtlElemId list addr) */
};

struct AudioMixerCtlElemInfo {
    char cardSrvName[AUDIO_CARD_SRV_NAME_LEN];
    struct AudioHwCtlElemIndex eIndexId; /* W: element IDx */
    AudioCtlElemType type;               /* R: value type - AudioCtlElemType */
    uint32_t count;                      /* count of values */
    union {
        struct {
            int32_t min;                  /* R: minimum value */
            int32_t max;                  /* R: maximum value */
            int32_t step;                 /* R: step (0 variable) */
            long vals[AUDIO_INTEGER_NUM]; /* RW: values */
        } intVal;
        struct {
            uint32_t items;                 /* R: number of items */
            uint32_t item;                  /* W: item number */
            long val[AUDIO_ELEMENT_NUM];    /* RW: value */
            char name[AUDIO_ELEM_NAME_LEN]; /* R: value name */
            uint64_t names_ptr;             /* W: names list (ELEM_ADD only) */
            uint32_t names_length;
        } enumVal;
        unsigned char reserved[RESERVED_BUF_LEN];
    } value;
};

/* External structure */
struct AudioMixerContents {
    char cardServiceName[AUDIO_CARD_SRV_NAME_LEN];
    uint32_t elemNum;
    void *data; /* AudioHwCtlElemId Indicates the first link address of the structure type */
};

#endif /* AUDIO_INTERFACE_LIB_MIXER_H */
