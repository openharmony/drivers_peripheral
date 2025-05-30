/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef HDF_USB_DATA_FIFO_H
#define HDF_USB_DATA_FIFO_H

#include "hdf_base.h"

struct DataFifo {
    uint32_t rdIdx;
    uint32_t wrIdx;
    uint32_t size;
    void *data;
};

#ifndef MIN
inline int32_t MIN(int32_t a, int32_t b)
{
    return ((a) < (b) ? (a) : (b));
}
#endif

#ifndef MAX
inline int32_t MAX(int32_t a, int32_t b)
{
    return ((a) > (b) ? (a) : (b));
}
#endif

/* DataFifo Helper function */
inline void DataFifoInit(struct DataFifo *fifo, uint32_t size, void *data)
{
    fifo->rdIdx = 0;
    fifo->wrIdx = 0;
    fifo->size = size;
    fifo->data = data;
}

inline bool DataFifoIsInitialized(struct DataFifo * const fifo)
{
    return fifo->size != 0;
}

inline void DataFifoReset(struct DataFifo * const fifo)
{
    fifo->rdIdx = fifo->wrIdx = 0;
}

inline uint32_t DataFifoLen(struct DataFifo * const fifo)
{
    return fifo->wrIdx - fifo->rdIdx;
}

inline bool DataFifoIsEmpty(struct DataFifo * const fifo)
{
    return fifo->wrIdx == fifo->rdIdx;
}

inline bool DataFifoIsFull(struct DataFifo * const fifo)
{
    return DataFifoLen(fifo) > (fifo->size - 1);
}

inline uint32_t DataFifoAvailSize(struct DataFifo * const fifo)
{
    return fifo->size - DataFifoLen(fifo);
}

inline void DataFifoSkip(struct DataFifo * const fifo, uint32_t size)
{
    fifo->rdIdx += size;
}

inline uint32_t DataFifoWrite(struct DataFifo *fifo, uint8_t *data, uint32_t size)
{
    uint32_t mask = fifo->size - 1;
    uint8_t *buf = (uint8_t *)fifo->data;
    uint8_t *end;

    size = MIN(size, DataFifoAvailSize(fifo));
    end = data + size;
    while (data < end) {
        buf[fifo->wrIdx++ & mask] = *data++;
    }
    return size;
}

inline uint32_t DataFifoRead(struct DataFifo *fifo, uint8_t *data, uint32_t size)
{
    uint32_t mask = fifo->size - 1;
    uint8_t *buf = (uint8_t *)fifo->data;
    uint8_t *end;

    size = MIN(size, DataFifoLen(fifo));
    end = data + size;
    while (data < end) {
        *data++ = buf[fifo->rdIdx++ & mask];
    }
    return size;
}

#endif /* HDF_USB_DATA_FIFO_H */
