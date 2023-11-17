#include <byte_show.h>
#include <string.h>
#include <stdlib.h>
#include <hdf_log.h>

#define BYTE_SHOW_PRINTF HDF_LOGI
#define BYTE_SHOW_ONECE_MAX_LEN 128

static char ParseHexNum2ASCII(unsigned char src)
{
    if (src < 0xa) {
        return src + '0';
    } else {
        return src + 'a' - 0xa;
    }
}

static void ParseBytes2HexChar(unsigned char *src, unsigned int srcLen, unsigned char *dst,
    unsigned int *dtsLen, unsigned int bufferLen) {
    if (src == nullptr || dst == nullptr) {
        return;
    }
    if (srcLen * 2 > bufferLen) {
        return;
    }
    memset(dst, 0x0, bufferLen);
    for (unsigned int idx = 0; idx < srcLen; idx++) {
        dst[idx * 2] = ParseHexNum2ASCII((src[idx] >> 4) & 0x0F);
        dst[idx * 2 + 1] = ParseHexNum2ASCII(src[idx] & 0x0F);
    }

    if (dtsLen != nullptr) {
        *dtsLen = srcLen * 2;
    }
}

void ByteShow(const char *name, unsigned char *src, unsigned int srcLen) {
    unsigned char *tmpBuf = (unsigned char *)malloc(srcLen * 2 * sizeof(unsigned char) + 1);
    unsigned int tmpBufLen;
    unsigned int idx;
    ParseBytes2HexChar(src, srcLen, tmpBuf, &tmpBufLen, srcLen * 2 * sizeof(unsigned char));
    tmpBuf[srcLen * 2 * sizeof(unsigned char)] = '\0';
    BYTE_SHOW_PRINTF("Byteshow %s: \n", name);
    BYTE_SHOW_PRINTF("%s Len: %d \n", name, srcLen);
    for (idx = 0; idx + BYTE_SHOW_ONECE_MAX_LEN < tmpBufLen; idx += BYTE_SHOW_ONECE_MAX_LEN) {
        unsigned char *showBuf = (unsigned char *)malloc(BYTE_SHOW_ONECE_MAX_LEN * sizeof(unsigned char));
        unsigned int showBufLen = BYTE_SHOW_ONECE_MAX_LEN *sizeof(unsigned char);
        memset(showBuf, 0x0, showBufLen);
        memcpy(showBuf, tmpBuf + idx, showBufLen);
        BYTE_SHOW_PRINTF("%s DATA[%d]:%s\n", name, idx, showBuf);
        free(showBuf);
        showBuf = nullptr;
    }
    BYTE_SHOW_PRINTF("%s DATA[%d]:%s\n", name, idx, tmpBuf + idx);
    BYTE_SHOW_PRINTF("*******************************************name:%s,\n", name);
    free(tmpBuf);
    tmpBuf = nullptr;
}