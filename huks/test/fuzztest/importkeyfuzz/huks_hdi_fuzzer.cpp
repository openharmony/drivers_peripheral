
#include "huks_hdi_fuzzer.h"
#include "huks_hdi_passthrough_adapter.h"
#include "huks_hdi_fuzz_common.h"

#include <cstddef>
#include <cstdint>
#include <securec.h>


struct HuksHdi *g_instance = nullptr;

#define SIZE_ALIAS 16
#define SIZE_KEY 16

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    if (data == nullptr || size <= (sizeof(struct HksParamSet) + SIZE_ALIAS + SIZE_KEY)) {
        return false;
    }

    uint8_t *myData = static_cast<uint8_t *>(malloc(sizeof(uint8_t)*size));
    if (myData == nullptr) {
        return false;
    }

    (void)memcpy_s(myData, size, data, size);

    struct HksBlob keyAlias = { SIZE_ALIAS, myData };
    struct HksBlob aesKey = { SIZE_KEY, static_cast<uint8_t *>(myData + SIZE_ALIAS) };
    struct HksParamSet *paramSet = reinterpret_cast<struct HksParamSet *>(myData + SIZE_ALIAS + SIZE_KEY);

    paramSet->paramSetSize = size - (SIZE_ALIAS + SIZE_KEY);

    uint8_t buffer[1024];
    struct HksBlob out = {
        .data = buffer,
        .size = sizeof(buffer)
    };
    (void)g_instance->HuksHdiImportKey(&keyAlias, &aesKey, paramSet, &out);

    free(myData);
    return true;
}

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (InitHuksCoreEngine(&g_instance) != 0) {
        return -1;
    }
    DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
