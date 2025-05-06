#ifndef I_CODEC_BUFFER_H
#define I_CODEC_BUFFER_H
#include <buffer_handle.h>
namespace OHOS {
namespace Codec {
namespace Omx {
 
struct DynamicBuffer {
    int32_t type = 0;
    BufferHandle *bufferHandle = nullptr;
};
 
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS
 
#endif // I_CODEC_BUFFER_H