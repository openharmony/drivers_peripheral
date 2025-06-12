#ifndef BUFFER_HELPER_H
#define BUFFER_HELPER_H

#include <memory>
#include <base/native_buffer.h>

namespace OHOS::Codec::Omx {
using HDI::Base::NativeBuffer;

class UniqueFd {
public:
    static std::shared_ptr<UniqueFd> Create(int fd, bool transferOwnership);
    ~UniqueFd();
    int Get();

private:
    UniqueFd(int fd);
    int fd_ = -1;
};

sptr<NativeBuffer> ReWrap(const sptr<NativeBuffer>& src, bool isIpcMode);
int32_t Mmap(const sptr<NativeBuffer>& handle);
int32_t Unmap(const sptr<NativeBuffer>& handle);

}
#endif