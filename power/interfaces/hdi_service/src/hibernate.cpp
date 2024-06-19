/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "hibernate.h"

#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cinttypes>
#include <cstdio>
#include <thread>
#include <fcntl.h>
#include <securec.h>
#include <sys/stat.h>
#include <sys/random.h>
#include <sys/swap.h>
#include <sys/sysinfo.h>
#include <linux/fs.h>
#include <linux/fiemap.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <unique_fd.h>
#include <hdf_base.h>
#include <hdf_log.h>
#include <file_ex.h>


namespace OHOS {
namespace HDI {
namespace Power {
namespace V1_2 {

#ifndef HMFS_IOCTL_MAGIC
#define HMFS_IOCTL_MAGIC 0xf5
#endif

#define HMFS_IOC_SWAPFILE_PREALLOC _IOWR(HMFS_IOCTL_MAGIC, 32, uint32_t)

constexpr int32_t SWAP_HEADER_INFO_VERSION = 1;
constexpr int32_t SWAP_HEADER_INFO_UUID_OFFSET = 3;
constexpr int32_t SWAP_HEADER_MAGIC_SIZE = 10;
constexpr int32_t SWAP_HEADER_SIZE = 129;
constexpr int32_t SWAP_HEADER_INFO_BOOTBITS_SIZE = 1024;
constexpr int32_t SWAP_HEADER_BUF_LEN = 1024;
constexpr int32_t FILE_MAP_BUF_LEN = 2048;
// The swap file size, which can be configured in subsequent version.
constexpr uint64_t SWAP_FILE_SIZE = 17179869184; // 16G
constexpr uint32_t SWAP_FILE_MODE = 0660;

constexpr int32_t UUID_VERSION_OFFSET = 6;
constexpr int32_t UUID_CLOCK_OFFSET = 8;
constexpr int32_t UUID_BUF_LEN = 16;
constexpr unsigned char UUID_VERSION_OPERAND1 = 0x0F;
constexpr unsigned char UUID_VERSION_OPERAND2 = 0x40;
constexpr unsigned char UUID_CLOCK_OPERAND1 = 0x3F;
constexpr unsigned char UUID_CLOCK_OPERAND2 = 0x80;

constexpr const char * const SWAP_FILE_PATH = "/data/power/swapfile";
constexpr const char * const SWAP_DIR_PATH = "/data/power";
constexpr const char * const HIBERNATE_RESUME = "/sys/hibernate/resume";
constexpr const char * const SYS_POWER_RESUME = "/sys/power/resume";
constexpr const char * const SYS_POWER_RESUME_OFFSET = "/sys/power/resume_offset";
constexpr const char * const HIBERNATE_STATE_PATH = "/sys/power/state";
constexpr const char * const HIBERNATE_STATE = "disk";

// Partition the swap file is located, which can be configured in subsequent version.
constexpr const char * const RESUME = "/dev/nvme0n1p61";

struct SwapfileCfg {
    unsigned long long len;
};

static int UlongLen(unsigned long arg)
{
    int l = 0;
    arg >>= 1;
    while (arg) {
        l++;
        arg >>= 1;
    }
    return l;
}

void Hibernate::Init()
{
    HDF_LOGI("hibernate init begin.");
    auto myThread = std::thread(&Hibernate::InitSwap, this);
    myThread.detach();
}

void Hibernate::InitSwap()
{
    std::lock_guard<std::mutex> lock(initMutex_);
    if (swapFileReady_) {
        HDF_LOGI("swap file is ready, do nothing.");
        return;
    }
    bool needToCreateSwapFile;
    auto ret = CheckSwapFile(needToCreateSwapFile);
    if (ret != HDF_SUCCESS) {
        return;
    }

    if (needToCreateSwapFile) {
        ret = CreateSwapFile();
        if (ret != HDF_SUCCESS) {
            return;
        }
        ret = MkSwap();
        if (ret != HDF_SUCCESS) {
            HDF_LOGI("init swap failed");
            RemoveSwapFile();
            return;
        }
    }

    ret = WriteOffsetAndResume();
    if (ret != HDF_SUCCESS) {
        return;
    }
    swapFileReady_ = true;
}

int32_t Hibernate::MkSwap()
{
    int fd = open(SWAP_FILE_PATH, O_RDWR);
    if (fd < 0) {
        HDF_LOGE("open swap file failed when mkswap");
        return HDF_FAILURE;
    }
    int32_t retvalue = HDF_FAILURE;
    do {
        int pagesize = sysconf(_SC_PAGE_SIZE);
        if (pagesize == 0) {
            break;
        }
        unsigned int pages = (SWAP_FILE_SIZE / pagesize) - 1;
        char buff[SWAP_HEADER_BUF_LEN];
        uint32_t *swap = reinterpret_cast<uint32_t *>(buff);

        swap[0] = SWAP_HEADER_INFO_VERSION;
        swap[1] = pages;
        if (lseek(fd, SWAP_HEADER_INFO_BOOTBITS_SIZE, SEEK_SET) < 0) {
            HDF_LOGE("skip bootbits failed when mkswap.");
            break;
        }

        char *uuid = reinterpret_cast<char *>(swap + SWAP_HEADER_INFO_UUID_OFFSET);
        if (getrandom(uuid, UUID_BUF_LEN, GRND_RANDOM) != UUID_BUF_LEN) {
            HDF_LOGE("create uuid failed when mkswap.");
            break;
        }
        uuid[UUID_VERSION_OFFSET] = (uuid[UUID_VERSION_OFFSET] & UUID_VERSION_OPERAND1) | UUID_VERSION_OPERAND2;
        uuid[UUID_CLOCK_OFFSET] = (uuid[UUID_CLOCK_OFFSET] & UUID_CLOCK_OPERAND1) | UUID_CLOCK_OPERAND2;
        size_t len = SWAP_HEADER_SIZE * sizeof(uint32_t);
        auto ret = write(fd, swap, len);
        if (ret < 0 || static_cast<size_t>(ret) != len) {
            HDF_LOGE("write swap header info failed when mkswap.");
            break;
        }
        if (lseek(fd, pagesize - SWAP_HEADER_MAGIC_SIZE, SEEK_SET) < 0) {
            HDF_LOGE("seek magic of swap failed when mkswap");
            break;
        }
        if (write(fd, "SWAPSPACE2", SWAP_HEADER_MAGIC_SIZE) != SWAP_HEADER_MAGIC_SIZE) {
            HDF_LOGE("write magic of swap failed when mkswap");
            break;
        }
        fsync(fd);
        retvalue = HDF_SUCCESS;
        HDF_LOGI("mkswap success");
    } while (0);
    close(fd);
    return retvalue;
}

int32_t Hibernate::CheckSwapFile(bool &needToCreateSwapFile)
{
    needToCreateSwapFile = false;
    if (!IsSwapFileExist()) {
        needToCreateSwapFile = true;
        HDF_LOGI("CheckSwapFile, need to create swap file.");
        return HDF_SUCCESS;
    }
    bool isRightSize;
    if (CheckSwapFileSize(isRightSize) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    if (!isRightSize) {
        needToCreateSwapFile = true;
        HDF_LOGI("swapfile size was changed, will remove old swapfile.");
        if (RemoveSwapFile() != HDF_SUCCESS) {
            return HDF_FAILURE;
        }
    }
    HDF_LOGI("CheckSwapFile end.");
    return HDF_SUCCESS;
}

bool Hibernate::IsSwapFileExist()
{
    return access(SWAP_FILE_PATH, F_OK) == 0;
}

int32_t Hibernate::CheckSwapFileSize(bool &isRightSize)
{
    HDF_LOGI("CheckSwapFileSize begin.");
    struct stat swapFileStat;
    auto ret = stat(SWAP_FILE_PATH, &swapFileStat);
    if (ret != 0) {
        HDF_LOGE("stat swap file failed, errno=%{public}d", errno);
        return HDF_FAILURE;
    }

    isRightSize = true;
    if (swapFileStat.st_size != SWAP_FILE_SIZE) {
        HDF_LOGE("swap file size error, actual_size=%{public}lld expected_size=%{public}lld",
            static_cast<long long>(swapFileStat.st_size), static_cast<long long>(SWAP_FILE_SIZE));
        isRightSize = false;
    }
    HDF_LOGI("CheckSwapFileSize end.");
    return HDF_SUCCESS;
}

int32_t Hibernate::CreateSwapFile()
{
    HDF_LOGI("CreateSwapFile begin.");
    if (access(SWAP_DIR_PATH, F_OK) != 0) {
        HDF_LOGE("the swap dir not exist.");
        return HDF_FAILURE;
    }

    struct SwapfileCfg cfg;
    cfg.len = SWAP_FILE_SIZE;

    int fd = open(SWAP_FILE_PATH, O_RDONLY | O_LARGEFILE | O_EXCL | O_CREAT, SWAP_FILE_MODE);
    if (fd == -1) {
        HDF_LOGE("open swap file failed, errno=%{public}d", errno);
        return HDF_FAILURE;
    }
    int ret = ioctl(fd, HMFS_IOC_SWAPFILE_PREALLOC, &cfg);
    if (ret != 0) {
        HDF_LOGE("ioctl failed, ret=%{public}d", ret);
        close(fd);
        return HDF_FAILURE;
    }
    close(fd);
    HDF_LOGI("CreateSwapFile success.");
    return HDF_SUCCESS;
}

int32_t Hibernate::RemoveSwapFile()
{
    if (swapoff(SWAP_FILE_PATH) != 0) {
        HDF_LOGE("swap off failed when remove swap file, errno=%{public}d", errno);
    }

    if (remove(SWAP_FILE_PATH) != 0) {
        HDF_LOGE("remove swap file failed, errno=%{public}d", errno);
        return HDF_FAILURE;
    }

    HDF_LOGI("remove swap file success.");
    return HDF_SUCCESS;
}

int32_t Hibernate::EnableSwap()
{
    HDF_LOGI("swapon begin.");
    int ret = swapon(SWAP_FILE_PATH, 0);
    if (ret < 0) {
        HDF_LOGE("swapon failed, errno=%{public}d", errno);
        return HDF_FAILURE;
    }
    HDF_LOGI("swapon success.");
    return HDF_SUCCESS;
}

int32_t Hibernate::WriteOffsetAndResume()
{
    uint64_t resumeOffset;
    auto status = GetResumeOffset(resumeOffset);
    if (status != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    UniqueFd fd(TEMP_FAILURE_RETRY(open(HIBERNATE_RESUME, O_RDWR | O_CLOEXEC)));
    if (fd < 0) {
        HDF_LOGE("write offset and resume error, fd < 0, errno=%{public}d", errno);
        return HDF_FAILURE;
    }

    std::string offsetResume = std::to_string(resumeOffset) + ":" + RESUME;
    HDF_LOGI("offsetResume=%{public}s", offsetResume.c_str());

    bool ret = SaveStringToFd(fd, offsetResume.c_str());
    if (!ret) {
        HDF_LOGE("WriteOffsetAndResume fail");
        return HDF_FAILURE;
    }
    HDF_LOGI("WriteOffsetAndResume end");
    return HDF_SUCCESS;
}

int32_t Hibernate::WriteOffset()
{
    uint64_t resumeOffset;
    auto status = GetResumeOffset(resumeOffset);
    if (status != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    UniqueFd fd(TEMP_FAILURE_RETRY(open(SYS_POWER_RESUME_OFFSET, O_RDWR | O_CLOEXEC)));
    if (fd < 0) {
        HDF_LOGE("write offset error, fd < 0, errno=%{public}d", errno);
        return HDF_FAILURE;
    }

    std::string offset = std::to_string(resumeOffset);

    bool ret = SaveStringToFd(fd, offset.c_str());
    if (!ret) {
        HDF_LOGE("WriteOffset fail");
        return HDF_FAILURE;
    }
    HDF_LOGI("WriteOffset end");
    return HDF_SUCCESS;
}

int32_t Hibernate::WriteResume()
{
    UniqueFd fd(TEMP_FAILURE_RETRY(open(SYS_POWER_RESUME, O_RDWR | O_CLOEXEC)));
    if (fd < 0) {
        HDF_LOGE("write resume error, fd < 0, errno=%{public}d", errno);
        return HDF_FAILURE;
    }

    bool ret = SaveStringToFd(fd, RESUME);
    if (!ret) {
        HDF_LOGE("WriteResume fail");
        return HDF_FAILURE;
    }

    HDF_LOGI("WriteResume end");
    return HDF_SUCCESS;
}

int32_t Hibernate::WritePowerState()
{
    UniqueFd fd(TEMP_FAILURE_RETRY(open(HIBERNATE_STATE_PATH, O_RDWR | O_CLOEXEC)));
    if (fd < 0) {
        HDF_LOGE("WritePowerState error, fd < 0, errno=%{public}d", errno);
        return HDF_FAILURE;
    }

    bool ret = SaveStringToFd(fd, HIBERNATE_STATE);
    if (!ret) {
        HDF_LOGE("WritePowerState fail");
        return HDF_FAILURE;
    }

    HDF_LOGE("WritePowerState end");
    return HDF_SUCCESS;
}

int32_t Hibernate::DoHibernate()
{
    InitSwap();
    if (EnableSwap() != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    if (WriteResume() != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    if (WriteOffset() != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    if (WritePowerState() != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    if (swapoff(SWAP_FILE_PATH) != 0) {
        HDF_LOGE("swap off failed, errno=%{public}d", errno);
    }
    return HDF_SUCCESS;
}

int32_t Hibernate::GetResumeOffset(uint64_t &resumeOffset)
{
    int fd = open(SWAP_FILE_PATH, O_RDONLY);
    if (fd < 0) {
        HDF_LOGE("open swap file failed, errno=%{public}d", errno);
        return HDF_FAILURE;
    }

    struct stat fileStat;
    int rc = stat(SWAP_FILE_PATH, &fileStat);
    if (rc != 0) {
        HDF_LOGE("stat swap file failed, errno=%{public}d", errno);
        close(fd);
        return HDF_FAILURE;
    }

    __u64 buf[FILE_MAP_BUF_LEN];
    unsigned long flags = 0;
    struct fiemap *swapFileFiemap = reinterpret_cast<struct fiemap *>(buf);
    struct fiemap_extent *swapFileFmExt = &swapFileFiemap->fm_extents[0];
    int count = (sizeof(buf) - sizeof(*swapFileFiemap)) / sizeof(struct fiemap_extent);

    if (memset_s(swapFileFiemap, sizeof(buf), 0, sizeof(struct fiemap)) != EOK) {
        close(fd);
        return HDF_FAILURE;
    }

    swapFileFiemap->fm_length = ~0ULL;
    swapFileFiemap->fm_flags = flags;
    swapFileFiemap->fm_extent_count = count;

    rc = ioctl(fd, FS_IOC_FIEMAP, reinterpret_cast<unsigned long>(swapFileFiemap));
    if (rc != 0) {
        HDF_LOGE("get swap file physical blk fail, rc=%{public}d", rc);
        close(fd);
        return HDF_FAILURE;
    }

    resumeOffset = swapFileFmExt[0].fe_physical >> UlongLen(fileStat.st_blksize);
    HDF_LOGI("resume offset size: %{public}lld", static_cast<long long>(resumeOffset));
    close(fd);
    return HDF_SUCCESS;
}
} // namespace V1_2
} // namespace Power
} // namespace HDI
} // namespace OHOS
