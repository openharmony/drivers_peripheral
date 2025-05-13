/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "thermal_dfx.h"
#include <cerrno>
#include <cstdio>
#include <deque>
#include <dirent.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>
#include <hdf_log.h>
#include <hdf_base.h>

#include "directory_ex.h"
#include <datetime_ex.h>
#ifdef DATA_SIZE_HISYSEVENT_ENABLE
#include "hisysevent.h"
#endif
#include "param_wrapper.h"
#include "parameter.h"
#include "securec.h"
#include "string_ex.h"
#include "sysparam_errno.h"
#include "thermal_hdf_utils.h"
#ifdef THERMAL_HITRACE_ENABLE
#include "hitrace_meter.h"
#endif
#include "thermal_log.h"
#include "thermal_zone_manager.h"
#include "zlib.h"

namespace OHOS {
namespace HDI {
namespace Thermal {
namespace V1_1 {
namespace {
constexpr uint8_t LOG_INDEX_LEN = 4;
constexpr int32_t MAX_FILE_NUM = 10;
constexpr long int MAX_FILE_SIZE = 10 * 1024 * 1024;
constexpr int32_t MAX_TIME_LEN = 20;
constexpr int32_t TIME_FORMAT_1 = 1;
constexpr int32_t TIME_FORMAT_2 = 2;
constexpr int32_t COMPRESS_READ_BUF_SIZE = 4096;
constexpr int32_t DEFAULT_WIDTH = 20;
constexpr int32_t DEFAULT_INTERVAL = 5000;
constexpr int32_t MIN_INTERVAL = 100;
constexpr int64_t TWENTY_FOUR_HOURS = 60 * 60 * 24 * 1000;
const std::string TIMESTAMP_TITLE = "timestamp";
const std::string THERMAL_LOG_ENABLE = "persist.thermal.log.enable";
const std::string THERMAL_LOG_WIDTH = "persist.thermal.log.width";
const std::string THERMAL_LOG_INTERVAL = "persist.thermal.log.interval";
const std::string DATA_FILE_PATH = "/data";
uint32_t g_currentLogIndex = 0;
bool g_firstReport = true;
bool g_firstCreate = true;
std::deque<std::string> g_saveLogFile;
std::string g_outPath = "";
std::string g_logTime = "";
}

std::shared_ptr<ThermalDfx> ThermalDfx::instance_ = nullptr;
std::mutex ThermalDfx::mutexInstance_;

ThermalDfx& ThermalDfx::GetInstance()
{
    std::lock_guard<std::mutex> lock(mutexInstance_);
    if (instance_ == nullptr) {
        instance_ = std::make_shared<ThermalDfx>();
    }
    return *(instance_.get());
}

void ThermalDfx::DestroyInstance()
{
    std::lock_guard<std::mutex> lock(mutexInstance_);
    instance_ = nullptr;
}

static std::string GetCurrentTime(const int32_t format)
{
    struct tm* pTime;
    char strTime[MAX_TIME_LEN] = {0};
    time_t t;
    if (time(&t) == -1) {
        THERMAL_HILOGW(COMP_HDI, "call time failed");
        return "";
    }

    pTime = localtime(&t);
    if (pTime == nullptr) {
        THERMAL_HILOGW(COMP_HDI, "pTime Get localtime failed");
        return "";
    }
    if (format == TIME_FORMAT_1) {
        if (strftime(strTime, sizeof(strTime), "%Y%m%d-%H%M%S", pTime) == 0U) {
            THERMAL_HILOGW(COMP_HDI, "call strfime failed");
            return "";
        }
    } else if (format == TIME_FORMAT_2) {
        if (strftime(strTime, sizeof(strTime), "%Y-%m-%d %H:%M:%S", pTime) == 0U) {
            THERMAL_HILOGW(COMP_HDI, "call strfime failed");
            return "";
        }
    } else {
        THERMAL_HILOGW(COMP_HDI, "invalid format value");
        return "";
    }
    return strTime;
}

ThermalDfx::ThermalDfx() :
    width_(static_cast<uint8_t>(DEFAULT_WIDTH)), interval_(static_cast<uint32_t>(DEFAULT_INTERVAL)), enable_(true)
{
}

ThermalDfx::~ThermalDfx()
{
    enable_ = false;
}

std::string ThermalDfx::GetFileNameIndex(const uint32_t index)
{
    char res[LOG_INDEX_LEN];
    (void)snprintf_s(res, sizeof(res), sizeof(res) - 1, "%03d", index % MAX_FILE_NUM);
    std::string fileNameIndex(res);
    return fileNameIndex;
}

std::string ThermalDfx::CanonicalizeSpecPath(const char* src)
{
    if (src == nullptr || strlen(src) >= PATH_MAX) {
        fprintf(stderr, "Error: CanonicalizeSpecPath %s failed", src);
        return "";
    }
    char resolvedPath[PATH_MAX] = { 0 };
    if (access(src, F_OK) == 0) {
        if (realpath(src, resolvedPath) == nullptr) {
            fprintf(stderr, "Error: realpath %s failed", src);
            return "";
        }
    } else {
        std::string fileName(src);
        if (fileName.find("..") == std::string::npos) {
            if (snprintf_s(resolvedPath, PATH_MAX, sizeof(resolvedPath) - 1, src) == -1) {
                fprintf(stderr, "Error: sprintf_s %s failed", src);
                return "";
            }
        } else {
            fprintf(stderr, "Error: find .. %s failed", src);
            return "";
        }
    }

    std::string res(resolvedPath);
    return res;
}

bool ThermalDfx::Compress(const std::string& dataFile, const std::string& destFile)
{
    std::string resolvedPath = CanonicalizeSpecPath(dataFile.c_str());
    FILE* fp = fopen(resolvedPath.c_str(), "rb");
    if (fp == nullptr) {
        THERMAL_HILOGE(COMP_HDI, "Fail to open data file %{public}s", dataFile.c_str());
        perror("Fail to fopen(rb)");
        return false;
    }

    std::unique_ptr<gzFile_s, decltype(&gzclose)> fgz(gzopen(destFile.c_str(), "wb"), gzclose);
    if (fgz == nullptr) {
        THERMAL_HILOGE(COMP_HDI, "Fail to call gzopen(%{public}s)", destFile.c_str());
        fclose(fp);
        return false;
    }

    std::vector<char> buf(COMPRESS_READ_BUF_SIZE);
    size_t len = 0;
    while ((len = fread(buf.data(), sizeof(uint8_t), buf.size(), fp))) {
        if (gzwrite(fgz.get(), buf.data(), len) == 0) {
            THERMAL_HILOGE(COMP_HDI, "Fail to call gzwrite for %{public}zu bytes", len);
            fclose(fp);
            return false;
        }
    }
    if (!feof(fp)) {
        if (ferror(fp) != 0) {
            THERMAL_HILOGE(COMP_HDI, "ferror return err");
            fclose(fp);
            return false;
        }
    }
    if (fclose(fp) < 0) {
        return false;
    }
    return true;
}

void ThermalDfx::CompressFile()
{
#ifdef THERMAL_HITRACE_ENABLE
    HitraceScopedEx trace(HITRACE_LEVEL_COMMERCIAL, HITRACE_TAG_POWER, "ThermalDfx_CompressFile");
#endif
    THERMAL_HILOGD(COMP_HDI, "CompressFile start");
    std::string unCompressFile = g_outPath + "/" + "thermal." + GetFileNameIndex(g_currentLogIndex) + "." + g_logTime;

    FILE* fp = fopen(unCompressFile.c_str(), "rb");
    if (fp == nullptr) {
        THERMAL_HILOGE(COMP_HDI, "open uncompressfile failed");
        return;
    }

    if (fseek(fp, SEEK_SET, SEEK_END) != 0) {
        THERMAL_HILOGE(COMP_HDI, "fseek() failed");
        fclose(fp);
        return;
    }

    long int size = ftell(fp);
    if (size < MAX_FILE_SIZE) {
        if (fclose(fp) < 0) {
            THERMAL_HILOGW(COMP_HDI, "fclose() failed");
        }
        THERMAL_HILOGD(COMP_HDI, "file is not enough for compress");
        return;
    }
    if (fclose(fp) < 0) {
        THERMAL_HILOGW(COMP_HDI, "fclose() failed");
    }

    std::string compressFile =
        g_outPath + "/" + "thermal." + GetFileNameIndex(g_currentLogIndex) + "." + g_logTime + ".gz";
    if (!Compress(unCompressFile, compressFile)) {
        THERMAL_HILOGE(COMP_HDI, "CompressFile fail");
        return;
    }

    if (remove(unCompressFile.c_str()) != 0) {
        THERMAL_HILOGW(COMP_HDI, "failed to remove file %{public}s", unCompressFile.c_str());
    }

    if (g_saveLogFile.size() >= MAX_FILE_NUM) {
        if (remove(g_saveLogFile.front().c_str()) != 0) {
            THERMAL_HILOGW(COMP_HDI, "failed to remove file %{public}s", compressFile.c_str());
        }
        g_saveLogFile.pop_front();
    }
    g_saveLogFile.push_back(compressFile);
    g_currentLogIndex++;
    g_logTime = GetCurrentTime(TIME_FORMAT_1);
    THERMAL_HILOGD(COMP_HDI, "CompressFile done");
}

bool ThermalDfx::PrepareWriteDfxLog()
{
    if (g_outPath == "") {
        THERMAL_HILOGW(COMP_HDI, "parse thermal_hdi_config.xml outpath fail");
        return false;
    }
    if (!enable_) {
        THERMAL_HILOGD(COMP_HDI, "param does not start recording");
        return false;
    }

    return true;
}

void ThermalDfx::CreateLogFile()
{
#ifdef THERMAL_HITRACE_ENABLE
    HitraceScopedEx trace(HITRACE_LEVEL_COMMERCIAL, HITRACE_TAG_POWER, "ThermalDfx_CreateLogFile");
#endif
    THERMAL_HILOGD(COMP_HDI, "CreateLogFile start");
    if (!PrepareWriteDfxLog()) {
        THERMAL_HILOGD(COMP_HDI, "prepare write dfx log failed");
        return;
    }
    if (g_firstCreate) {
        g_currentLogIndex = 0;
        g_logTime = GetCurrentTime(TIME_FORMAT_1);
        g_firstCreate = false;
    }
    std::string logFile = g_outPath + "/" + "thermal." + GetFileNameIndex(g_currentLogIndex) +
        "." + g_logTime;
    if (access(g_outPath.c_str(), 0) == -1) {
        auto ret = ForceCreateDirectory(g_outPath.c_str());
        if (!ret) {
            THERMAL_HILOGE(COMP_HDI, "create output dir failed");
            return;
        }
    }

    bool isEmpty = false;
    std::ifstream fin(logFile);
    std::fstream file;
    file.open(logFile, std::ios::in);
    if (file.eof() || !fin) {
        isEmpty = true;
    }
    file.close();

    ProcessLogInfo(logFile, isEmpty);
    THERMAL_HILOGD(COMP_HDI, "CreateLogFile done");
}

void ThermalDfx::ProcessLogInfo(std::string& logFile, bool isEmpty)
{
    std::string currentTime = GetCurrentTime(TIME_FORMAT_2);
    std::ofstream wStream(logFile, std::ios::app);
    if (wStream.is_open()) {
        if (isEmpty) {
            WriteToEmptyFile(wStream, currentTime);
            return;
        }

        WriteToFile(wStream, currentTime);
        wStream.close();
    }
}

void ThermalDfx::WriteToEmptyFile(std::ofstream& wStream, std::string& currentTime)
{
    wStream << TIMESTAMP_TITLE;
    for (uint8_t i = 0; i < width_; ++i) {
        wStream << " ";
    }
    std::vector<DfxTraceInfo> logInfo = ThermalHdfConfig::GetInstance().GetTracingInfo();
    for (const auto& info : logInfo) {
        wStream << info.title;
        if (info.valuePath == logInfo.back().valuePath && info.title == logInfo.back().title) {
            break;
        }
        for (uint8_t i = 0; i < width_ - info.title.length(); ++i) {
            wStream << " ";
        }
    }
    wStream << "\n";

    WriteToFile(wStream, currentTime);
    wStream.close();
}

void ThermalDfx::WriteToFile(std::ofstream& wStream, std::string& currentTime)
{
    wStream << currentTime;
    for (uint8_t i = 0; i < width_ + TIMESTAMP_TITLE.length() - currentTime.length(); ++i) {
        wStream << " ";
    }
    std::vector<DfxTraceInfo>& logInfo = ThermalHdfConfig::GetInstance().GetTracingInfo();
    std::string value;
    for (const auto& info : logInfo) {
        if (!ThermalHdfUtils::ReadNode(info.valuePath, value)) {
            THERMAL_HILOGW(COMP_HDI, "Read node failed, title = %{public}s", info.title.c_str());
        }
        wStream << value;
        if (info.valuePath == logInfo.back().valuePath && info.title == logInfo.back().title) {
            break;
        }
        for (uint8_t i = 0; i < width_ - value.length(); ++i) {
            wStream << " ";
        }
    }
    wStream << "\n";
}

void ThermalDfx::InfoChangedCallback(const char* key, const char* value, void* context)
{
    if (key == nullptr || value == nullptr) {
        return;
    }
    std::string keyStr(key);
    std::string valueStr(value);
    THERMAL_HILOGI(COMP_HDI, "thermal log param change, key = %{public}s, value = %{public}s", keyStr.c_str(),
        valueStr.c_str());
    auto& thermalDfx = ThermalDfx::GetInstance();
    if (keyStr == THERMAL_LOG_ENABLE) {
        thermalDfx.EnableWatchCallback(valueStr);
    }
    if (keyStr == THERMAL_LOG_WIDTH) {
        thermalDfx.WidthWatchCallback(valueStr);
    }
    if (keyStr == THERMAL_LOG_INTERVAL) {
        thermalDfx.IntervalWatchCallback(valueStr);
    }
}

void ThermalDfx::WidthWatchCallback(const std::string& value)
{
    int32_t width = OHOS::StrToInt(value, width) ? width : DEFAULT_WIDTH;
    width_ = static_cast<uint8_t>((width < DEFAULT_WIDTH) ? DEFAULT_WIDTH : width);
}

void ThermalDfx::IntervalWatchCallback(const std::string& value)
{
    int32_t interval = OHOS::StrToInt(value, interval) ? interval : DEFAULT_INTERVAL;
    interval_ = static_cast<uint32_t>((interval < MIN_INTERVAL) ? MIN_INTERVAL : interval);
}

void ThermalDfx::EnableWatchCallback(const std::string& value)
{
    enable_ = (value == "true");
}

int32_t ThermalDfx::GetIntParameter(const std::string& key, const int32_t def, const int32_t minValue)
{
    int32_t value = OHOS::system::GetIntParameter(key, def);
    return (value < minValue) ? def : value;
}

bool ThermalDfx::GetBoolParameter(const std::string& key, const bool def)
{
    std::string value;
    if (OHOS::system::GetStringParameter(THERMAL_LOG_ENABLE, value) != 0) {
        return def;
    }
    return (value == "true");
}

uint32_t ThermalDfx::GetInterval()
{
    return interval_;
}

double ThermalDfx::GetDeviceValidSize(const std::string& path)
{
    struct statfs stat;
    if (statfs(path.c_str(), &stat) != 0) {
        return 0;
    }
    constexpr double units = 1024.0;
    return (static_cast<double>(stat.f_bfree) / units) * (static_cast<double>(stat.f_bsize) / units);
}

uint64_t ThermalDfx::GetDirectorySize(const std::string& directoryPath)
{
    uint64_t totalSize = 0;
    DIR* dir = opendir(directoryPath.c_str());
    if (dir == nullptr) {
        THERMAL_HILOGE(COMP_HDI, "Failed to open directory: %{public}s, errno = %{public}d",
            directoryPath.c_str(), errno);
        return totalSize;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        std::string filePath = directoryPath + "/" + entry->d_name;
        struct stat fileStat;
        if (stat(filePath.c_str(), &fileStat) == 0) {
            totalSize += fileStat.st_size;
        }
    }

    closedir(dir);
    return totalSize;
}

void ThermalDfx::WriteDataHisysevent()
{
    THERMAL_HILOGD(COMP_HDI, "Report data hisysevent, g_outPath: %{public}s", g_outPath.c_str());
#ifdef DATA_SIZE_HISYSEVENT_ENABLE
    uint64_t remainSize = static_cast<uint64_t>(GetDeviceValidSize(DATA_FILE_PATH));
    uint64_t fileSize = GetDirectorySize(g_outPath);
    HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::FILEMANAGEMENT, "USER_DATA_SIZE",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "COMPONENT_NAME", "drivers_peripheral_thermal",
        "PARTITION_NAME", DATA_FILE_PATH,
        "REMAIN_PARTITION_SIZE", remainSize,
        "FILE_OR_FOLDER_PATH", g_outPath,
        "FILE_OR_FOLDER_SIZE", fileSize);
#endif
}

void ThermalDfx::ReportDataHisysevent()
{
    if (g_firstReport) {
        WriteDataHisysevent();
        beginTimeMs_ = GetTickCount();
        g_firstReport = false;
        return;
    }
    int64_t endTimeMs = GetTickCount();
    if (endTimeMs - beginTimeMs_ >= TWENTY_FOUR_HOURS) {
        WriteDataHisysevent();
        beginTimeMs_ = endTimeMs;
    }
}

void ThermalDfx::DoWork()
{
    if (enable_) {
        CreateLogFile();
        CompressFile();
#ifdef DATA_SIZE_HISYSEVENT_ENABLE
        ReportDataHisysevent();
#endif
    }
}

void ThermalDfx::Init()
{
    beginTimeMs_ = GetTickCount();
    interval_ = static_cast<uint32_t>(GetIntParameter(THERMAL_LOG_INTERVAL, DEFAULT_INTERVAL, MIN_INTERVAL));
    width_ = static_cast<uint8_t>(GetIntParameter(THERMAL_LOG_WIDTH, DEFAULT_WIDTH, DEFAULT_WIDTH));
    enable_ = GetBoolParameter(THERMAL_LOG_ENABLE, true);
    THERMAL_HILOGI(COMP_HDI,
        "The thermal log param is init, interval_ = %{public}d, width = %{public}d, enable = %{public}d",
        interval_.load(), width_.load(), enable_.load());

    WatchParameter(THERMAL_LOG_ENABLE.c_str(), InfoChangedCallback, nullptr);
    WatchParameter(THERMAL_LOG_WIDTH.c_str(), InfoChangedCallback, nullptr);
    int32_t code = WatchParameter(THERMAL_LOG_INTERVAL.c_str(), InfoChangedCallback, nullptr);
    if (code != OHOSStartUpSysParamErrorCode::EC_SUCCESS) {
        THERMAL_HILOGW(COMP_HDI, "thermal log watch parameters failed. error = %{public}d", code);
    }

    XmlTraceConfig& config = ThermalHdfConfig::GetInstance().GetXmlTraceConfig();
    g_outPath = config.outPath;
}
} // V1_1
} // Thermal
} // HDI
} // OHOS
