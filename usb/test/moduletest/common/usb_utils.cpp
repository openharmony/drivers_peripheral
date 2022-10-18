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

#include "usb_utils.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sys/time.h>

using namespace std;

bool HasLog(const string &target, double startTs, const string &file)
{
    bool ret = false;
    ifstream logFile(file);
    string::size_type pos;
    string lineStr;
    const string flagStr = "[XTSCHECK]";
    const int32_t tsStartPos = 11;
    const int32_t tsLength = 17;
    while (getline(logFile, lineStr)) {
        double logTs;
        pos = lineStr.find(flagStr);
        if (pos == string::npos) {
            lineStr.clear();
            continue;
        }
        logTs = stod(lineStr.substr(pos + tsStartPos, tsLength));
        if ((logTs - startTs) >= 0) {
            if (lineStr.find(target) != string::npos) {
                ret = true;
            }
        }
        lineStr.clear();
    }
    logFile.close();
    return ret;
}

double GetNowTs(void)
{
    const double transUsecNum = 1000000.0;
    timeval tv = {0};
    gettimeofday(&tv, nullptr);
    return (tv.tv_sec + tv.tv_usec / transUsecNum);
}

char *ParseSysCmdResult(FILE &result, int32_t line, int32_t word)
{
    char s[1024];
    char *pch = nullptr;
    int32_t lineCnt = 1;
    int32_t wordCnt = 1;
    while (1) {
        if (fgets(s, sizeof(s), &result) == nullptr) {
            break;
        }
        pch = strtok(s, " ");
        while (pch != nullptr) {
            if (lineCnt == line && wordCnt == word) {
                return pch;
            }
            pch = strtok(nullptr, " ");
            wordCnt++;
        }
        lineCnt++;
        wordCnt = 1;
    }
    return pch;
}

static void ParseFile(char *pch, struct ParseProcInfo &pinfo)
{
    while (pch != nullptr) {
        if (strstr(pch, "VmRSS")) {
            pch = strtok(nullptr, " ");
            pinfo.ramCur = stod(pch);
            pinfo.ramCount += 1;
            pinfo.ramTotal += pinfo.ramCur;
            if (pinfo.ramCur > pinfo.ramPeak) {
                pinfo.ramPeak = pinfo.ramCur;
            }
            break;
        }
        if (strstr(pch, "Cpu")) {
            pch = strtok(nullptr, " ");
            pinfo.cpuCur = stod(pch);
            pinfo.cpuCount += 1;
            pinfo.cpuTotal += pinfo.cpuCur;
            if (pinfo.cpuCur > pinfo.cpuPeak) {
                pinfo.cpuPeak = pinfo.cpuCur;
            }
            break;
        }
        if (strstr(pch, "Threads")) {
            pch = strtok(nullptr, " ");
            pinfo.threadCur = stoi(pch);
            if (pinfo.threadCur > pinfo.threadPeak) {
                pinfo.threadPeak = pinfo.threadCur;
            }
            break;
        }
        pch = strtok(nullptr, " ");
    }
}

void CalcProcInfoFromFile(struct ProcInfo &info, const string &file)
{
    char s[100];
    struct ParseProcInfo pinfo = {0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0, 0, 0, 0};

    FILE *fp = fopen(file.c_str(), "r");
    if (!fp) {
        printf("%s:%d file open failed.", __func__, __LINE__);
        return;
    }
    while (1) {
        if (fgets(s, sizeof(s), fp) == nullptr) {
            break;
        }
        ParseFile(strtok(s, " \t"), pinfo);
    }

    if (pinfo.ramCount == 0 || pinfo.cpuCount == 0) {
        (void)fclose(fp);
        return;
    }
    info.ramPeak = pinfo.ramPeak;
    info.ramAvg = pinfo.ramTotal / pinfo.ramCount;
    info.cpuPeak = pinfo.cpuPeak;
    info.cpuAvg = pinfo.cpuTotal / pinfo.cpuCount;
    info.threadPeak = pinfo.threadPeak;
    
    (void)fclose(fp);
    return;
}

double GetTsFromLog(const string &target, double startTs, const string &file)
{
    double logTs;
    ifstream logFile(file);
    string lineStr;
    const int32_t tsStartPos = 11;
    const int32_t tsLength = 17;
    while (getline(logFile, lineStr)) {
        if (lineStr.find(target) != string::npos) {
            logTs = stod(lineStr.substr(tsStartPos, tsLength));
            if ((logTs - startTs) >= 0) {
                return logTs;
            }
        }
        lineStr.clear();
    }
    logFile.close();
    return 0;
}
