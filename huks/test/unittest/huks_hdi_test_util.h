/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HUKS_HDI_TEST_UTIL_H
#define HUKS_HDI_TEST_UTIL_H

#define HUKS_TEST_LOG_E(fmt...) \
do { \
    printf("[ERROR]\t[%s](%d): ", __func__, __LINE__); \
    printf(fmt); \
    printf("\r\n"); \
} while (0)

#define HUKS_TEST_LOG_I(fmt...) \
do { \
    printf("[INFO]\t[%s](%d): ", __func__, __LINE__); \
    printf(fmt); \
    printf("\r\n"); \
} while (0)

#define HUKS_TEST_LOG_W(fmt...) \
do { \
    printf("[WARN]\t[%s](%d): ", __func__, __LINE__); \
    printf(fmt); \
    printf("\r\n"); \
} while (0)

#define HUKS_TEST_LOG_D(fmt...) \
do { \
    printf("[DEBUG]\t[%s](%d): ", __func__, __LINE__); \
    printf(fmt); \
    printf("\r\n"); \
} while (0)

#endif /* HUKS_HDI_TEST_UTIL_H */