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

#ifndef LIB_ACM_TEST_H
#define LIB_ACM_TEST_H

extern "C" {
void AcmOpen();
void AcmClose();
void AcmWrite(char *data);
void AcmRead(char *str, int32_t timeout = 5);
void acm_prop_regist(const char *propName, const char *propValue);
void acm_prop_write(const char *propName, const char *propValue);
void acm_prop_read(const char *propName, char *propValue);
}
#endif /* LIB_ACM_TEST_H */
