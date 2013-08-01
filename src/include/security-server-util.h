/*
 *  security-server
 *
 *  Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Bumjin Im <bj.im@samsung.com>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 *
 */

#ifndef SECURITY_SERVER_UTIL_H
#define SECURITY_SERVER_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "security-server-common.h"
int util_smack_label_is_valid(const char *smack_label);
char *read_exe_path_from_proc(pid_t pid);
int authorize_SS_API_caller_socket(int sockfd, char *required_API_label, char *required_rule);

#ifdef __cplusplus
}
#endif

#endif /*SECURITY_SERVER_UTIL_H*/
