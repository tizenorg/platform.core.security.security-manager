/*
 *  Copyright (c) 2000 - 2016 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Rafal Krypa <r.krypa@samsung.com>
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
 *  Security Manager NSS library
 */
/*
 * @file        nss_securitymanager.cpp
 * @author      Aleksander Zdyb <a.zdyb@samsung.com>
 * @version     1.0
 * @brief       This file contains NSS library implementation for Security Manager
 */

#include <cerrno>
#include <cstddef>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <nss.h>

#include <security-manager.h>

extern "C" {

__attribute__((visibility("default")))
enum nss_status _nss_securitymanager_initgroups_dyn(const char *user, gid_t group, long int *start,
                                                    long int *size, gid_t **groupsp,
                                                    long int limit, int *errnop) {

    /* TODO:
     * 1. [IMPORTANT] Check sizes and limits
     * 2. Check again meaning of retcodes and errno in NSS
     * 3. Introduce some logging
     */

    (void) group;
    (void) size;
    (void) limit;

    auto pwnam = getpwnam(user);
    if (pwnam == nullptr) {
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }

    char **groups;
    std::size_t groupsCount;
    int ret = security_manager_groups_for_uid(pwnam->pw_uid, &groups, &groupsCount);

    if (ret != SECURITY_MANAGER_SUCCESS && ret != SECURITY_MANAGER_ERROR_NO_SUCH_OBJECT) {
        *errnop = ENOENT;
        return NSS_STATUS_UNAVAIL;
    }

    // If user is not managed by Security Manager, we want to apply all the groups
    if (ret == SECURITY_MANAGER_ERROR_NO_SUCH_OBJECT) {
        ret = security_manager_groups_get(&groups, &groupsCount);
    }

    if (ret != SECURITY_MANAGER_SUCCESS) {
        *errnop = ENOENT;
        return NSS_STATUS_UNAVAIL;
    }

    for (auto i = 0u; i < groupsCount; ++i) {
        auto grnam = getgrnam(groups[i]);

        if (grnam == nullptr) {
            *errnop = ENOENT;
            return NSS_STATUS_NOTFOUND;
        }

        (*groupsp)[*start] = grnam->gr_gid;
        *start = *start + 1;
    }

    return NSS_STATUS_SUCCESS;
}

} /* extern "C" */