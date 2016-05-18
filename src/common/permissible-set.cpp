/*
 *  Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
 */
/*
 * @file        permissible-set.cpp
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @author      Radoslaw Bartosiak <r.bartosiak@samsung.com>
 * @version     1.0
 * @brief       Implementation of API for adding, deleting and reading permissible labels
 */
#ifndef _GNU_SOURCE //for TEMP_FAILURE_RETRY
#define _GNU_SOURCE
#endif

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <string>
#include <sys/file.h>
#include <unistd.h>

#include <config.h>
#include <dpl/errno_string.h>
#include <dpl/fstream_accessors.h>
#include <dpl/log/log.h>
#include <permissible-set.h>
#include <privilege_db.h>
#include <security-manager-types.h>
#include <smack-labels.h>

namespace SecurityManager {
namespace PermissibleSet {

template <typename T>
static inline int getFd(T &fstream)
{
    return DPL::FstreamAccessors<T>::GetFd(fstream);
}

template <typename T>
static void openAndLockLabelFile(const std::string &labelFile, T &fstream)
{
    fstream.open(labelFile);
    if (!fstream.is_open()) {
        LogError("Unable to open file " << labelFile << ": " << GetErrnoString(errno));
        // throw
    }

    if (TEMP_FAILURE_RETRY(flock(getFd(fstream), LOCK_EX)) == -1) {
        LogError("Unable to lock file " << labelFile << ": " << GetErrnoString(errno));
        // throw
    }
}

void getUserAppLabels(const uid_t uid, std::vector<std::string> &appLabels)
 {
     PrivilegeDb::getInstance().GetUserApps(uid, appLabels);
     std::transform(appLabels.begin(), appLabels.end(), appLabels.begin(),
             SmackLabels::generateAppLabel);
 }

bool updatePermissibleFile(const uid_t user, const int installationType)
{
    std::string labelFile;
    if ((installationType == SM_APP_INSTALL_GLOBAL)
            || (installationType == SM_APP_INSTALL_PRELOADED)) {
        labelFile = Config::SMACK_APPS_LABELS_GLOBAL_FILE;
    } else if (installationType == SM_APP_INSTALL_LOCAL) {
        labelFile = Config::SMACK_APPS_LABELS_USER_FILE_PREFIX
                + std::to_string(user);
    } else {
        LogError("Installation type: unknown");
        return false;
    }

    std::ofstream fstream;
    openAndLockLabelFile(labelFile, fstream);

    std::vector<std::string> appLabels;
    getUserAppLabels(user, appLabels);
    for (const auto label : appLabels) {
        fstream << label << std::endl;
        if (fstream.bad()) {
            LogError("I/O error during write to file " << labelFile);
            // throw
        }
    }

    if (fstream.flush().fail()) {
        LogError("Error flushing file " << labelFile);
        // throw
    }

    if (TEMP_FAILURE_RETRY(fsync(getFd(fstream))) == -1) {
        LogError("Error fsync on file " << labelFile);
        // throw
    }

    return true;
}

lib_retcode readLabelsFromPermissibleFile(const std::string &labelFile,
        std::vector<std::string> &labels)
{
    std::ifstream fstream;
    openAndLockLabelFile(labelFile, fstream);

    std::string line;
    while (std::getline(fstream, line))
        labels.push_back(line);

    return SECURITY_MANAGER_SUCCESS;
}

} // PermissibleSet
} // SecurityManager
