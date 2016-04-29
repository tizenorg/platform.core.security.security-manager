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
#include <memory>
#include <string>
#include <sys/file.h>
#include <unistd.h>

#include <config.h>
#include <dpl/errno_string.h>
#include <dpl/log/log.h>
#include <permissible-set.h>
#include <privilege_db.h>
#include <security-manager-types.h>
#include <smack-labels.h>

typedef std::unique_ptr<FILE, int (*)(FILE *)> filePtr;

namespace SecurityManager {
namespace PermissibleSet {

static filePtr openAndLockLabelFile(const std::string &labelFile, const char* mode)
{
    filePtr file(fopen(labelFile.c_str(), mode), fclose);
    if (!file) {
        LogError("Unable to open file " << labelFile << ": " << GetErrnoString(errno));
        return filePtr(nullptr, nullptr);
    }

    int ret = TEMP_FAILURE_RETRY(flock(fileno(file.get()), LOCK_EX));
    if (ret == -1) {
        LogError("Unable to lock file " << labelFile << ": " << GetErrnoString(errno));
        return filePtr(nullptr, nullptr);
    }
    return file;
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
    filePtr file = openAndLockLabelFile(labelFile, "w");
    if (!file) {
        LogError("Unable to open file "<< GetErrnoString(errno));
        return false;
    }
    std::vector<std::string> appLabels;
    getUserAppLabels(user, appLabels);
    for (auto label : appLabels) {
        if (fprintf(file.get(), "%s\n", label.c_str()) < 0) {
            LogError("Unable to fprintf() to file " << labelFile << ": " << GetErrnoString(errno));
            return false;
        }
    }
    return true;
}

lib_retcode readLabelsFromPermissibleFile(const std::string &labelFile,
        std::vector<std::string> &labels)
{
    filePtr file = openAndLockLabelFile(labelFile, "r");
    int ret;
    do {
        char *buf = nullptr;
        std::size_t bufSize = 0;
        switch (ret = getline(&buf, &bufSize, file.get())) {
        case 0:
            continue;
        case -1:
            if (feof(file.get()))
                break;
            LogError("Failure while reading file " << labelFile << ": " << GetErrnoString(errno));
            return SECURITY_MANAGER_ERROR_FILE_OPEN_FAILED;
        default:
            std::unique_ptr<char, decltype(free)*> buf_up(buf, free);
            if (buf[ret - 1] == '\n')
                buf[ret - 1] = '\0';
            labels.push_back(buf);
            buf_up.release();
        }
    } while (ret != -1);

    return SECURITY_MANAGER_SUCCESS;
}

} // PermissibleSet
} // SecurityManager
