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
#include <pwd.h>
#include <string>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <config.h>
#include <dpl/errno_string.h>
#include <dpl/exception.h>
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
        LogError("Unable to open file" << labelFile << ": " << GetErrnoString(errno));
        ThrowMsg(PermissibleSetException::FileOpenError, "Unable to open file ");
    }

    int ret = TEMP_FAILURE_RETRY(flock(fileno(file.get()), LOCK_EX));
    if (ret == -1) {
        LogError("Unable to lock file " << labelFile << ": " << GetErrnoString(errno));
        ThrowMsg(PermissibleSetException::FileLockError, "Unable to lock file");
    }
    return file;
}

void getUserAppLabels(const uid_t uid, std::vector<std::string> &appLabels)
 {
     PrivilegeDb::getInstance().GetUserApps(uid, appLabels);
     std::transform(appLabels.begin(), appLabels.end(), appLabels.begin(),
             SmackLabels::generateAppLabel);
 }

void getPerrmissibleFileLocation(std::string &path, const uid_t uid,
        const int installationType)
{
    if ((installationType == SM_APP_INSTALL_GLOBAL)
            || (installationType == SM_APP_INSTALL_PRELOADED)) {
        path = Config::SMACK_APPS_LABELS_GLOBAL_FILE;
        return;
    }
    struct passwd *userEntry = getpwuid(uid);
    if (userEntry == nullptr) {
        LogError(
                "Unable to get information for uid:" << uid << ": " << GetErrnoString(errno));
        ThrowMsg(PermissibleSetException::UserInfoReadError,
                "Unable to get information for uid");
    }
    path = std::string(userEntry->pw_dir) + Config::SMACK_APPS_LABELS_USER_FILE;
}

void updatePermissibleFile(const uid_t uid, const int installationType) {
    std::string labelFile;
    getPerrmissibleFileLocation(labelFile, uid, installationType);
    try {
        filePtr file = openAndLockLabelFile(labelFile, "w");
        std::vector<std::string> appLabels;
        getUserAppLabels(uid, appLabels);
        for (auto label : appLabels) {
            if (fprintf(file.get(), "%s\n", label.c_str()) < 0) {
                LogError("Unable to fprintf() to file " << labelFile << ": " <<
                        GetErrnoString(errno));
                ThrowMsg(PermissibleSetException::PermissibleSetException::FileWriteError, "Unable to fprintf() to file");
            }
        }
        if (fsync (fileno(file.get())) == -1) {
            LogError("Error at fsync " << labelFile << ": " << GetErrnoString(errno));

        }
        if (fchmod(fileno(file.get()), 00406) == -1) { //owner r, others r+w
            LogError("Error at fchmod " << labelFile << ": " << GetErrnoString(errno));
        }
    } catch (...) {
        if (chmod(labelFile.c_str(), 00006) == -1)  //owner nothing, others r+w
            LogError("Error at chmod " << labelFile << ": " << GetErrnoString(errno));
        throw;
    }
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
