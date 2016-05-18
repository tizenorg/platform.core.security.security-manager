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

#include <cstdio>
#include <cstring>
#include <fstream>
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
#include <dpl/fstream_accessors.h>
#include <dpl/log/log.h>
#include <permissible-set.h>
#include <privilege_db.h>
#include <security-manager-types.h>
#include <tzplatform_config.h>

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
        LogError("Unable to open file" << labelFile << ": " << GetErrnoString(errno));
        ThrowMsg(PermissibleSetException::FileOpenError, "Unable to open file ");
    }

    int ret = TEMP_FAILURE_RETRY(flock(getFd(fstream), LOCK_EX));
    if (ret == -1) {
        LogError("Unable to lock file " << labelFile << ": " << GetErrnoString(errno));
        ThrowMsg(PermissibleSetException::FileLockError, "Unable to lock file");
    }
}

std::string getPerrmissibleFileLocation(int installationType)
{
    if ((installationType == SM_APP_INSTALL_GLOBAL)
            || (installationType == SM_APP_INSTALL_PRELOADED))
        return tzplatform_mkpath(TZ_SYS_RW_APP, Config::SMACK_APPS_LABELS_GLOBAL_FILE.c_str());
    return tzplatform_mkpath(TZ_USER_APP, Config::SMACK_APPS_LABELS_USER_FILE.c_str());

}

void updatePermissibleFile(uid_t uid, int installationType) {
    std::string labelFile = getPerrmissibleFileLocation(installationType);
    std::ofstream fstream;
    openAndLockLabelFile(labelFile, fstream);
    if (fchmod(getFd(fstream), 0400) == -1)  //owner w
        LogError("Error at chmod " << labelFile << ": " << GetErrnoString(errno));
    std::vector<std::string> appLabels;
    PrivilegeDb::getInstance().GetUserApps(uid, appLabels);
    for (auto label : appLabels) {
        fstream << label << std::endl;
        if (fstream.bad()) {
            LogError("Unable to fprintf() to file " << labelFile << ": " << GetErrnoString(errno));
            ThrowMsg(PermissibleSetException::PermissibleSetException::FileWriteError,
                    "Unable to fprintf() to file");
        }
    }
    if (fstream.flush().fail()) {
        LogError("Error at fflush " << labelFile << ": " << GetErrnoString(errno));
    }
    if (fsync(getFd(fstream)) == -1) {
        LogError("Error at fsync " << labelFile << ": " << GetErrnoString(errno));
    }
    if (fchmod(getFd(fstream), 00640) == -1) { //owner rw, group r
        LogError("Error at fchmod " << labelFile << ": " << GetErrnoString(errno));
    }
}

void readLabelsFromPermissibleFile(const std::string &labelFile, std::vector<std::string> &labels)
{
    std::ifstream fstream;
    openAndLockLabelFile(labelFile, fstream);

    std::string line;
    while (std::getline(fstream, line))
        labels.push_back(line);
}

} // PermissibleSet
} // SecurityManager
