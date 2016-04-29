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
#include <memory>
#include <string>
#include <sys/file.h>
#include <unistd.h>
#include <vector>

#include <config.h>
#include <dpl/errno_string.h>
#include <dpl/log/log.h>
#include <permissible-set.h>
#include <security-manager.h>
#include <security-manager-types.h>

typedef std::unique_ptr<FILE, int (*)(FILE *)> filePtr;

namespace SecurityManager {
namespace PermissibleSet {

static filePtr openAndLockLabelFile(const int installationType, const std::string &user,
        std::string &labelFile) {
    int errsv;
    if ((installationType == SM_APP_INSTALL_GLOBAL)
            || (installationType == SM_APP_INSTALL_PRELOADED)) {
        labelFile = Config::SMACK_APPS_LABELS_GLOBAL_FILE;
    } else if (installationType == SM_APP_INSTALL_LOCAL) {
        labelFile = Config::SMACK_APPS_LABELS_USER_FILE_PREFIX + user;
    } else {
        LogError("Installation type: unknown");
        return filePtr(nullptr, nullptr);
    }
    filePtr file(fopen(labelFile.c_str(), "a"), fclose);
    if (!file) {
        errsv = errno;
        LogError("Unable to open file " << labelFile << ": " << GetErrnoString(errsv));
        return filePtr(nullptr, nullptr);
    }

    long int ret = TEMP_FAILURE_RETRY(flock(fileno(file.get()), LOCK_EX));
    if (ret == -1) {
        errsv = errno;
        LogError("Unable to lock file " << labelFile << ": " << GetErrnoString(errsv));
        return filePtr(nullptr, nullptr);
    }
    return file;
}

bool addLabelToPermissibleSet(const std::string &label, const std::string &user,
         int installationType)
{
    int errsv;
    if (label.length() < 1) {
          LogError("Label is empty.");
          return false;
    }
    std::string labelFile;
    filePtr file = openAndLockLabelFile(installationType, user, labelFile);
    if (!file)
        return false;
    long int end = ftell(file.get());
    if (fprintf(file.get(), "%s\n", label.c_str()) < 0) {
        errsv = errno;
        LogError("Unable to fprintf() to file " << labelFile << ": " << GetErrnoString(errsv));
        TEMP_FAILURE_RETRY(ftruncate(fileno(file.get()), end));
        return false;
    }
    if (fsync(fileno(file.get())) == -1) {
        errsv = errno;
        LogError("Failure while fsync() file " << labelFile << ": " << GetErrnoString(errsv));
        TEMP_FAILURE_RETRY(ftruncate(fileno(file.get()), end));
        return false;
    }
    return true;
}

bool deleteLabelFromPermissibleSet(const std::string &label, const std::string &user,
        int installationType)
{
    int errsv;
    if (label.length() < 1) {
        LogError("Label is empty.");
        return false;
    }
    std::string labelFile;
    filePtr file = openAndLockLabelFile(installationType, user, labelFile);
    if (!file)
        return false;
    PtrVector<char> labels;
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
            errsv = errno;
            LogError("Failure while reading file " << labelFile << ": " << GetErrnoString(errsv));
            return SECURITY_MANAGER_ERROR_FILE_OPEN_FAILED;
        default:
            if (buf[ret - 1] == '\n')
                buf[ret - 1] = '\0';
            try {
                if (strcmp(buf, label.c_str()) != 0)
                    labels.push_back(buf);
                else
                    free(buf);
            } catch (...) {
                free(buf);
                throw;
            }
        }
    } while (ret != -1);
    if (TEMP_FAILURE_RETRY(ftruncate(fileno(file.get()), 0) == -1)) {
        errsv = errno;
        LogError("Cannot truncate labels file " << labelFile << ": " << GetErrnoString(errsv));
        return false;
    }
    rewind(file.get());
    for (unsigned int i = 0; i < labels.size(); ++i)
        if (fprintf(file.get(), "%s\n", labels[i]) == -1) {
            errsv = errno;
            LogError("Failure while writing to file " << labelFile << ": " << GetErrnoString(errsv));
            TEMP_FAILURE_RETRY(ftruncate(fileno(file.get()), 0));
            return false;
        }

    if (fsync(fileno(file.get())) == -1) {
        errsv = errno;
        LogError("Failure while fsync() file " << labelFile << ": " << GetErrnoString(errsv));
        TEMP_FAILURE_RETRY(ftruncate(fileno(file.get()), 0));
        return false;
    }
    return true;
}

lib_retcode readLabelsFromPermissibleSet(const std::string label_file,
        PtrVector<char> &labels)
{
    typedef std::unique_ptr<FILE, int (*)(FILE *)> filePtr;
    int errsv;
    filePtr file(fopen(label_file.c_str(), "r"), fclose);
    if (!file) {
        errsv = errno;
        LogError("Unable to open file " << label_file << ": " << GetErrnoString(errsv));
        return SECURITY_MANAGER_ERROR_FILE_OPEN_FAILED;
    }

    long int r = TEMP_FAILURE_RETRY(flock(fileno(file.get()), LOCK_EX));
    if (r == -1) {
        errsv = errno;
        LogError("Unable to lock file " << label_file << ": " << GetErrnoString(errsv));
        return SECURITY_MANAGER_ERROR_FILE_OPEN_FAILED;
    }

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
            errsv = errno;
            LogError("Failure while reading file " << label_file << ": " << GetErrnoString(errsv));
            return SECURITY_MANAGER_ERROR_FILE_OPEN_FAILED;
        default:
            if (buf[ret - 1] == '\n')
                buf[ret - 1] = '\0';
            try {
                labels.push_back(buf);
            } catch (...) {
                free(buf);
                throw;
            }
        }
    } while (ret != -1);

    return SECURITY_MANAGER_SUCCESS;
}

} // PermissibleSet
} // SecurityManager
