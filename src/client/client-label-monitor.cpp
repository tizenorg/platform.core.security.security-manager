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
 * @file        client-label-monitor.cpp
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @author      Radoslaw Bartosiak <r.bartosiak@samsung.com>
 * @version     1.0
 * @brief       Implementation of API for managing list of permited labels for launcher
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <cstring>
#include <cstdlib>
#include <memory>
#include <string>

#include <unistd.h>
#include <fcntl.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/smack.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <client-common.h>
#include <config.h>
#include <dpl/log/log.h>
#include <dpl/errno_string.h>
#include <label-monitor.h>
#include <permissible-set.h>
#include <protocols.h>

//This is a mock-up, to be replaced by implementation in libsmack

#define SMACK_LABEL_LEN 255
#define DICT_HASH_SIZE 4096

static inline ssize_t get_label(char *dest, const char *src, unsigned int *hash)
{
    int i;
    unsigned int h = 5381;/*DJB2 hashing function magic number*/;

    if (!src || src[0] == '\0' || src[0] == '-')
        return -1;

    for (i = 0; i < (SMACK_LABEL_LEN + 1) && src[i]; i++) {
        if (src[i] <= ' ' || src[i] > '~')
            return -1;
        switch (src[i]) {
        case '/':
        case '"':
        case '\\':
        case '\'':
            return -1;
        default:
            break;
        }

        if (dest)
            dest[i] = src[i];
        if (hash)
            /* This efficient hash function,
             * created by Daniel J. Bernstein,
             * is known as DJB2 algorithm */
            h = (h << 5) + h + src[i];
    }

    if (dest && i < (SMACK_LABEL_LEN + 1))
        dest[i] = '\0';
    if (hash)
        *hash = h % DICT_HASH_SIZE;

    return i < (SMACK_LABEL_LEN + 1) ? i : -1;
}

int smack_set_relabel_self_mockup(const char **labels, int cnt)
{
    int i;
    int ret;
    int fd = -1;
    char *buf = NULL;
    int size = 0;
    int len;

    //if (init_smackfs_mnt())
    //    return -1;

    buf = (char*) malloc((SMACK_LABEL_LEN + 1) * cnt);
    if (buf == NULL)
        return -1;

    fd = open("/etc/relabel-self", O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (fd < 0) {
        ret = -1;
        goto out;
    }

    for (i = 0; i < cnt; ++i) {
        len = get_label(buf + size, labels[i], NULL);
        if (len <= 0) {
            ret = -1;
            goto out;
        }
        size += len;
        buf[size++] = ' ';

    }

    if (write(fd, buf, size) < 0)
        ret = -1;
    else
        ret = 0;

out:
    free(buf);
    close(fd);
    return ret;
}

//end of mockup

static lib_retcode apply_relabel_list(const std::string global_label_file,
        const std::string user_label_file)
{
    PtrVector<char> labels;
    lib_retcode ret;
    if ((ret = PermissibleSet::readLabelsFromPermissibleSet(global_label_file, labels))
            != SECURITY_MANAGER_SUCCESS)
        return ret;

    if ((ret = PermissibleSet::readLabelsFromPermissibleSet(user_label_file, labels))
            != SECURITY_MANAGER_SUCCESS)
        return ret;

    if (smack_set_relabel_self_mockup(const_cast<const char **>(labels.data()), labels.size()) != 0) {
        LogError("smack_set_relabel_self failed");
        return SECURITY_MANAGER_ERROR_UNKNOWN;
    }
    return SECURITY_MANAGER_SUCCESS;
}

static lib_retcode inotify_add_watch_full(int fd, const char* pathname, uint32_t mask, int *wd)
{
    if (wd == nullptr) {
        LogError("Error input param \"wd\"");
        return SECURITY_MANAGER_ERROR_WATCH_ADD_TO_FILE_FAILED;
    }
    int observed_fd = TEMP_FAILURE_RETRY(open(pathname, O_CREAT | O_EXCL, S_IWUSR | S_IRUSR));
    if ((observed_fd == -1) && (errno != EEXIST)) {
        LogError("Creation of file" << pathname << "failed" << GetErrnoString(errno));
        return SECURITY_MANAGER_ERROR_FILE_OPEN_FAILED;
    }
    close(observed_fd);
    int inotify_fd = inotify_add_watch(fd, pathname, mask);
    if (inotify_fd == -1) {
        LogError("Inotify watch failed on file " << pathname << ": " << GetErrnoString(errno));
        return SECURITY_MANAGER_ERROR_WATCH_ADD_TO_FILE_FAILED;
    }
    *wd = inotify_fd;
    return SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
int security_manager_app_labels_monitor_init(app_labels_monitor **monitor)
{
    typedef std::unique_ptr<app_labels_monitor, void (*)(app_labels_monitor *)> monitorPtr;
    return try_catch([&] {
        LogDebug("security_manager_app_labels_monitor_init() called");
        if (monitor == nullptr) {
            LogWarning("Error input param \"monitor\"");
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        }
        int ret;
        lib_retcode ret_lib;
        std::string user_smack_apps_label_file =
                Config::SMACK_APPS_LABELS_USER_FILE_PREFIX + std::to_string(getuid());
        std::string global_apps_label_file = Config::SMACK_APPS_LABELS_GLOBAL_FILE;

        *monitor = nullptr;

        monitorPtr m(new app_labels_monitor,
            security_manager_app_labels_monitor_finish);
        if (!m) {
            LogError("Bad memory allocation for app_labels_monitor");
            return SECURITY_MANAGER_ERROR_MEMORY;
        }
        ret = inotify_init();
        if (ret == -1) {
            LogError("Inotify init failed: " << GetErrnoString(errno));
            return SECURITY_MANAGER_ERROR_WATCH_ADD_TO_FILE_FAILED;
        }
        m.get()->inotify = ret;
        ret_lib = inotify_add_watch_full(m.get()->inotify, global_apps_label_file.c_str(),
                IN_CLOSE_WRITE, &(m.get()->global_labels_file_watch));
        if (ret_lib != SECURITY_MANAGER_SUCCESS) {
            return ret_lib;
        }
        ret_lib = inotify_add_watch_full(m.get()->inotify,
            user_smack_apps_label_file.c_str(), IN_CLOSE_WRITE, &(m.get()->user_labels_file_watch));
        if (ret_lib != SECURITY_MANAGER_SUCCESS) {
            return ret_lib;
        }
        *monitor = m.release();
        return SECURITY_MANAGER_SUCCESS;
    });
}

SECURITY_MANAGER_API
void security_manager_app_labels_monitor_finish(app_labels_monitor *monitor)
{
    try_catch([&] {
        LogDebug("security_manager_app_labels_monitor_finish() called");
        if (monitor == nullptr) {
            LogWarning("Error input param \"monitor\"");
            return 0;
        }

        std::string user_smack_apps_label_file = Config::SMACK_APPS_LABELS_USER_FILE_PREFIX +
                std::to_string(getuid());
        if (monitor->inotify != -1) {
            if (monitor->global_labels_file_watch != -1) {
                int ret = inotify_rm_watch(monitor->inotify, monitor->global_labels_file_watch);
                if (ret == -1) {
                    LogError("Inotify watch removal failed on file " <<
                            Config::SMACK_APPS_LABELS_GLOBAL_FILE << ": " << GetErrnoString(errno));
                }
            }
            if (monitor->user_labels_file_watch != -1) {
                int ret = inotify_rm_watch(monitor->inotify, monitor->user_labels_file_watch);
                if (ret == -1) {
                    LogError("Inotify watch removal failed on file " << user_smack_apps_label_file
                            << ": " << GetErrnoString(errno));
                }
            }
            close(monitor->inotify);
        }

        delete monitor;
        return 0;
    });
}

SECURITY_MANAGER_API
int security_manager_app_labels_monitor_get_fd(app_labels_monitor *monitor, int *fd)
{
    return try_catch([&] {
        LogDebug("security_manager_app_labels_monitor_get_fd() called");

        if (monitor == nullptr) {
            LogWarning("Error input param \"monitor\"");
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        }

        if (fd == nullptr) {
            LogWarning("Error input param \"fd\"");
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        }

        if (monitor->inotify == -1 || monitor->global_labels_file_watch == -1 ||
            monitor->user_labels_file_watch == -1) {
            LogWarning("Relabel list monitor was not initialized");
            return SECURITY_MANAGER_ERROR_NO_SUCH_OBJECT;
        }

        *fd = monitor->inotify;
        return SECURITY_MANAGER_SUCCESS;
    });
}

SECURITY_MANAGER_API
int security_manager_app_labels_monitor_process(app_labels_monitor *monitor)
{
    typedef std::unique_ptr<char, void (*)(void *)> bufPtr;
    return try_catch([&] {
        LogDebug("security_manager_app_labels_process() called");
        if (monitor == nullptr) {
            LogWarning("Error input param \"monitor\"");
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        }

        std::string global_smack_apps_label_file = Config::SMACK_APPS_LABELS_GLOBAL_FILE;
        std::string user_smack_apps_label_file = Config::SMACK_APPS_LABELS_USER_FILE_PREFIX +
                std::to_string(getuid());

        if (monitor->inotify == -1 || monitor->global_labels_file_watch == -1 ||
            monitor->user_labels_file_watch == -1) {
            LogWarning("Relabel list monitor was not initialized");
            return SECURITY_MANAGER_ERROR_NO_SUCH_OBJECT;
        }

        if (monitor->fresh) {
            monitor->fresh = false;
            return apply_relabel_list(global_smack_apps_label_file, user_smack_apps_label_file);
        }

        int avail;
        int ret = ioctl(monitor->inotify, FIONREAD, &avail);
        if (ret == -1) {
            LogError("Ioctl on inotify descriptor failed: " << GetErrnoString(errno));
            return SECURITY_MANAGER_ERROR_UNKNOWN;
        }

        bufPtr buffer(static_cast<char *>(malloc(avail)), free);
        for (int pos = 0; pos < avail;) {
            int ret = TEMP_FAILURE_RETRY(read(monitor->inotify, buffer.get() + pos, avail - pos));
            if (ret == -1) {
                LogError("Inotify read failed: " << GetErrnoString(errno));
                return SECURITY_MANAGER_ERROR_UNKNOWN;
            }
            pos += ret;
        }

        for (int pos = 0; pos < avail;) {
            struct inotify_event event;

            /* Event must be copied to avoid memory alignment issues */
            memcpy(&event, buffer.get() + pos, sizeof(struct inotify_event));
            pos += sizeof(struct inotify_event) + event.len;
            if ((event.mask & IN_CLOSE_WRITE) &&
                ((event.wd == monitor->global_labels_file_watch) ||
                 (event.wd == monitor->user_labels_file_watch))
               ){
                lib_retcode r = apply_relabel_list(global_smack_apps_label_file,
                        user_smack_apps_label_file);
                if (r != SECURITY_MANAGER_SUCCESS)
                    return r;
                break;
            }
        }
        return SECURITY_MANAGER_SUCCESS;
    });
}



