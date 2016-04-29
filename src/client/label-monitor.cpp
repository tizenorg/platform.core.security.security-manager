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
 */
/*
 * @file        label-monitor.cpp
 * @author      Radoslaw Bartosiak <r.bartosiak@samsung.com>
 * @version     1.0
 * @brief       Implementation of API for managing list of permited labels for launcher
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif


#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <unistd.h>
#include <sys/file.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/smack.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/capability.h>

#include <client-common.h>
#include <client-offline.h>
#include <config.h>
#include <dpl/log/log.h>
#include <dpl/errno_string.h>
#include <dpl/exception.h>
#include <label-monitor.h>
#include <label-files.h>
#include <protocols.h>
#include <smack-labels.h>
#include <security-manager.h>

static lib_retcode apply_relabel_list(const std::string global_label_file,
        const std::string user_label_file)
{
    PtrVector<char> labels;
    lib_retcode ret;
    if ((ret = LabelFiles::read_labels_from_file(global_label_file, labels)) != SECURITY_MANAGER_SUCCESS)
        return ret;
    if ((ret = LabelFiles::read_labels_from_file(user_label_file, labels)) != SECURITY_MANAGER_SUCCESS)
        return ret;

    if (labels.size() == 0) {
        LogError("Files " <<  global_label_file << " and " << user_label_file <<" are both empty. "
                << "Something wrong must have happened, skipping reload of relabel-self list.");
        return SECURITY_MANAGER_ERROR_UNKNOWN;
    }

    if (smack_set_relabel_self(const_cast<const char **>(labels.data()), labels.size()) != 0) {
        LogError("smack_set_relabel_self failed");
        return SECURITY_MANAGER_ERROR_UNKNOWN;
    }

    return SECURITY_MANAGER_SUCCESS;
}

static int inotify_add_watch_full(int fd, const char* pathname, uint32_t mask, int *wd)
{
    if (wd == nullptr) {
        LogError("Error input param \"wd\"");
        return SECURITY_MANAGER_ERROR_WATCH_ADD_TO_FILE_FAILED;
    }
    int ret = open(pathname, O_CREAT | O_EXCL, S_IWUSR | S_IRUSR);
    if ((ret == -1) && (errno != EEXIST)) {
        LogError("Creation of file" << pathname << "failed" << strerror(errno));
        return SECURITY_MANAGER_ERROR_FILE_OPEN_FAILED;
    }
    close(ret);
    ret = inotify_add_watch(fd, pathname, mask);
    if (ret == -1) {
        LogError("Inotify watch failed on file " << pathname << ": " << strerror(errno));
        return SECURITY_MANAGER_ERROR_WATCH_ADD_TO_FILE_FAILED;
    }
    *wd = ret;
    return SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
int security_manager_app_inst_labels_monitor_init(app_labels_monitor **monitor)
{
    typedef std::unique_ptr<app_labels_monitor, void (*)(app_labels_monitor *)> monitorPtr;
    return try_catch([&] {
        LogDebug("security_manager_app_inst_labels_monitor_init() called");
        int ret;
        std::string user_smack_apps_label_file =
                Config::SMACK_APPS_LABELS_USER_FILE_PREFIX + std::to_string(getuid());
        std::string globalSmackAppsLabelFile = Config::SMACK_APPS_LABELS_GLOBAL_FILE;

        if (monitor == nullptr) {
            LogWarning("Error input param \"monitor\"");
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        }
        *monitor = nullptr;

        monitorPtr m(new app_labels_monitor,
            security_manager_app_inst_labels_monitor_finish);
        m.get()->inotify = -1;
        m.get()->global_labels_file_watch = -1;
        m.get()->user_labels_file_watch = -1;
        m.get()->fresh = true;

        ret = inotify_init();
        if (ret == -1) {
            LogError("Inotify init failed: " << strerror(errno));
            return SECURITY_MANAGER_ERROR_WATCH_ADD_TO_FILE_FAILED;
        }
        m.get()->inotify = ret;
        ret = inotify_add_watch_full(m.get()->inotify, globalSmackAppsLabelFile.c_str(),
                IN_CLOSE_WRITE, &(m.get()->global_labels_file_watch));
        if (ret != SECURITY_MANAGER_SUCCESS) {
            return SECURITY_MANAGER_ERROR_WATCH_ADD_TO_FILE_FAILED;
        }

        ret = inotify_add_watch_full(m.get()->inotify,
            user_smack_apps_label_file.c_str(), IN_CLOSE_WRITE, &(m.get()->user_labels_file_watch));
        if (ret != SECURITY_MANAGER_SUCCESS) {
            return SECURITY_MANAGER_ERROR_WATCH_ADD_TO_FILE_FAILED;
        }

        *monitor = m.release();
        return SECURITY_MANAGER_SUCCESS;
    });
}

SECURITY_MANAGER_API
void security_manager_app_inst_labels_monitor_finish(app_labels_monitor *monitor)
{
    try_catch([&] {
        LogDebug("security_manager_app_inst_labels_monitor_finish() called");
        std::string user_smack_apps_label_file = Config::SMACK_APPS_LABELS_USER_FILE_PREFIX +
                std::to_string(getuid());
        if (monitor == nullptr) {
            LogWarning("Error input param \"monitor\"");
            return 0;
        }

        if (monitor->inotify != -1) {
            if (monitor->user_labels_file_watch != -1) {
                int ret = inotify_rm_watch(monitor->inotify, monitor->global_labels_file_watch);
                if (ret == -1)
                    LogError("Inotify watch removal failed on file " <<
                            Config::SMACK_APPS_LABELS_GLOBAL_FILE << ": " << strerror(errno));
            }
            if (monitor->user_labels_file_watch != -1) {
                int ret = inotify_rm_watch(monitor->inotify, monitor->user_labels_file_watch);
                if (ret == -1)
                    LogError("Inotify watch removal failed on file " << user_smack_apps_label_file << ": "
                            << strerror(errno));
            }
            close(monitor->inotify);
        }

        delete monitor;
        return 0;
    });
}

SECURITY_MANAGER_API
int security_manager_app_inst_labels_monitor_get_fd(app_labels_monitor *monitor, int *fd)
{
    return try_catch([&] {
        LogDebug("security_manager_app_inst_labels_monitor_get_fd() called");

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
int security_manager_app_inst_labels_process(app_labels_monitor *monitor)
{
    typedef std::unique_ptr<char, void (*)(void *)> bufPtr;
    return try_catch([&] {
        LogDebug("security_manager_app_inst_labels_process() called");
        std::string user_smack_apps_label_file = Config::SMACK_APPS_LABELS_USER_FILE_PREFIX +
                std::to_string(getuid());

        if (monitor == nullptr) {
            LogWarning("Error input param \"monitor\"");
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        }

        if (monitor->inotify == -1 || monitor->global_labels_file_watch == -1 ||
            monitor->user_labels_file_watch == -1) {
            LogWarning("Relabel list monitor was not initialized");
            return SECURITY_MANAGER_ERROR_NO_SUCH_OBJECT;
        }

        if (monitor->fresh) {
            monitor->fresh = false;
            return apply_relabel_list(Config::SMACK_APPS_LABELS_GLOBAL_FILE, user_smack_apps_label_file);
        }

        int avail;
        int ret = ioctl(monitor->inotify, FIONREAD, &avail);
        if (ret == -1) {
            LogError("Ioctl on inotify descriptor failed: " << strerror(errno));
            return SECURITY_MANAGER_ERROR_UNKNOWN;
        }

        bufPtr buffer(static_cast<char *>(malloc(avail)), free);
        for (int pos = 0; pos < avail;) {
            int ret = TEMP_FAILURE_RETRY(read(monitor->inotify, buffer.get() + pos, avail - pos));
            if (ret == -1) {
                LogError("Inotify read failed: " << strerror(errno));
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
                lib_retcode r = apply_relabel_list(Config::SMACK_APPS_LABELS_GLOBAL_FILE,
                        user_smack_apps_label_file);
                if (r != SECURITY_MANAGER_SUCCESS)
                    return r;
                break;
            }
        }
        return SECURITY_MANAGER_SUCCESS;
    });
}



