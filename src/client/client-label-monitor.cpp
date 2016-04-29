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
#include <string.h>
#include <vector>

#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
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

struct app_labels_monitor {
    int inotify;
    int global_labels_file_watch;
    int user_labels_file_watch;
    bool fresh;
    char *user_label_file_path;
    app_labels_monitor() : inotify(-1), global_labels_file_watch(-1), user_labels_file_watch(-1),
                           fresh(true), user_label_file_path(nullptr) {}
};

static lib_retcode apply_relabel_list(const std::string &global_label_file,
        const std::string user_label_file)
{
    std::vector<std::string> labels;
    lib_retcode ret;
    if ((ret = PermissibleSet::readLabelsFromPermissibleFile(global_label_file, labels))
            != SECURITY_MANAGER_SUCCESS)
        return ret;

    if ((ret = PermissibleSet::readLabelsFromPermissibleFile(user_label_file, labels))
            != SECURITY_MANAGER_SUCCESS)
        return ret;

    std::vector<const char*> temp;
    for (auto &e : labels)
        temp.push_back(e.c_str());


    if (smack_set_relabel_self(const_cast<const char **>(temp.data()), temp.size()) != 0) {
        LogError("smack_set_relabel_self failed");
        return SECURITY_MANAGER_ERROR_UNKNOWN;
    }
    return SECURITY_MANAGER_SUCCESS;
}

static lib_retcode inotify_add_watch_full(int fd, const char* pathname, uint32_t mask, int *wd)
{
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
        uid_t uid = getuid();
        lib_retcode ret_lib;
        struct passwd *userEntry = getpwuid(uid);
        if (userEntry == nullptr) {
            LogError("Unable to get information for uid:" << uid << ": " << GetErrnoString(errno));
            return SECURITY_MANAGER_ERROR_UNKNOWN;
        }
        const std::string user_smack_apps_label_file = std::string(userEntry->pw_dir) + Config::SMACK_APPS_LABELS_USER_FILE;
        const std::string global_apps_label_file = Config::SMACK_APPS_LABELS_GLOBAL_FILE;

        *monitor = nullptr;

        monitorPtr m(new app_labels_monitor, security_manager_app_labels_monitor_finish);
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
        int len = strlen(user_smack_apps_label_file.c_str())*sizeof(char);
        m->user_label_file_path = (char*) malloc(len);
        if (!(m->user_label_file_path)) {
            return SECURITY_MANAGER_ERROR_MEMORY;
        }
        strncpy(m->user_label_file_path, user_smack_apps_label_file.c_str(), len+1);
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
            LogDebug("input param \"monitor\" is nullptr");
            return 0;
        }
        std::string user_smack_apps_label_file("");
        if (monitor->user_label_file_path) {
            user_smack_apps_label_file = std::string(monitor->user_label_file_path);
            free(monitor->user_label_file_path);
            monitor->user_label_file_path = nullptr;
        }
        if (monitor->inotify != -1) {
            if (monitor->global_labels_file_watch != -1) {
                int ret = inotify_rm_watch(monitor->inotify, monitor->global_labels_file_watch);
                if (ret == -1) {
                    LogError("Inotify watch removal failed on file " <<
                            Config::SMACK_APPS_LABELS_GLOBAL_FILE << ": "
                            << GetErrnoString(errno));
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
        delete monitor->user_label_file_path;
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

        const std::string global_smack_apps_label_file = Config::SMACK_APPS_LABELS_GLOBAL_FILE;
        const std::string user_smack_apps_label_file = std::string(monitor->user_label_file_path);

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



