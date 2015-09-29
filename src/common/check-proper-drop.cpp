/*
 *  Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        check-proper-drop.cpp
 * @author      Zofia Abramowska <z.abramowska@samsung.com>
 * @version     1.0
 * @brief       Implementation of proper privilege dropping check utilities
 */

#include <check-proper-drop.h>

#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>

#include <cstring>
#include <cstdlib>

#include <fstream>
#include <sstream>
#include <string>
#include <iterator>

#include <vector>

#include <stats.h>
#include <dpl/log/log.h>

namespace {

const int self_pid = getpid();
const std::string PROC_DIR = "/proc/";
const std::string TASK_SUBDIR = std::string(PROC_DIR) + "self/task/";
const std::string STATUS_FILE = "/status";
const std::string CURRENT_FILE = "/attr/current";

const std::string UID = "Uid";
const std::string GID = "Gid";
const std::string GROUPS = "Groups";
const std::string CAP_INH = "CapInh";
const std::string CAP_PRM = "CapPrm";
const std::string CAP_EFF = "CapEff";


std::vector<pid_t> getThreads()
{
    std::vector<pid_t> threads;

    DIR* dir = opendir(TASK_SUBDIR.c_str());
    if (dir == NULL) {
        LogError("opendir failed for " << TASK_SUBDIR << " with: " << strerror(errno));
        //to throw or not to throw, that is the question
        return threads;
    }

    struct dirent* dent;
    while((dent = readdir(dir)) != NULL) {
        if(strcmp(dent->d_name, ".") == 0 || strcmp(dent->d_name, "..") == 0)
            continue;

        struct stat st;
        if (fstatat(dirfd(dir), dent->d_name, &st, 0) < 0) {
            LogWarning("fstat failed for " << dent->d_name << " with: " << strerror(errno));
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            LogDebug("Adding thread: " << dent->d_name);
            threads.push_back(atoi(dent->d_name));
        }

    }
    closedir(dir);
    return threads;
}

SecurityManager::Stats readStats(const std::string &path) {
    std::ifstream file(path);
    std::string line;
    SecurityManager::Stats stats;
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string option, value;
        if (std::getline(iss, option, ':')) {
            std::getline(iss, value, ':');
            if (option == UID ) {
                stats.setUidInfo(value);
            } else if (option == GID) {
                stats.setGidInfo(value);
            } else if (option == GROUPS) {
                stats.setGroupInfo(value);
            } else if (option == CAP_INH) {
                stats.setCapInhInfo(value);
            } else if (option == CAP_EFF) {
                stats.setCapEffInfo(value);
            } else if (option == CAP_PRM) {
                stats.setCapPrmInfo(value);
            }
        }
    }
    return stats;
}

std::string readLabel(const std::string &path) {
    std::ifstream file(path);
    std::string label;
    file >> label;
    return label;
}

} // namespace anonymous

namespace SecurityManager {

bool check_proper_drop() {
    std::vector<pid_t> threads = getThreads();
    pid_t main_thread = getpid();

    if (threads.size() == 1 && threads.front() == main_thread) {
        LogDebug("No other threads spawned.");
        return true;
    }

    Stats properStat = {};
    std::vector<Stats> threadsStats;
    for (const auto &thread : threads) {
        const std::string statusFile = PROC_DIR + std::to_string(thread) + STATUS_FILE;
        const std::string currentFile = PROC_DIR + std::to_string(thread) + CURRENT_FILE;
        if (thread == main_thread) {
            properStat = readStats(statusFile);
            properStat.setLabel(readLabel(currentFile));
            LogDebug("Main thread stats: \n" << properStat);
            if (!properStat.noCaps()) {
                LogError("Main thread kept capabilities!");
                return false;
            }
        } else {
            Stats threadStat = readStats(statusFile);
            threadStat.setLabel(readLabel(currentFile));
            threadStat.setPid(thread);
            LogDebug("Thread " << thread << " stats: \n" << threadStat);
            if (!threadStat.noCaps()) {
                LogError("Thread " << thread << " kept capabilities!");
                return false;
            }
            threadsStats.push_back(threadStat);
        }
    }

    for (const auto &stat : threadsStats) {
        if (stat != properStat) {
            LogError("Stats of thread " << stat.getPid() << " differ with main thread");
            return false;
        }
    }


    return true;
}

} // namespace SecurityManager
