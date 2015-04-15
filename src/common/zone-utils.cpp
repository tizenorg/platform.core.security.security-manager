/*
 *  Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        zone-utils.cpp
 * @author      Lukasz Kostyra (l.kostyra@samsung.com)
 * @version     1.0
 * @brief       Implementation of Zone utility functions
 */

#include "zone-utils.h"

#include <fstream>

#include <dpl/log/log.h>

// FIXME This module is a replacement for Vasum functions.
//       When Vasum will be included into OBS, the module should be replaced with vasum-client.

namespace {

const std::string CPUSET_HOST = "/";
const std::string CPUSET_LXC_PREFIX = "/lxc/";

} // namespace

namespace SecurityManager
{

bool getZoneIdFromPid(int pid, std::string& zoneId)
{
    //open /proc/<pid>/cpuset and get its contents
    const std::string path = "/proc/" + std::to_string(pid) + "/cpuset";

    std::ifstream cpusetFile(path);
    if (!cpusetFile) {
        LogError("Failed to open cpuset");
        return false;
    }

    std::string cpuset;
    std::getline(cpusetFile, cpuset);
    cpusetFile.close();

    //check if we are in host
    if (cpuset == CPUSET_HOST) {
        zoneId = "host";
        return true;
    }

    //in lxc container, cpuset contains "/lxc/<id>" string - try to parse zoneID from there
    //search for lxc prefix
    size_t lxcPrefixPos = cpuset.find(CPUSET_LXC_PREFIX);
    if (lxcPrefixPos == std::string::npos) {
        LogError("LXC prefix not found - probably other virtualization method is used");
        return false;
    }

    //assign zone name and leave
    zoneId.assign(cpuset, CPUSET_LXC_PREFIX.size(), cpuset.size() - CPUSET_LXC_PREFIX.size());
    return true;
}

} // namespace SecurityManager
