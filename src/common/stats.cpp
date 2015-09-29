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
 * @file        stats.cpp
 * @author      Zofia Abramowska <z.abramowska@samsung.com>
 * @version     1.0
 * @brief       Implementation of process stat class
 */

#include <stats.h>

#include <sstream>
#include <dpl/log/log.h>

namespace SecurityManager {

bool operator==(const GroupInfo &l, const GroupInfo &r) {
    if (l.size() != r.size())
        return false;
    auto lIt = l.begin();
    auto rIt = r.begin();

    while (lIt != l.end()) {
        if (*lIt != *rIt)
            return false;
    }
    return true;
}

std::ostream &operator<<(std::ostream &os, const UidInfo &u) {
    os << u.real << " " << u.effective << " " << u.saved << " " << u.filesystem;
    return os;
}

std::ostream &operator<<(std::ostream &os, const GroupInfo &g) {
    for (const auto &group : g) {
        os << group << ",";
    }
    return os;
}

std::ostream &operator<<(std::ostream &os, const Stats &s) {
    os << "Uid: " << s.getUid() << std::endl;
    os << "Gid: " << s.getGid() << std::endl;
    os << "Groups: " << s.getGroup() << std::endl;
    os << "CapInh: " << s.getCapInh() << std::endl;
    os << "CapPrm: " << s.getCapPrm() << std::endl;
    os << "CapEff: " << s.getCapEff() << std::endl;
    return os;
}

void Stats::setPid(pid_t pid) {
    m_pid = pid;
}
void Stats::setUidInfo(const std::string &info) {
    std::istringstream iss(info);
    iss >> m_uid.real >> m_uid.effective >> m_uid.saved >> m_uid.filesystem;
}
void Stats::setGidInfo(const std::string &info) {
    std::istringstream iss(info);
    iss >> m_gid.real >> m_gid.effective >> m_gid.saved >> m_gid.filesystem;
}
void Stats::setGroupInfo(const std::string &info) {
    std::istringstream iss(info);
    gid_t group;
    while (iss >> group) {
        m_groups.insert(group);
    }
}
void Stats::setCapInhInfo(const std::string &info) {
    std::istringstream iss(info);
    iss >> m_capInh;
}
void Stats::setCapPrmInfo(const std::string &info) {
    std::istringstream iss(info);
    iss >> m_capPrm;
}
void Stats::setCapEffInfo(const std::string &info) {
    std::istringstream iss(info);
    iss >> m_capEff;
}
void Stats::setLabel(const std::string &label) {
    m_label = label;
}

bool Stats::operator==(const Stats &other) const {
    if (getUid() != other.getUid()) {
        LogWarning("Uid differs : " << getPid() << " has " << getUid() << ", " << other.getPid() <<
                   " has " << other.getUid());
        return false;
    }
    if (getGid() != other.getGid()) {
        LogWarning("Gid differs : " << getPid() << " has " << getGid() << ", " << other.getPid() <<
                   " has " << other.getGid());
        return false;
    }
    if (getGroup() != other.getGroup()) {
        LogWarning("Groups differ : " << getPid() << " has " << getGroup() << ", " << other.getPid() <<
                   " has " << other.getGroup());
        return false;
    }
    return true;
}

bool Stats::operator!=(const Stats &other) const {
    return !(*this == other);
}

bool Stats::noCaps() const {
    return !m_capInh && !m_capPrm && !m_capEff;
}

} //namespace SecurityManager
