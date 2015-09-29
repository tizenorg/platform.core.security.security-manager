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
 * @file        stats.h
 * @author      Zofia Abramowska <z.abramowska@samsung.com>
 * @version     1.0
 * @brief       Definition of process stat class
 */


#ifndef SECURITY_MANAGER_STATS_
#define SECURITY_MANAGER_STATS_

#include <ostream>
#include <sstream>
#include <set>
#include <string>

#include <sys/types.h>

namespace SecurityManager {
struct UidInfo {
    uid_t real;
    uid_t effective;
    uid_t saved;
    uid_t filesystem;

    bool operator==(const UidInfo &other) const {
        return real == other.real && effective == other.effective &&
               saved == other.saved && filesystem == other.filesystem;
    }

    bool operator!=(const UidInfo &other) const {
        return !(*this == other);
    }
};

struct GidInfo : UidInfo {
};

typedef std::set<gid_t> GroupInfo;
typedef short CapInfo;

bool operator==(const GroupInfo &l, const GroupInfo &r);

std::ostream &operator<<(std::ostream &os, const UidInfo &u);
std::ostream &operator<<(std::ostream &os, const GroupInfo &g);

class Stats {
public:
    void setPid(pid_t pid);
    // Extract infos from string
    void setUidInfo(const std::string &info);
    void setGidInfo(const std::string &info);
    void setGroupInfo(const std::string &info);
    void setCapInhInfo(const std::string &info);
    void setCapPrmInfo(const std::string &info);
    void setCapEffInfo(const std::string &info);
    void setLabel(const std::string &label);

    bool operator==(const Stats &other) const;
    bool operator!=(const Stats &other) const;

    bool noCaps() const;

    pid_t getPid() const { return m_pid; }
    UidInfo getUid() const { return m_uid; }
    GidInfo getGid() const { return m_gid; }
    GroupInfo getGroup() const { return m_groups; }
    CapInfo getCapInh() const { return m_capInh; }
    CapInfo getCapPrm() const { return m_capPrm; }
    CapInfo getCapEff() const { return m_capEff; }

private:
    pid_t m_pid;
    UidInfo m_uid;
    GidInfo m_gid;
    GroupInfo m_groups;
    CapInfo m_capInh;
    CapInfo m_capPrm;
    CapInfo m_capEff;
    std::string m_label;
};

std::ostream &operator<<(std::ostream &os, const Stats &s);

} // namespace SecurityManager

#endif /* SECURITY_MANAGER_STATS_ */
