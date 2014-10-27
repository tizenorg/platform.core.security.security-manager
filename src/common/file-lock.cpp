/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        file-lock.cpp
 * @author      Sebastian Grabowski (s.grabowski@samsung.com)
 * @version     1.0
 * @brief       Implementation of simple file locking for a service
 */
/* vim: set ts=4 et sw=4 tw=78 : */

#include <fstream>
#include <dpl/log/log.h>
#include <boost/date_time/posix_time/posix_time.hpp>

#include "file-lock.h"

namespace SecurityManager {

char const * const SERVICE_LOCK_FILE = tzplatform_mkpath3(TZ_SYS_RUN,
                                                         "lock",
                                                         "security-manager.lock");

FileLocker::FileLocker(const std::string &lockFile, bool canWait,
                       unsigned int tryto)
{
    Try {
        Init(true, lockFile, canWait, tryto);
    } Catch (FileLocker::Exception::Base) {
        ReThrow(FileLocker::Exception::LockFailed);
    }
}


FileLocker::FileLocker(bool lockNow, const std::string &lockFile, bool canWait,
                       unsigned int tryto)
{
    Try {
        Init(lockNow, lockFile, canWait, tryto);
    } Catch (FileLocker::Exception::Base) {
        ReThrow(FileLocker::Exception::LockFailed);
    }
}

FileLocker::~FileLocker()
{
    Unlock();
}

void FileLocker::Init(bool lockNow, const std::string &lockFile, bool canWait,
                      unsigned int tryto)
{
    try {
        m_canWait = canWait;
        m_lockFile = lockFile;
        if (canWait && (tryto != 0))
            m_msTimeout = tryto;
        if (lockNow)
            Lock();
    } catch (FileLocker::Exception::Base &e) {
        LogError("Failed to lock " << lockFile << " file: "
                 << e.DumpToString());
        ThrowMsg(FileLocker::Exception::LockFailed,
                 "Failed to lock " << lockFile << " file: "
                 << e.DumpToString());
    }
}

bool FileLocker::Locked()
{
    return m_lock;
}

void FileLocker::Lock()
{
    try {
        if (m_lock)
            return;
        if (m_lockFile.empty()) {
            ThrowMsg(FileLocker::Exception::LockFailed,
                     "File name can not be empty.");
        }
        if (!std::ifstream(m_lockFile).good())
            std::ofstream(m_lockFile.c_str());
        m_flock = boost::interprocess::file_lock(m_lockFile.c_str());
        if (m_canWait) {
            if (!m_msTimeout)
                m_lock = boost::interprocess::scoped_lock
                         <boost::interprocess::file_lock>(m_flock);
            else {
                boost::posix_time::ptime to =
                    boost::posix_time::second_clock::universal_time()
                    + boost::posix_time::milliseconds(m_msTimeout);
                m_lock = boost::interprocess::scoped_lock
                         <boost::interprocess::file_lock>(m_flock, to);
            }
        } else {
            m_lock = boost::interprocess::scoped_lock
                     <boost::interprocess::file_lock>(m_flock,
                                                      boost::interprocess::try_to_lock);
        }
    } catch (const std::exception &e) {
            ThrowMsg(FileLocker::Exception::LockFailed,
                     "Error while locking a file.");
    }
    if (m_lock) {
        LogDebug("We have a lock on " << m_lockFile << " file.");
    } else {
        ThrowMsg(FileLocker::Exception::LockFailed,
                 "Unable to lock file.");
    }
}

void FileLocker::Unlock()
{
    if (m_lock) {
        m_lock.unlock();
        LogDebug("Lock released.");
    }
}

} // namespace SecurityManager

