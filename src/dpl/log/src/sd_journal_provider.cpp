/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
/*
 * @file        sd_journal_provider.cpp
 * @author      Marcin Lis (m.lis@samsung.com)
 * @version     1.0
 * @brief       This file contains the implementation of systemd journal log provider
 */

#include <dpl/log/sd_journal_provider.h>
#include <string>
#include <sstream>
#include <systemd/sd-journal.h>

#define UNUSED __attribute__((unused))

namespace SecurityManager {
namespace Log {
std::string SdJournalProvider::FormatMessage(const char *message,
                                           const char *filename,
                                           int line,
                                           const char *function)
{
    std::ostringstream val;

    val << std::string("[") <<
    LocateSourceFileName(filename) << std::string(":") << line <<
    std::string("] ") << function << std::string("(): ") << message;

    return val.str();
}

SdJournalProvider::SdJournalProvider()
{}

SdJournalProvider::~SdJournalProvider()
{}

void SdJournalProvider::SetTag(const char *tag)
{
    m_tag = std::string(tag);
}

void SdJournalProvider::Debug(const char *message,
                            const char *filename,
                            int line,
                            const char *function)
{
    // sd-journal imports LOG priorities from the syslog, see syslog(3) for details
    sd_journal_print(LOG_DEBUG, "%s: %s", m_tag.c_str(),
                     (FormatMessage(message, filename, line, function)).c_str());
}

void SdJournalProvider::Info(const char *message,
                           const char *filename,
                           int line,
                           const char *function)
{
    sd_journal_print(LOG_INFO, "%s: %s", m_tag.c_str(),
                     (FormatMessage(message, filename, line, function)).c_str());
}

void SdJournalProvider::Warning(const char *message,
                              const char *filename,
                              int line,
                              const char *function)
{
    sd_journal_print(LOG_WARNING, "%s: %s", m_tag.c_str(),
                     (FormatMessage(message, filename, line, function)).c_str());
}

void SdJournalProvider::Error(const char *message,
                            const char *filename,
                            int line,
                            const char *function)
{
    sd_journal_print(LOG_ERR, "%s: %s", m_tag.c_str(),
                     (FormatMessage(message, filename, line, function)).c_str());
}

// All Pedantic logs are translated to Debug
void SdJournalProvider::Pedantic(const char *message,
                               const char *filename,
                               int line,
                               const char *function)
{
    Debug(message, filename, line, function);
}

// All Secure* logs are treated as their non-secure equivalents
void SdJournalProvider::SecureDebug(const char *message UNUSED,
                            const char *filename UNUSED,
                            int line UNUSED,
                            const char *function UNUSED)
{
    Debug(message, filename, line, function);
}

void SdJournalProvider::SecureInfo(const char *message UNUSED,
                           const char *filename UNUSED,
                           int line UNUSED,
                           const char *function UNUSED)
{
    Info(message, filename, line, function);
}

void SdJournalProvider::SecureWarning(const char *message UNUSED,
                              const char *filename UNUSED,
                              int line UNUSED,
                              const char *function UNUSED)
{
    Warning(message, filename, line, function);
}

void SdJournalProvider::SecureError(const char *message UNUSED,
                            const char *filename UNUSED,
                            int line UNUSED,
                            const char *function UNUSED)
{
    Error(message, filename, line, function);
}

} // namespace Log
} // namespace SecurityManager
