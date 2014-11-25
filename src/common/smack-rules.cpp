/*
 *  Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
/**
 * @file        smack-rules.cpp
 * @author      Jacek Bukarewicz <j.bukarewicz@samsung.com>
 * @version     1.0
 * @brief       Implementation of a class managing smack rules
 *
 */

#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/smack.h>
#include <fcntl.h>
#include <fstream>
#include <cstring>
#include <sstream>

#include <dpl/log/log.h>
#include <tzplatform_config.h>

#include <smack-common.h>
#include "protocols.h"
#include "smack-labels.h"
#include "smack-rules.h"

namespace SecurityManager {

const char *const SMACK_APP_LABEL_TEMPLATE     = "~APP~";
const char *const SMACK_PKG_LABEL_TEMPLATE     = "~PKG~";
const char *const APP_RULES_TEMPLATE_FILE_PATH = tzplatform_mkpath(TZ_SYS_SMACK, "app-rules-template.smack");
const char *const SMACK_APP_IN_PACKAGE_PERMS   = "rwxat";

SmackRules::SmackRules()
{
    if (smack_accesses_new(&m_handle) < 0) {
        LogError("Failed to create smack_accesses handle");
        throw std::bad_alloc();
    }
}

SmackRules::~SmackRules() {
    smack_accesses_free(m_handle);
}

bool SmackRules::add(const std::string &subject, const std::string &object,
        const std::string &permissions)
{
    return 0 == smack_accesses_add(m_handle, subject.c_str(), object.c_str(), permissions.c_str());
}

bool SmackRules::addModify(const std::string &subject, const std::string &object,
        const std::string &allowPermissions, const std::string &denyPermissions)
{
    return 0 == smack_accesses_add_modify(m_handle, subject.c_str(), object.c_str(), allowPermissions.c_str(), denyPermissions.c_str());
}

bool SmackRules::clear() const
{
    return 0 == smack_accesses_clear(m_handle);
}

bool SmackRules::apply() const
{
    return 0 == smack_accesses_apply(m_handle);
}

bool SmackRules::loadFromFile(const std::string &path)
{
    int fd;
    bool ret = true;

    fd = TEMP_FAILURE_RETRY(open(path.c_str(), O_RDONLY));
    if (fd == -1) {
        LogError("Failed to open file: " << path);
        return false;
    }

    if (smack_accesses_add_from_file(m_handle, fd)) {
        LogError("Failed to load smack rules from file: " << path);
        ret = false;
    }

    if (close(fd) == -1) {
        // don't change the return code, the descriptor should be closed despite the error.
        LogWarning("Error while closing the file: " << path << ", error: " << strerror(errno));
    }

    return ret;
}

bool SmackRules::saveToFile(const std::string &path) const
{
    int fd;
    bool ret = true;

    fd = TEMP_FAILURE_RETRY(open(path.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644));
    if (fd == -1) {
        LogError("Failed to create file: " << path);
        return false;
    }

    LogDebug ("Opened rules file for writing path: \"" << path << "\"");

    if (smack_accesses_save(m_handle, fd)) {
        LogError("Failed to save rules to file: " << path);
        unlink(path.c_str());
        ret = false;
    }

    LogDebug ("Wrote rules to file path: \"" << path << "\"");

    if (close(fd) == -1) {
        if (errno == EIO) {
            LogError("I/O Error occured while closing the file: " << path << ", error: " << strerror(errno));
            unlink(path.c_str());
            return false;
        } else {
            // non critical error
            // don't change the return code, the descriptor should be closed despite the error.
            LogWarning("Error while closing the file: " << path << ", error: " << strerror(errno));
        }
    }

    return ret;
}


bool SmackRules::addFromTemplateFile(const app_inst_req &req)
{
    std::vector<std::string> templateRules;
    std::string line;
    std::ifstream templateRulesFile(APP_RULES_TEMPLATE_FILE_PATH);

    if (!templateRulesFile.is_open()) {
        LogError("Cannot open rules template file: " << APP_RULES_TEMPLATE_FILE_PATH);
        return false;
    }

    while (std::getline(templateRulesFile, line)) {
        templateRules.push_back(line);
    }

    if (templateRulesFile.bad()) {
        LogError("Error reading template file: " << APP_RULES_TEMPLATE_FILE_PATH);
        return false;
    }

    return addFromTemplate(templateRules, req);
}

bool SmackRules::addFromTemplate(const std::vector<std::string> &templateRules,
        const app_inst_req &req)
{
    for (auto rule : templateRules) {
        if (rule.empty())
            continue;

        std::stringstream stream(rule);
        std::string subject, object, permissions;
        stream >> subject >> object >> permissions;

        if (stream.fail() || !stream.eof()) {
            LogError("Invalid rule template: " << rule);
            return false;
        }

        bool subjectIsTemplate = (subject == SMACK_APP_LABEL_TEMPLATE || subject == SMACK_PKG_LABEL_TEMPLATE);

        if (subjectIsTemplate) {
            if (!generatePkgIdLabel(req.pkgId, subject)) {
                LogError("Failed to generate app label from pkgid: " << req.pkgId);
                return false;
            }
        }

        if (object == SMACK_PKG_LABEL_TEMPLATE) {
            if (!generatePkgIdLabel(req.pkgId, object)) {
                LogError("Failed to generate app label from pkgid: " << req.pkgId);
                return false;
            }
        }

        if (object == SMACK_APP_LABEL_TEMPLATE) {
            if (!generateAppIdLabel(req.appId, object)) {
                LogError("Failed to generate app label from pkgid: " << req.pkgId);
                return false;
            }
        }

        if (!add(subject, object, permissions)) {
            LogError("Failed to add rule: " << subject << " " << object << " " << permissions);
            return false;
        }
    }

    if (!generatePackageCrossDeps(req.pkgId))
    {
        LogError ("Failed to create application in-package cross dependencies");
        return false;
    }

    return true;
}

bool SmackRules::generatePackageCrossDeps(const std::string &pkgId, PrivilegeDb *pdb)
{
    if (pdb == nullptr)
    {
        pdb = new PrivilegeDb();
    }

    try {
        LogDebug ("Generating cross-package rules pkgId: " << pkgId);
        std::vector<std::string> appIds;
        std::string subjectLabel, objectLabel;
        std::string appsInPackagePerms = SMACK_APP_IN_PACKAGE_PERMS;

        pdb->GetAppIdsForPkgId(pkgId, appIds);

        for (std::vector<std::string>::size_type sIndex = 0; sIndex < appIds.size(); sIndex++) {
            for (std::vector<std::string>::size_type oIndex = 0; oIndex < appIds.size(); oIndex++) {
                if (appIds[sIndex] == appIds[oIndex]) {
                    /* if the subject and object are the same, continue */
                    continue;
                }

                if (generateAppIdLabel(appIds[oIndex], subjectLabel) && generateAppIdLabel(appIds[sIndex], objectLabel)) {
                    LogDebug ("Trying to add rule subject: " << subjectLabel << " object: " << objectLabel << " perms: " << appsInPackagePerms);
                    if (!add (subjectLabel, objectLabel, appsInPackagePerms)) {
                        LogError ("Can't add in-package rule for subject appId: " << appIds[sIndex] << " and object appId: " << appIds[oIndex]);
                        return false;
                    }
                }
                else {
                    LogError ("Failed to created smack labels for subject appId: " << appIds[sIndex] << " and object appId: " << appIds[oIndex]);
                    return false;
                }
            }
        }
    } catch (DB::SqlConnection::Exception::InternalError &e) {
        LogError ("Can't select all application ids for pkgId: " << pkgId << ", database error: " << e.DumpToString());
        return false;
    }

    return true;
}

std::string SmackRules::getPackageRulesFilePath(const std::string &pkgId)
{
    std::string path(tzplatform_mkpath3(TZ_SYS_SMACK, "accesses.d", pkgId.c_str()));
    return path;
}

bool SmackRules::installPackageRules(const app_inst_req &req) {
    try {
         SmackRules smackRules;
         std::string path = getPackageRulesFilePath(req.pkgId);

         if (!smackRules.addFromTemplateFile(req)) {
             LogError("Failed to load smack rules for appId: " << req.appId << " with pkgId: " << req.pkgId);
             return false;
         }

         if (smack_smackfs_path() != NULL && !smackRules.apply()) {
             LogError("Failed to apply application rules to kernel");
             return false;
         }

         if (!smackRules.saveToFile(path)) {
             smackRules.clear();
             return false;
         }

         return true;
     } catch (const std::bad_alloc &e) {
         LogError("Out of memory while trying to install smack rules for appId: " << req.appId << "in pkgId: " << req.pkgId);
         return false;
     }
}

bool SmackRules::uninstallPackageRules(const std::string &pkgId)
{
    std::string path = getPackageRulesFilePath(pkgId);
    if (access(path.c_str(), F_OK) == -1) {
        if (errno == ENOENT) {
            LogWarning("Smack rules were not installed for pkgId: " << pkgId);
            return true;
        }

        LogWarning("Cannot access smack rules path: " << path);
        return false;
    }

    try {
        SmackRules rules;
        if (rules.loadFromFile(path)) {
            if (smack_smackfs_path() != NULL && !rules.clear()) {
                LogWarning("Failed to clear smack kernel rules for pkgId: " << pkgId);
                // don't stop uninstallation
            }
        } else {
            LogWarning("Failed to load rules from file: " << path);
            // don't stop uninstallation
        }

        if (unlink(path.c_str()) == -1) {
            LogError("Failed to remove smack rules file: " << path);
            return false;
        }

        return true;
    } catch (const std::bad_alloc &e) {
        LogError("Out of memory while trying to uninstall smack rules for pkgId: " << pkgId);
        return false;
    }
}

bool SmackRules::uninstallApplicationRules(const std::string &appId, const std::string &pkgId, std::vector<std::string> appsInPkg)
{
    std::string path = getPackageRulesFilePath(pkgId);
    if (access(path.c_str(), F_OK) == -1) {
        if (errno == ENOENT) {
            LogWarning("Smack rules were not installed for pkgId: " << pkgId);
            return true;
        }

        LogWarning("Cannot access smack rules path: " << path);
        return false;
    }

    try {
        SmackRules rules;
        if (rules.loadFromFile(path)) {
            for (std::vector<std::string>::size_type sIndex = 0; sIndex < appsInPkg.size(); sIndex++) {
                for (std::vector<std::string>::size_type oIndex = 0; oIndex < appsInPkg.size(); oIndex++) {
                    if (appsInPkg[sIndex] == appsInPkg[oIndex]) {
                        /* if the subject and object are the same, continue */
                        continue;
                    }

                    /* If the removed app appears in a rule as either a subject or an object
                        add a negated rule, so that it is removed */
                    if (appsInPkg[oIndex] == appId || appsInPkg[sIndex] == appId) {
                        if (!rules.addModify(appsInPkg[oIndex], appsInPkg[sIndex], std::string(), std::string (SMACK_APP_IN_PACKAGE_PERMS))) {
                            LogWarning("Can't modify rule for appId: " << appId << " object: " << appsInPkg[oIndex] << " subject: " << appsInPkg[sIndex]);
                        }
                    }
                }
            }

            /* Re-save the file with modified rules now */
            if (!rules.saveToFile(path))
            {
                LogError("Unable to save rules file at path: \"" << path << "\"");
                return false;
            }
            return true;
        }
        else
        {
            LogError ("Unable to load rules from path: \"" << path << "\"");
            return false;
        }
        return true;
    } catch (const std::bad_alloc &e) {
        LogError("Out of memory while trying to uninstall smack rules for pkgId: " << pkgId);
        return false;
    }
}

} // namespace SecurityManager

