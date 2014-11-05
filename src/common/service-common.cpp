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
 * @file        service-common.h
 * @author      Sebastian Grabowski (s.grabowski@samsung.com)
 * @version     1.0
 * @brief       Implementation of common routines for a service
 */
/* vim: set ts=4 et sw=4 tw=78 : */

#include <pwd.h>
#include <tzplatform_config.h>

#include "protocols.h"
#include <smack-common.h>
#include <security-manager.h>
#include <cynara-admin.h>
#include <cynara.h>
#include <smack-labels.h>
#include <smack-rules.h>
#include <smack-check.h>

#include "service-common.h"

namespace SecurityManager {

uid_t getGlobalUserId(void) {
    static uid_t globaluid = tzplatform_getuid(TZ_SYS_GLOBALAPP_USER);
    return globaluid;
}

void checkGlobalUser(uid_t &uid, std::string &cynaraUserStr)
{
    static uid_t globaluid = getGlobalUserId();
    if (uid == 0 || uid == globaluid) {
        uid = globaluid;
        cynaraUserStr = CYNARA_ADMIN_WILDCARD;
    } else {
        cynaraUserStr = std::to_string(static_cast<unsigned int>(uid));
    }
}

static inline bool isSubDir(const char *parent, const char *subdir)
{
    while (*parent && *subdir)
        if (*parent++ != *subdir++)
            return false;

    return (*subdir == '/');
}

static inline bool installRequestAuthCheck(const app_inst_req &req, uid_t uid)
{
    struct passwd *pwd;
    do {
        errno = 0;
        pwd = getpwuid(uid);
        if (!pwd && errno != EINTR) {
            LogError("getpwuid failed with '" << uid
                    << "' as paramter: " << strerror(errno));
            return false;
        }
    } while (!pwd);

    std::unique_ptr<char, std::function<void(void*)>> home(
        realpath(pwd->pw_dir, NULL), free);
    if (!home.get()) {
            LogError("realpath failed with '" << pwd->pw_dir
                    << "' as paramter: " << strerror(errno));
            return false;
    }

    for (const auto &appPath : req.appPaths) {
        std::unique_ptr<char, std::function<void(void*)>> real_path(
            realpath(appPath.first.c_str(), NULL), free);
        if (!real_path.get()) {
            LogError("realpath failed with '" << appPath.first.c_str()
                    << "' as paramter: " << strerror(errno));
            return false;
        }
        LogDebug("Requested path is '" << appPath.first.c_str()
                << "'. User's HOME is '" << pwd->pw_dir << "'");
        if (!isSubDir(home.get(), real_path.get())) {
            LogWarning("User's apps may have registered folders only in user's home dir");
            return false;
        }

        app_install_path_type pathType = static_cast<app_install_path_type>(appPath.second);
        if (pathType == SECURITY_MANAGER_PATH_PUBLIC) {
            LogWarning("Only root can register SECURITY_MANAGER_PATH_PUBLIC path");
            return false;
        }
    }
    return true;
}

int AppInstall(PrivilegeDb *pdb, const app_inst_req &req)
{
    int ret = SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    bool offlineMode = pdb == nullptr;

    LogDebug("AppInstall");
    bool pkgIdIsNew = false;
    std::vector<std::string> addedPermissions;
    std::vector<std::string> removedPermissions;
    std::string uidstr;
    uid_t uid = req.uid;

    if (offlineMode) {
        LogDebug("Offline mode request.");
    }
    checkGlobalUser(uid, uidstr);
    if (!installRequestAuthCheck(req, uid)) {
        LogError("Request from uid " << uid << " for app installation denied");
        return SECURITY_MANAGER_API_ERROR_AUTHENTICATION_FAILED;
    }

    std::string smackLabel;
    if (!generateAppLabel(req.pkgId, smackLabel)) {
        LogError("Cannot generate Smack label for package: " << req.pkgId);
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    }

    LogDebug("Install parameters: appId: " << req.appId << ", pkgId: " << req.pkgId
             << ", generated smack label: " << smackLabel << ", uid: " << uid);

    // create null terminated array of strings for permissions
    std::unique_ptr<const char *[]> pp_permissions(new const char* [req.privileges.size() + 1]);
    for (size_t i = 0; i < req.privileges.size(); ++i) {
        LogDebug("  Permission = " << req.privileges[i]);
        pp_permissions[i] = req.privileges[i].c_str();
    }
    pp_permissions[req.privileges.size()] = nullptr;

    bool have_smack = SecurityManager::smack_check() != 0;
    if (offlineMode)
        pdb = new PrivilegeDb();
    try {
        std::vector<std::string> oldPkgPrivileges, newPkgPrivileges;

        LogDebug("Install parameters: appId: " << req.appId << ", pkgId: " << req.pkgId
                 << ", uidstr " << uidstr << ", generated smack label: " << smackLabel);

        pdb->BeginTransaction();
        pdb->GetPkgPrivileges(req.pkgId, uid, oldPkgPrivileges);
        pdb->AddApplication(req.appId, req.pkgId, uid, pkgIdIsNew);
        pdb->UpdateAppPrivileges(req.appId, uid, req.privileges);
        pdb->GetPkgPrivileges(req.pkgId, uid, newPkgPrivileges);
        CynaraAdmin::UpdatePackagePolicy(smackLabel, uidstr, oldPkgPrivileges,
                                         newPkgPrivileges);
        pdb->CommitTransaction();
        LogDebug("Application installation commited to database");
    } catch (const PrivilegeDb::Exception::InternalError &e) {
        pdb->RollbackTransaction();
        LogError("Error while saving application info to database: " << e.DumpToString());
        goto out;
    } catch (const CynaraException::Base &e) {
        pdb->RollbackTransaction();
        LogError("Error while setting Cynara rules for application: " << e.DumpToString());
        goto out;
    } catch (const std::bad_alloc &e) {
        pdb->RollbackTransaction();
        LogError("Memory allocation while setting Cynara rules for application: " << e.what());
        goto out;
    }

    if (have_smack) {
        // register paths
        for (const auto &appPath : req.appPaths) {
            const std::string &path = appPath.first;
            app_install_path_type pathType = static_cast<app_install_path_type>(appPath.second);
            int result = setupPath(req.pkgId, path, pathType);

            if (!result) {
                LogError("setupPath() failed");
                goto out;
            }
        }
    }

    if (pkgIdIsNew && have_smack) {
        LogDebug("Adding Smack rules for new pkgId " << req.pkgId);
        if (!SmackRules::installPackageRules(req.pkgId)) {
            LogError("Failed to apply package-specific smack rules");
            goto out;
        }
    }

    // success
    ret = SECURITY_MANAGER_API_SUCCESS;
out:
    if (offlineMode)
        delete pdb;
    return ret;
}

} // namespace SecurityManager

