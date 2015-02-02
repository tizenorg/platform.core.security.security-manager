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
/*
 * @file        service_impl.cpp
 * @author      Michal Witanowski <m.witanowski@samsung.com>
 * @author      Jacek Bukarewicz <j.bukarewicz@samsung.com>
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @brief       Implementation of the service methods
 */

#include <grp.h>
#include <limits.h>
#include <pwd.h>

#include <cstring>
#include <algorithm>

#include <dpl/log/log.h>
#include <tzplatform_config.h>

#include "protocols.h"
#include "privilege_db.h"
#include "cynara.h"
#include "smack-rules.h"
#include "smack-labels.h"

#include "service_impl.h"

namespace SecurityManager {
namespace ServiceImpl {

static uid_t getGlobalUserId(void)
{
    static uid_t globaluid = tzplatform_getuid(TZ_SYS_GLOBALAPP_USER);
    return globaluid;
}

static bool getGlobalUserHome(std::string &userHome)
{
    const char *globalUserHome = tzplatform_getenv(TZ_SYS_RW_APP);

    if (!globalUserHome)
        return false;

    userHome = globalUserHome;

    return true;
}

/**
 * Unifies user data of apps installed for all users
 * @param  uid            peer's uid - may be changed during process
 * @param  cynaraUserStr  string to which cynara user parameter will be put
 */
static void checkGlobalUser(uid_t &uid, std::string &cynaraUserStr)
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

static bool createTzConfigCtx(struct tzplatform_context **tz_ctx)
{
    LogDebug("Creating tizen config context");

    if (tzplatform_context_create(tz_ctx))
        return false;

     return true;
}


static bool setTzConfigCtxUser(struct tzplatform_context *tz_ctx, const uid_t &uid)
{
    LogDebug("Setting user uid: " << uid << " for tizen config context");

    if (tzplatform_context_set_user(tz_ctx, uid))
         return false;

     return true;
}

static bool getSingleUserHome(const uid_t &uid, std::string &userHome)
{
    struct tzplatform_context *tz_ctx = nullptr;

    if (!createTzConfigCtx(&tz_ctx)) {
        LogError("Failed creating tzconfig context");
        return false;
    }

    std::unique_ptr<tzplatform_context, std::function<void(tzplatform_context*)>> tz_ctx_ptr(
            tz_ctx, tzplatform_context_destroy);

    if (!setTzConfigCtxUser(tz_ctx_ptr.get(), uid)) {
        LogError("Failed setting tzconfig context user for uid: " << uid);
        return false;
    }

    const char *home = tzplatform_context_getenv(tz_ctx_ptr.get(), TZ_USER_HOME);
    if (!home) {
        LogError("Failed checking HOME from tzconfig context for user with uid: " << uid);
        return false;
    }

    userHome = home;

    return true;
}

static bool getSingleUserAppDir(const uid_t &uid, std::string &userAppDir)
{
    struct tzplatform_context *tz_ctx = nullptr;

    if (!createTzConfigCtx(&tz_ctx)) {
        LogError("Failed creating tzconfig context");
        return false;
    }

    std::unique_ptr<tzplatform_context, std::function<void(tzplatform_context*)>> tz_ctx_ptr(
            tz_ctx, tzplatform_context_destroy);

    if (!setTzConfigCtxUser(tz_ctx_ptr.get(), uid)) {
        LogError("Failed setting tzconfig context user for uid: " << uid);
        return false;
    }

    const char *appDir = tzplatform_context_getenv(tz_ctx_ptr.get(), TZ_USER_APP);
    if (!appDir) {
        LogError("Failed checking app dir from tzconfig context for user with uid: " << uid);
        return false;
    }

    userAppDir = appDir;

    return true;
}
static bool getUserHome(const uid_t &uid, std::string &userHome, bool &isGlobalInstallation)
{
    if (isGlobalInstallation) {
        if (!getGlobalUserHome(userHome)) {
            LogError("Failed checking HOME path for global user");
            return false;
        }
    } else {
        if (!getSingleUserHome(uid, userHome)) {
            LogError("Failed checking HOME path for single user");
            return false;
        }
    }

    return true;
}

static inline bool installRequestAuthCheck(const app_inst_req &req, uid_t uid, bool &isCorrectPath, std::string &appPath)
{
    std::string userHome;
    std::string userAppDir;
    std::stringstream correctPath;
    bool isGlobalInstallation = true;

    if (uid != getGlobalUserId()) {
        LogDebug("Installation type: single user");
        isGlobalInstallation = false;
    } else
        LogDebug("Installation type: global installation");

    if (!getUserHome(uid, userHome, isGlobalInstallation)) {
        LogError("Failed getting HOME for user uid: " << uid);
        return false;
    }

    if (isGlobalInstallation)
        userAppDir = userHome;
    else {
        if (!getSingleUserAppDir(uid, userAppDir)) {
            LogError("Failed getting app dir for user uid: " << uid);
            return false;
        }
    }

    std::unique_ptr<char, std::function<void(void*)>> home(
        realpath(userHome.c_str(), NULL), free);
    if (!home.get()) {
            LogError("realpath failed with '" << userHome
                    << "' as parameter: " << strerror(errno));
            return false;
    }

    std::unique_ptr<char, std::function<void(void*)>> app(
        realpath(userAppDir.c_str(), NULL), free);
    if (!app.get()) {
            LogError("realpath failed with '" << userAppDir
                    << "' as parameter: " << strerror(errno));
            return false;
    }

    appPath = app.get();
    correctPath.clear();
    correctPath << app.get() << "/" << req.pkgId << "/" << req.appId;
    LogDebug("correctPath: " << correctPath.str());

    for (const auto &appPath : req.appPaths) {
        std::unique_ptr<char, std::function<void(void*)>> real_path(
            realpath(appPath.first.c_str(), NULL), free);
        if (!real_path.get()) {
            LogError("realpath failed with '" << appPath.first.c_str()
                    << "' as parameter: " << strerror(errno));
            return false;
        }
        LogDebug("Requested path is '" << appPath.first.c_str()
                << "'. User's HOME is '" << userHome << "'");
        if (!isSubDir(home.get(), real_path.get())) {
            LogWarning("User's apps may have registered folders only in user's home dir");
            return false;
        }

        if (!isSubDir(correctPath.str().c_str(), real_path.get())) {
            LogWarning("Installation is outside correct path: " << correctPath.str());
            //return false;
        } else
            isCorrectPath = true;

        app_install_path_type pathType = static_cast<app_install_path_type>(appPath.second);
        if (pathType == SECURITY_MANAGER_PATH_PUBLIC) {
            LogWarning("Only root can register SECURITY_MANAGER_PATH_PUBLIC path");
            return false;
        }
    }
    return true;
}

int appInstall(const app_inst_req &req, uid_t uid)
{
    std::vector<std::string> addedPermissions;
    std::vector<std::string> removedPermissions;
    std::vector<std::string> pkgContents;
    std::string uidstr;
    bool isCorrectPath = false;
    std::string appPath;
    if (uid) {
        if (uid != req.uid) {
            LogError("User " << uid <<
                     " is denied to install application for user " << req.uid);
            return SECURITY_MANAGER_API_ERROR_ACCESS_DENIED;
        }
    } else {
        if (req.uid)
            uid = req.uid;
    }
    checkGlobalUser(uid, uidstr);

    if (!installRequestAuthCheck(req, uid, isCorrectPath, appPath)) {
        LogError("Request from uid " << uid << " for app installation denied");
        return SECURITY_MANAGER_API_ERROR_AUTHENTICATION_FAILED;
    }

    std::string smackLabel;
    if (!generateAppLabel(req.appId, smackLabel)) {
        LogError("Cannot generate Smack label for application: " << req.appId);
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    }

    LogDebug("Install parameters: appId: " << req.appId << ", pkgId: " << req.pkgId
            << ", generated smack label: " << smackLabel);

    // create null terminated array of strings for permissions
    std::unique_ptr<const char *[]> pp_permissions(new const char* [req.privileges.size() + 1]);
    for (size_t i = 0; i < req.privileges.size(); ++i) {
        LogDebug("  Permission = " << req.privileges[i]);
        pp_permissions[i] = req.privileges[i].c_str();
    }
    pp_permissions[req.privileges.size()] = nullptr;

    try {
        std::vector<std::string> oldAppPrivileges;
        LogDebug("Install parameters: appId: " << req.appId << ", pkgId: " << req.pkgId
                 << ", uidstr " << uidstr << ", generated smack label: " << smackLabel);

        PrivilegeDb::getInstance().BeginTransaction();
        std::string pkg;
        bool ret = PrivilegeDb::getInstance().GetAppPkgId(req.appId, pkg);
        if (ret == true && pkg != req.pkgId) {
            LogError("Application already installed with different package id");
            PrivilegeDb::getInstance().RollbackTransaction();
            return SECURITY_MANAGER_API_ERROR_INPUT_PARAM;
        }
        PrivilegeDb::getInstance().GetAppPrivileges(req.appId, uid, oldAppPrivileges);
        PrivilegeDb::getInstance().AddApplication(req.appId, req.pkgId, uid);
        PrivilegeDb::getInstance().UpdateAppPrivileges(req.appId, uid, req.privileges);
        /* Get all application ids in the package to generate rules withing the package */
        PrivilegeDb::getInstance().GetAppIdsForPkgId(req.pkgId, pkgContents);
        CynaraAdmin::getInstance().UpdateAppPolicy(smackLabel, uidstr, oldAppPrivileges,
                                         req.privileges);
        PrivilegeDb::getInstance().CommitTransaction();
        LogDebug("Application installation commited to database");
    } catch (const PrivilegeDb::Exception::IOError &e) {
        LogError("Cannot access application database: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    } catch (const PrivilegeDb::Exception::InternalError &e) {
        PrivilegeDb::getInstance().RollbackTransaction();
        LogError("Error while saving application info to database: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    } catch (const CynaraException::Base &e) {
        PrivilegeDb::getInstance().RollbackTransaction();
        LogError("Error while setting Cynara rules for application: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        PrivilegeDb::getInstance().RollbackTransaction();
        LogError("Memory allocation while setting Cynara rules for application: " << e.what());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    }

    if (isCorrectPath)
        if (!setupCorrectPath(req.pkgId, req.appId, appPath)) {
            LogError("Can't setup <APP_ROOT> dirs");
            return false;
        }

    // register paths
    for (const auto &appPath : req.appPaths) {
        const std::string &path = appPath.first;
        app_install_path_type pathType = static_cast<app_install_path_type>(appPath.second);
        int result = setupPath(req.pkgId, path, pathType);

        if (!result) {
            LogError("setupPath() failed");
            return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
        }
    }

    LogDebug("Adding Smack rules for new appId: " << req.appId << " with pkgId: "
            << req.pkgId << ". Applications in package: " << pkgContents.size());
    if (!SmackRules::installApplicationRules(req.appId, req.pkgId, pkgContents)) {
        LogError("Failed to apply package-specific smack rules");
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    }

    return SECURITY_MANAGER_API_SUCCESS;
}

int appUninstall(const std::string &appId, uid_t uid)
{
    std::string pkgId;
    std::string smackLabel;
    std::vector<std::string> pkgContents;
    bool appExists = true;
    bool removePkg = false;
    std::string uidstr;
    checkGlobalUser(uid, uidstr);

    try {
        std::vector<std::string> oldAppPrivileges;

        PrivilegeDb::getInstance().BeginTransaction();
        if (!PrivilegeDb::getInstance().GetAppPkgId(appId, pkgId)) {
            LogWarning("Application " << appId <<
                " not found in database while uninstalling");
            PrivilegeDb::getInstance().RollbackTransaction();
            appExists = false;
        } else {

            LogDebug("Uninstall parameters: appId: " << appId << ", pkgId: " << pkgId
                     << ", uidstr " << uidstr << ", generated smack label: " << smackLabel);

            if (!generateAppLabel(appId, smackLabel)) {
                LogError("Cannot generate Smack label for package: " << pkgId);
                return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
            }

            /* Before we remove the app from the database, let's fetch all apps in the package
                that this app belongs to, this will allow us to remove all rules withing the
                package that the app appears in */
            PrivilegeDb::getInstance().GetAppIdsForPkgId(pkgId, pkgContents);
            PrivilegeDb::getInstance().GetAppPrivileges(appId, uid, oldAppPrivileges);
            PrivilegeDb::getInstance().UpdateAppPrivileges(appId, uid, std::vector<std::string>());
            PrivilegeDb::getInstance().RemoveApplication(appId, uid, removePkg);
            CynaraAdmin::getInstance().UpdateAppPolicy(smackLabel, uidstr, oldAppPrivileges,
                                             std::vector<std::string>());
            PrivilegeDb::getInstance().CommitTransaction();
            LogDebug("Application uninstallation commited to database");
        }
    } catch (const PrivilegeDb::Exception::IOError &e) {
        LogError("Cannot access application database: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    } catch (const PrivilegeDb::Exception::InternalError &e) {
        PrivilegeDb::getInstance().RollbackTransaction();
        LogError("Error while removing application info from database: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    } catch (const CynaraException::Base &e) {
        PrivilegeDb::getInstance().RollbackTransaction();
        LogError("Error while setting Cynara rules for application: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        PrivilegeDb::getInstance().RollbackTransaction();
        LogError("Memory allocation while setting Cynara rules for application: " << e.what());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    }

    if (appExists) {

        if (removePkg) {
            LogDebug("Removing Smack rules for deleted pkgId " << pkgId);
            if (!SmackRules::uninstallPackageRules(pkgId)) {
                LogError("Error on uninstallation of package-specific smack rules");
                return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
            }
        }
        LogDebug ("Removing smack rules for deleted appId " << appId);
        if (!SmackRules::uninstallApplicationRules(appId, pkgId, pkgContents)) {
            LogError("Error during uninstallation of application-specific smack rules");
            return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
        }
    }

    return SECURITY_MANAGER_API_SUCCESS;
}

int getPkgId(const std::string &appId, std::string &pkgId)
{
    LogDebug("appId: " << appId);

    try {
        if (!PrivilegeDb::getInstance().GetAppPkgId(appId, pkgId)) {
            LogWarning("Application " << appId << " not found in database");
            return SECURITY_MANAGER_API_ERROR_NO_SUCH_OBJECT;
        } else {
            LogDebug("pkgId: " << pkgId);
        }
    } catch (const PrivilegeDb::Exception::Base &e) {
        LogError("Error while getting pkgId from database: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    }

    return SECURITY_MANAGER_API_SUCCESS;
}

int getAppGroups(const std::string &appId, uid_t uid, pid_t pid, std::unordered_set<gid_t> &gids)
{
    try {
        std::string pkgId;
        std::string smackLabel;
        std::string uidStr = std::to_string(uid);
        std::string pidStr = std::to_string(pid);

        LogDebug("appId: " << appId);

        if (!PrivilegeDb::getInstance().GetAppPkgId(appId, pkgId)) {
            LogWarning("Application " << appId << " not found in database");
            return SECURITY_MANAGER_API_ERROR_NO_SUCH_OBJECT;
        }
        LogDebug("pkgId: " << pkgId);
        if (!generatePkgLabel(pkgId, smackLabel)) {
            LogError("Cannot generate Smack label for pkgId: " << pkgId);
            return SECURITY_MANAGER_API_ERROR_NO_SUCH_OBJECT;
        }
        LogDebug("smack label: " << smackLabel);

        std::vector<std::string> privileges;
        PrivilegeDb::getInstance().GetPkgPrivileges(pkgId, uid, privileges);
        /*there is also a need of checking, if privilege is granted to all users*/
        size_t tmp = privileges.size();
        PrivilegeDb::getInstance().GetPkgPrivileges(pkgId, getGlobalUserId(), privileges);
        /*privileges needs to be sorted and with no duplications - for cynara sake*/
        std::inplace_merge(privileges.begin(), privileges.begin() + tmp, privileges.end());
        privileges.erase( unique( privileges.begin(), privileges.end() ), privileges.end() );

        for (const auto &privilege : privileges) {
            std::vector<std::string> gidsTmp;
            PrivilegeDb::getInstance().GetPrivilegeGroups(privilege, gidsTmp);
            if (!gidsTmp.empty()) {
                LogDebug("Considering privilege " << privilege << " with " <<
                    gidsTmp.size() << " groups assigned");
                if (Cynara::getInstance().check(smackLabel, privilege, uidStr, pidStr)) {
                    for_each(gidsTmp.begin(), gidsTmp.end(), [&] (std::string group)
                    {
                        struct group *grp = getgrnam(group.c_str());
                        if (grp == NULL) {
                                LogError("No such group: " << group.c_str());
                                return;
                        }
                        gids.insert(grp->gr_gid);
                    });
                    LogDebug("Cynara allowed, adding groups");
                } else
                    LogDebug("Cynara denied, not adding groups");
            }
        }
    } catch (const PrivilegeDb::Exception::Base &e) {
        LogError("Database error: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    } catch (const CynaraException::Base &e) {
        LogError("Error while querying Cynara for permissions: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation failed: " << e.what());
        return SECURITY_MANAGER_API_ERROR_OUT_OF_MEMORY;
    }

    return SECURITY_MANAGER_API_SUCCESS;
}

int userAdd(uid_t uidAdded, int userType, uid_t uid)
{
    if (uid != 0)
        return SECURITY_MANAGER_API_ERROR_AUTHENTICATION_FAILED;

    try {
        CynaraAdmin::getInstance().UserInit(uidAdded, static_cast<security_manager_user_type>(userType));
    } catch (CynaraException::InvalidParam &e) {
        return SECURITY_MANAGER_API_ERROR_INPUT_PARAM;
    }
    return SECURITY_MANAGER_API_SUCCESS;
}

int userDelete(uid_t uidDeleted, uid_t uid)
{
    int ret = SECURITY_MANAGER_API_SUCCESS;
    if (uid != 0)
        return SECURITY_MANAGER_API_ERROR_AUTHENTICATION_FAILED;

    /*Uninstall all user apps*/
    std::vector<std::string> userApps;
    try {
        PrivilegeDb::getInstance().GetUserApps(uidDeleted, userApps);
    } catch (const PrivilegeDb::Exception::Base &e) {
        LogError("Error while getting user apps from database: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    }

    for (auto &app: userApps) {
        if (appUninstall(app, uidDeleted) != SECURITY_MANAGER_API_SUCCESS) {
        /*if uninstallation of this app fails, just go on trying to uninstall another ones.
        we do not have anything special to do about that matter - user will be deleted anyway.*/
            ret = SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
        }
    }

    CynaraAdmin::getInstance().UserRemove(uidDeleted);

    return ret;
}

} /* namespace ServiceImpl */
} /* namespace SecurityManager */
