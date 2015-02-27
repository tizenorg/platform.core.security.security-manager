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
 * @author      Krzysztof Sasiak <k.sasiak@samsung.com>
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
#include "security-manager.h"

#include "service_impl.h"

namespace SecurityManager {
namespace ServiceImpl {

static const std::string ADMIN_PRIVILEGE = "http://tizen.org/privilege/systemsettings.admin";
static const std::string SELF_PRIVILEGE = "http://tizen.org/privilege/systemsettings";

namespace {

static inline int validatePolicy(policy_entry &policyEntry, std::string uidStr, bool &forAdmin, CynaraAdminPolicy &cyap)
{
    LogDebug("Authenticating and validating policy update request for user with id: " << uidStr);
    LogDebug("[policy_entry] app: " << policyEntry.appId
            << " user: " << policyEntry.user
            << " privilege: " << policyEntry.privilege
            << " current: " << policyEntry.currentLevel
            << " max: " << policyEntry.maxLevel);
    //automagically fill missing fields:
    if (policyEntry.user.empty()) {
        policyEntry.user = uidStr;
    };

    int level;

    if (policyEntry.currentLevel.empty()) { //for admin
        if (policyEntry.appId.empty()
            || policyEntry.privilege.empty()) {
            LogError("Bad admin update request");
            return SECURITY_MANAGER_API_ERROR_BAD_REQUEST;
        };

        if (!policyEntry.maxLevel.compare(SECURITY_MANAGER_DELETE)) {
            level = CYNARA_ADMIN_DELETE;
        } else {
            try {
                level = CynaraAdmin::getInstance().convertToPolicyType(policyEntry.maxLevel);
            } catch (const std::out_of_range& e) {
                LogError("policy max level cannot be: " << policyEntry.maxLevel);
                return SECURITY_MANAGER_API_ERROR_INPUT_PARAM;
            };
        };
        forAdmin = true;

    } else if (policyEntry.maxLevel.empty()) { //for self
        if (policyEntry.user.compare(uidStr)
            || !policyEntry.appId.compare(SECURITY_MANAGER_ANY)
            || !policyEntry.privilege.compare(SECURITY_MANAGER_ANY)
            || policyEntry.appId.empty()
            || policyEntry.privilege.empty()) {
            LogError("Bad privacy manager update request");
            return SECURITY_MANAGER_API_ERROR_BAD_REQUEST;
        };

        if (!policyEntry.currentLevel.compare(SECURITY_MANAGER_DELETE)) {
            level = CYNARA_ADMIN_DELETE;
        } else {
            try {
                level = CynaraAdmin::getInstance().convertToPolicyType(policyEntry.currentLevel);
            } catch (const std::out_of_range& e) {
                LogError("policy current level cannot be: " << policyEntry.currentLevel);
                return SECURITY_MANAGER_API_ERROR_INPUT_PARAM;
            };
        };
        forAdmin = false;

    } else { //neither => bad request
        return SECURITY_MANAGER_API_ERROR_BAD_REQUEST;
    };

    if (!policyEntry.user.compare(SECURITY_MANAGER_ANY))
        policyEntry.user = CYNARA_ADMIN_WILDCARD;
    if (!policyEntry.privilege.compare(SECURITY_MANAGER_ANY))
        policyEntry.privilege = CYNARA_ADMIN_WILDCARD;

    cyap = std::move(CynaraAdminPolicy(
        policyEntry.appId.compare(SECURITY_MANAGER_ANY) ?
            SmackLabels::generateAppLabel(policyEntry.appId) : CYNARA_ADMIN_WILDCARD,
        policyEntry.user,
        policyEntry.privilege,
        level,
        (forAdmin)?CynaraAdmin::Buckets.at(Bucket::ADMIN):CynaraAdmin::Buckets.at(Bucket::PRIVACY_MANAGER)));

    LogDebug("Policy update request authenticated and validated successfully");
    return SECURITY_MANAGER_API_SUCCESS;
}
} // end of anonymous namespace

static uid_t getGlobalUserId(void)
{
    static uid_t globaluid = tzplatform_getuid(TZ_SYS_GLOBALAPP_USER);
    return globaluid;
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

static bool getUserAppDir(const uid_t &uid, std::string &userAppDir)
{
    struct tzplatform_context *tz_ctx = nullptr;

    if (tzplatform_context_create(&tz_ctx))
            return false;

    if (tzplatform_context_set_user(tz_ctx, uid)) {
        tzplatform_context_destroy(tz_ctx);
        tz_ctx = nullptr;
        return false;
    }

    enum tzplatform_variable id =
            (uid == getGlobalUserId()) ? TZ_SYS_RW_APP : TZ_USER_APP;
    const char *appDir = tzplatform_context_getenv(tz_ctx, id);
    if (!appDir) {
        tzplatform_context_destroy(tz_ctx);
        tz_ctx = nullptr;
        return false;
    }

    userAppDir = appDir;

    tzplatform_context_destroy(tz_ctx);
    tz_ctx = nullptr;

    return true;
}

static inline bool installRequestAuthCheck(const app_inst_req &req, uid_t uid, bool &isCorrectPath, std::string &appPath)
{
    std::string userHome;
    std::string userAppDir;
    std::stringstream correctPath;

    if (uid != getGlobalUserId())
        LogDebug("Installation type: single user");
    else
        LogDebug("Installation type: global installation");

    if (!getUserAppDir(uid, userAppDir)) {
        LogError("Failed getting app dir for user uid: " << uid);
        return false;
    }

    appPath = userAppDir;
    correctPath.clear();
    correctPath << userAppDir << "/" << req.pkgId << "/" << req.appId;
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
                << "'. User's APPS_DIR is '" << userAppDir << "'");
        if (!isSubDir(userAppDir.c_str(), real_path.get())) {
            LogWarning("User's apps may have registered folders only in user's APPS_DIR");
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
    std::string appLabel;
    std::string pkgLabel;

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

    // create null terminated array of strings for permissions
    std::unique_ptr<const char *[]> pp_permissions(new const char* [req.privileges.size() + 1]);
    for (size_t i = 0; i < req.privileges.size(); ++i) {
        LogDebug("  Permission = " << req.privileges[i]);
        pp_permissions[i] = req.privileges[i].c_str();
    }
    pp_permissions[req.privileges.size()] = nullptr;

    try {
        std::vector<std::string> oldAppPrivileges;

        appLabel = SmackLabels::generateAppLabel(req.appId);
        /* NOTE: we don't use pkgLabel here, but generate it for pkgId validation */
        pkgLabel = SmackLabels::generatePkgLabel(req.pkgId);
        LogDebug("Install parameters: appId: " << req.appId << ", pkgId: " << req.pkgId
                 << ", uidstr " << uidstr
                 << ", app label: " << appLabel << ", pkg label: " << pkgLabel);

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
        CynaraAdmin::getInstance().UpdateAppPolicy(appLabel, uidstr, oldAppPrivileges,
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
    } catch (const SmackException::InvalidLabel &e) {
        PrivilegeDb::getInstance().RollbackTransaction();
        LogError("Error while generating Smack labels: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        PrivilegeDb::getInstance().RollbackTransaction();
        LogError("Memory allocation while setting Cynara rules for application: " << e.what());
        return SECURITY_MANAGER_API_ERROR_OUT_OF_MEMORY;
    }

    try {
        if (isCorrectPath)
            SmackLabels::setupCorrectPath(req.pkgId, req.appId, appPath);

        // register paths
        for (const auto &appPath : req.appPaths) {
            const std::string &path = appPath.first;
            app_install_path_type pathType = static_cast<app_install_path_type>(appPath.second);
            SmackLabels::setupPath(req.pkgId, path, pathType);
        }

        LogDebug("Adding Smack rules for new appId: " << req.appId << " with pkgId: "
                << req.pkgId << ". Applications in package: " << pkgContents.size());
        SmackRules::installApplicationRules(req.appId, req.pkgId, pkgContents);
    } catch (const SmackException::Base &e) {
        LogError("Error while applying Smack policy for application: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SETTING_FILE_LABEL_FAILED;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation error: " << e.what());
        return SECURITY_MANAGER_API_ERROR_OUT_OF_MEMORY;
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
            smackLabel = SmackLabels::generateAppLabel(appId);
            LogDebug("Uninstall parameters: appId: " << appId << ", pkgId: " << pkgId
                     << ", uidstr " << uidstr << ", generated smack label: " << smackLabel);

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
    } catch (const SmackException::InvalidLabel &e) {
        PrivilegeDb::getInstance().RollbackTransaction();
        LogError("Error while generating Smack labels: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        PrivilegeDb::getInstance().RollbackTransaction();
        LogError("Memory allocation while setting Cynara rules for application: " << e.what());
        return SECURITY_MANAGER_API_ERROR_OUT_OF_MEMORY;
    }

    try {
        if (appExists) {
            if (removePkg) {
                LogDebug("Removing Smack rules for deleted pkgId " << pkgId);
                SmackRules::uninstallPackageRules(pkgId);
            }

            LogDebug("Removing smack rules for deleted appId " << appId);
            SmackRules::uninstallApplicationRules(appId, pkgId, pkgContents);
        }
    } catch (const SmackException::Base &e) {
        LogError("Error while removing Smack rules for application: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SETTING_FILE_LABEL_FAILED;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation error: " << e.what());
        return SECURITY_MANAGER_API_ERROR_OUT_OF_MEMORY;
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

        smackLabel = SmackLabels::generatePkgLabel(pkgId);
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
    } catch (const SmackException::InvalidLabel &e) {
        LogError("Error while generating Smack labels: " << e.DumpToString());
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

int policyUpdate(const std::vector<policy_entry> &policyEntries, uid_t uid, pid_t pid, const std::string &smackLabel)
{
    enum {
        NOT_CHECKED,
        IS_NOT_ADMIN,
        IS_ADMIN
    }  isAdmin = NOT_CHECKED;

    try {
        std::string uidStr = std::to_string(uid);
        std::string pidStr = std::to_string(pid);

        if (policyEntries.size() == 0) {
            LogError("Validation failed: policy update request is empty");
            return SECURITY_MANAGER_API_ERROR_BAD_REQUEST;
        };

        if (!Cynara::getInstance().check(smackLabel, SELF_PRIVILEGE, uidStr, pidStr)) {
            LogError("Not enough permission to call: " << __FUNCTION__);
            return SECURITY_MANAGER_API_ERROR_ACCESS_DENIED;
        };

        std::vector<CynaraAdminPolicy> validatedPolicies;

        for (auto &entry : const_cast<std::vector<policy_entry>&>(policyEntries)) {
            bool forAdmin = false;
            CynaraAdminPolicy cyap("", "", "", CYNARA_ADMIN_NONE, "");
            int ret = validatePolicy(entry, uidStr, forAdmin, cyap);

            if (forAdmin && (isAdmin == NOT_CHECKED)) {
                isAdmin = Cynara::getInstance().check(smackLabel, ADMIN_PRIVILEGE, uidStr, pidStr)?IS_ADMIN:IS_NOT_ADMIN;
            };

            if (ret == SECURITY_MANAGER_API_SUCCESS) {
                if (!forAdmin
                    || (forAdmin && (isAdmin == IS_ADMIN))) {
                    validatedPolicies.push_back(std::move(cyap));
                } else {
                    LogError("Not enough privilege to enforce admin policy");
                    return SECURITY_MANAGER_API_ERROR_ACCESS_DENIED;
                };

            } else
                return ret;
        };

            // Apply updates
        CynaraAdmin::getInstance().SetPolicies(validatedPolicies);

    } catch (const CynaraException::Base &e) {
        LogError("Error while updating Cynara rules: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation error while updating Cynara rules: " << e.what());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    }

    return SECURITY_MANAGER_API_SUCCESS;
}

int getConfiguredPolicy(bool forAdmin, const policy_entry &filter, uid_t uid, pid_t pid,
    const std::string &smackLabel, std::vector<policy_entry> &policyEntries)
{
    try {
        std::string uidStr = std::to_string(uid);
        std::string pidStr = std::to_string(pid);

        if (!Cynara::getInstance().check(smackLabel, SELF_PRIVILEGE, uidStr, pidStr)) {
            LogError("Not enough permission to call: " << __FUNCTION__);
            return SECURITY_MANAGER_API_ERROR_ACCESS_DENIED;
        };

        LogDebug("Filter is: C: " << filter.appId
                    << ", U: " << filter.user
                    << ", P: " << filter.privilege
                    << ", current: " << filter.currentLevel
                    << ", max: " << filter.maxLevel
                    );

        std::vector<CynaraAdminPolicy> listOfPolicies;

        //convert appId to smack label
        std::string appLabel = filter.appId.compare(SECURITY_MANAGER_ANY) ? SmackLabels::generateAppLabel(filter.appId) : CYNARA_ADMIN_ANY;
        std::string user = filter.user.compare(SECURITY_MANAGER_ANY) ? filter.user : CYNARA_ADMIN_ANY;
        std::string privilege = filter.privilege.compare(SECURITY_MANAGER_ANY) ? filter.privilege : CYNARA_ADMIN_ANY;

        LogDebug("App: " << filter.appId << ", Label: " << appLabel);

        if (forAdmin) {
            if (!Cynara::getInstance().check(smackLabel, ADMIN_PRIVILEGE, uidStr, pidStr)) {
                LogError("Not enough privilege to access admin enforced policies: " << __FUNCTION__);
                return SECURITY_MANAGER_API_ERROR_ACCESS_DENIED;
                };

            //Fetch privileges from ADMIN bucket
            CynaraAdmin::getInstance().ListPolicies(
                CynaraAdmin::Buckets.at(Bucket::ADMIN),
                appLabel,
                user,
                privilege,
                listOfPolicies
                );
            LogDebug("ADMIN - number of policies matched: " << listOfPolicies.size());
        } else {
            if (uidStr.compare(user)) {
                if (!Cynara::getInstance().check(smackLabel, ADMIN_PRIVILEGE, uidStr, pidStr)) {
                    LogWarning("Not enough privilege to access other user's personal policies. Limiting query to personal privileges.");
                    user = uidStr;
                };
            };
            //Fetch privileges from PRIVACY_MANAGER bucket
            CynaraAdmin::getInstance().ListPolicies(
                CynaraAdmin::Buckets.at(Bucket::PRIVACY_MANAGER),
                appLabel,
                user,
                privilege,
                listOfPolicies
                );
            LogDebug("PRIVACY MANAGER - number of policies matched: " << listOfPolicies.size());
        };

        for (const auto &policy : listOfPolicies) {
            //ignore "jump to bucket" entries
            if (policy.result ==  CYNARA_ADMIN_BUCKET)
                continue;

            policy_entry pe;

            pe.appId = strcmp(policy.client, CYNARA_ADMIN_WILDCARD) ? SmackLabels::generateAppNameFromLabel(policy.client) : SECURITY_MANAGER_ANY;
            pe.user =  strcmp(policy.user, CYNARA_ADMIN_WILDCARD) ? policy.user : SECURITY_MANAGER_ANY;
            pe.privilege = strcmp(policy.privilege, CYNARA_ADMIN_WILDCARD) ? policy.privilege : pe.privilege = SECURITY_MANAGER_ANY;
            pe.currentLevel = CynaraAdmin::getInstance().convertToPolicyDescription(policy.result);

            if (!forAdmin) {
                // All policy entries in PRIVACY_MANAGER should be fully-qualified
                pe.maxLevel = CynaraAdmin::getInstance().convertToPolicyDescription(
                    CynaraAdmin::getInstance().GetPrivilegeManagerMaxLevel(
                        policy.client, policy.user, policy.privilege));
            } else {
                // Cannot reliably calculate maxLavel for policies from ADMIN bucket
                pe.maxLevel = CynaraAdmin::getInstance().convertToPolicyDescription(CYNARA_ADMIN_ALLOW);
            }


            LogDebug(
                "[policy_entry] app: " << pe.appId
                << " user: " << pe.user
                << " privilege: " << pe.privilege
                << " current: " << pe.currentLevel
                << " max: " << pe.maxLevel
                );

            policyEntries.push_back(pe);
        };

    } catch (const CynaraException::Base &e) {
        LogError("Error while listing Cynara rules: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    } catch (const SmackException::InvalidLabel &e) {
        LogError("Error while generating Smack labels: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation error while listing Cynara rules: " << e.what());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    }


    return SECURITY_MANAGER_API_SUCCESS;
}

int getPolicy(const policy_entry &filter, uid_t uid, pid_t pid, const std::string &smackLabel, std::vector<policy_entry> &policyEntries)
{
    try {
        std::string uidStr = std::to_string(uid);
        std::string pidStr = std::to_string(pid);

        if (!Cynara::getInstance().check(smackLabel, SELF_PRIVILEGE, uidStr, pidStr)) {
            LogWarning("Not enough permission to call: " << __FUNCTION__);
            return SECURITY_MANAGER_API_ERROR_ACCESS_DENIED;
        };

        LogDebug("Filter is: C: " << filter.appId
                    << ", U: " << filter.user
                    << ", P: " << filter.privilege
                    << ", current: " << filter.currentLevel
                    << ", max: " << filter.maxLevel
                    );

        std::vector<uid_t> listOfUsers;

        if (Cynara::getInstance().check(smackLabel, ADMIN_PRIVILEGE, uidStr, pidStr)) {
            LogDebug("User is privileged");
            if (filter.user.compare(SECURITY_MANAGER_ANY)) {
                LogDebug("Limitting Cynara query to user: " << filter.user);
                try {
                    listOfUsers.push_back(static_cast<uid_t>(std::stoul(filter.user)));
                } catch (std::invalid_argument &e) {
                    LogError("Invalid UID: " << e.what());
                };
            } else
                CynaraAdmin::getInstance().ListUsers(listOfUsers);
        } else {
            LogWarning("Not enough privilege to fetch user policy for all users by user: " << uid);
            LogDebug("Fetching personal policy for user: " << uid);
            listOfUsers.push_back(uid);
        };
        LogDebug("Fetching policy for " << listOfUsers.size() << " users");

        for (const uid_t &uid : listOfUsers) {
            LogDebug("User: " << uid);
            std::string userStr = std::to_string(uid);
            std::vector<std::string> listOfApps;

            if (filter.appId.compare(SECURITY_MANAGER_ANY)) {
                LogDebug("Limitting Cynara query to app: " << filter.appId);
                listOfApps.push_back(filter.appId);
            } else {
                PrivilegeDb::getInstance().GetUserApps(uid, listOfApps);
                LogDebug("Found apps: " << listOfApps.size());
            };

            for (const std::string &appId : listOfApps) {
                LogDebug("App: " << appId);
                std::string smackLabelForApp = SmackLabels::generateAppLabel(appId);
                std::vector<std::string> listOfPrivileges;

                // FIXME: also fetch privileges of global applications
                PrivilegeDb::getInstance().GetAppPrivileges(appId, uid, listOfPrivileges);

                if (filter.privilege.compare(SECURITY_MANAGER_ANY)) {
                    LogDebug("Limitting Cynara query to privilege: " << filter.privilege);
                    // FIXME: this filtering should be already performed by method fetching the privileges
                    if (std::find(listOfPrivileges.begin(), listOfPrivileges.end(),
                        filter.privilege) == listOfPrivileges.end()) {
                        LogDebug("Application " << appId <<
                            " doesn't have the filteres privilege " << filter.privilege);
                        continue;
                    }
                    listOfPrivileges.clear();
                    listOfPrivileges.push_back(filter.privilege);
                }

                LogDebug("Privileges matching filter - " << filter.privilege << ": " << listOfPrivileges.size());

                for (const std::string &privilege : listOfPrivileges) {
                    LogDebug("Privilege: " << privilege);
                    policy_entry pe;

                    pe.appId = appId;
                    pe.user = userStr;
                    pe.privilege = privilege;

                    pe.currentLevel = CynaraAdmin::getInstance().convertToPolicyDescription(
                        CynaraAdmin::getInstance().GetPrivilegeManagerCurrLevel(
                            smackLabelForApp, userStr, privilege));

                    pe.maxLevel = CynaraAdmin::getInstance().convertToPolicyDescription(
                        CynaraAdmin::getInstance().GetPrivilegeManagerMaxLevel(
                            smackLabelForApp, userStr, privilege));

                    LogDebug(
                        "[policy_entry] app: " << pe.appId
                        << " user: " << pe.user
                        << " privilege: " << pe.privilege
                        << " current: " << pe.currentLevel
                        << " max: " << pe.maxLevel
                        );

                    policyEntries.push_back(pe);
                };
            };
        };

    } catch (const CynaraException::Base &e) {
        LogError("Error while listing Cynara rules: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    } catch (const SmackException::InvalidLabel &e) {
        LogError("Error while generating Smack labels: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation error while listing Cynara rules: " << e.what());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    }

    return SECURITY_MANAGER_API_SUCCESS;
}

int policyGetDesc(std::vector<std::string> &levels)
{
    int ret = SECURITY_MANAGER_API_SUCCESS;

    try {
        CynaraAdmin::getInstance().ListPoliciesDescriptions(levels);
    } catch (const CynaraException::OutOfMemory &e) {
        LogError("Error - out of memory while querying Cynara for policy descriptions list: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_OUT_OF_MEMORY;
    } catch (const CynaraException::InvalidParam &e) {
        LogError("Error - invalid parameter while querying Cynara for policy descriptions list: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_INPUT_PARAM;
    } catch (const CynaraException::ServiceNotAvailable &e) {
        LogError("Error - service not available while querying Cynara for policy descriptions list: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_NO_SUCH_SERVICE;
    } catch (const CynaraException::Base &e) {
        LogError("Error while getting policy descriptions list from Cynara: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    }

    return ret;
}

} /* namespace ServiceImpl */
} /* namespace SecurityManager */
