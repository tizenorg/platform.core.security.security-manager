/*
 *  Copyright (c) 2014-2015 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <sys/socket.h>

#include <cstring>
#include <algorithm>

#include <dpl/log/log.h>
#include <dpl/errno_string.h>
#include <tzplatform_config.h>

#include <config.h>
#include "protocols.h"
#include "privilege_db.h"
#include "cynara.h"
#include "smack-rules.h"
#include "smack-labels.h"
#include "security-manager.h"

#include "service_impl.h"

namespace SecurityManager {

static const std::string ADMIN_PRIVILEGE = "http://tizen.org/privilege/systemsettings.admin";
static const std::string SELF_PRIVILEGE = "http://tizen.org/privilege/systemsettings";

namespace {

static inline int validatePolicy(policy_entry &policyEntry, std::string uidStr, bool &forAdmin, CynaraAdminPolicy &cyap)
{
    LogDebug("Authenticating and validating policy update request for user with id: " << uidStr);
    LogDebug("[policy_entry] app: " << policyEntry.appName
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
        if (policyEntry.appName.empty()
            || policyEntry.privilege.empty()) {
            LogError("Bad admin update request");
            return SECURITY_MANAGER_ERROR_BAD_REQUEST;
        };

        if (!policyEntry.maxLevel.compare(SECURITY_MANAGER_DELETE)) {
            level = CYNARA_ADMIN_DELETE;
        } else {
            try {
                level = CynaraAdmin::getInstance().convertToPolicyType(policyEntry.maxLevel);
            } catch (const std::out_of_range& e) {
                LogError("policy max level cannot be: " << policyEntry.maxLevel);
                return SECURITY_MANAGER_ERROR_INPUT_PARAM;
            };
        };
        forAdmin = true;

    } else if (policyEntry.maxLevel.empty()) { //for self
        if (policyEntry.user.compare(uidStr)
            || !policyEntry.appName.compare(SECURITY_MANAGER_ANY)
            || !policyEntry.privilege.compare(SECURITY_MANAGER_ANY)
            || policyEntry.appName.empty()
            || policyEntry.privilege.empty()) {
            LogError("Bad privacy manager update request");
            return SECURITY_MANAGER_ERROR_BAD_REQUEST;
        };

        if (!policyEntry.currentLevel.compare(SECURITY_MANAGER_DELETE)) {
            level = CYNARA_ADMIN_DELETE;
        } else {
            try {
                level = CynaraAdmin::getInstance().convertToPolicyType(policyEntry.currentLevel);
            } catch (const std::out_of_range& e) {
                LogError("policy current level cannot be: " << policyEntry.currentLevel);
                return SECURITY_MANAGER_ERROR_INPUT_PARAM;
            };
        };
        forAdmin = false;

    } else { //neither => bad request
        return SECURITY_MANAGER_ERROR_BAD_REQUEST;
    };

    if (!policyEntry.user.compare(SECURITY_MANAGER_ANY))
        policyEntry.user = CYNARA_ADMIN_WILDCARD;
    if (!policyEntry.privilege.compare(SECURITY_MANAGER_ANY))
        policyEntry.privilege = CYNARA_ADMIN_WILDCARD;

    cyap = std::move(CynaraAdminPolicy(
        policyEntry.appName.compare(SECURITY_MANAGER_ANY) ?
            SmackLabels::generateAppLabel(policyEntry.appName) : CYNARA_ADMIN_WILDCARD,
        policyEntry.user,
        policyEntry.privilege,
        level,
        (forAdmin)?CynaraAdmin::Buckets.at(Bucket::ADMIN):CynaraAdmin::Buckets.at(Bucket::PRIVACY_MANAGER)));

    LogDebug("Policy update request authenticated and validated successfully");
    return SECURITY_MANAGER_SUCCESS;
}

bool isTizen2XVersion(const std::string &version)
{
    std::size_t notWhitePos = version.find_first_not_of(" \t");
    if (notWhitePos == std::string::npos)
        return false;
    if (version.at(notWhitePos) == '2')
        return true;
    return false;
}

class ScopedTransaction {
public:
    ScopedTransaction() : m_isCommited(false) {
        PrivilegeDb::getInstance().BeginTransaction();
    }
    ScopedTransaction(const ScopedTransaction &other) = delete;
    ScopedTransaction& operation(const ScopedTransaction &other) = delete;

    void commit() {
        PrivilegeDb::getInstance().CommitTransaction();
        m_isCommited = true;
    }
    ~ScopedTransaction() {
        if (!m_isCommited) {
            try {
                PrivilegeDb::getInstance().RollbackTransaction();
            } catch (const SecurityManager::Exception &e) {
                LogError("Transaction rollback failed: " << e.GetMessage());
            } catch(...) {
                LogError("Transaction rollback failed with unknown exception");
            }
        }
    }
private:
    bool m_isCommited;
};

} // end of anonymous namespace

ServiceImpl::ServiceImpl()
{
}

ServiceImpl::~ServiceImpl()
{
}

uid_t ServiceImpl::getGlobalUserId(void)
{
    static uid_t globaluid = tzplatform_getuid(TZ_SYS_GLOBALAPP_USER);
    return globaluid;
}

/**
 * Unifies user data of apps installed for all users
 * @param  uid            peer's uid - may be changed during process
 * @param  cynaraUserStr  string to which cynara user parameter will be put
 */
void ServiceImpl::checkGlobalUser(uid_t &uid, std::string &cynaraUserStr)
{
    static uid_t globaluid = getGlobalUserId();
    if (uid == 0 || uid == globaluid) {
        uid = globaluid;
        cynaraUserStr = CYNARA_ADMIN_WILDCARD;
    } else {
        cynaraUserStr = std::to_string(static_cast<unsigned int>(uid));
    }
}

bool ServiceImpl::isSubDir(const char *parent, const char *subdir)
{
    while (*parent && *subdir)
        if (*parent++ != *subdir++)
            return false;

    return (*subdir == '/' || *parent == *subdir);
}

bool ServiceImpl::getUserAppDir(const uid_t &uid, std::string &userAppDir)
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

bool ServiceImpl::installRequestAuthCheck(const app_inst_req &req, uid_t uid, std::string &appPath)
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
    correctPath << userAppDir << "/" << req.pkgName;
    LogDebug("correctPath: " << correctPath.str());

    for (const auto &path : req.appPaths) {
        std::unique_ptr<char, std::function<void(void*)>> real_path(
            realpath(path.first.c_str(), NULL), free);
        if (!real_path.get()) {
            LogError("realpath failed with '" << path.first.c_str()
                    << "' as parameter: " << GetErrnoString(errno));
            return false;
        }
        LogDebug("Requested path is '" << path.first.c_str()
                << "'. User's APPS_DIR is '" << userAppDir << "'");
        if (!isSubDir(correctPath.str().c_str(), real_path.get())) {
            LogWarning("Installation is outside correct path: " << correctPath.str() << "," << real_path.get());
            return false;
        }
    }
    return true;
}

int ServiceImpl::appInstall(const app_inst_req &req, uid_t uid)
{
    std::vector<std::string> addedPermissions;
    std::vector<std::string> removedPermissions;
    std::vector<std::string> pkgContents;
    std::string uidstr;
    std::string appPath;
    std::string appLabel;
    std::string pkgLabel;
    std::vector<std::string> allTizen2XApps, allTizen2XPackages;
    int authorId;

    if (uid) {
        if (uid != req.uid) {
            LogError("User " << uid <<
                     " is denied to install application for user " << req.uid);
            return SECURITY_MANAGER_ERROR_ACCESS_DENIED;
        }
    } else {
        if (req.uid)
            uid = req.uid;
    }
    checkGlobalUser(uid, uidstr);

    if (!installRequestAuthCheck(req, uid, appPath)) {
        LogError("Request from uid " << uid << " for app installation denied");
        return SECURITY_MANAGER_ERROR_AUTHENTICATION_FAILED;
    }

    try {
        appLabel = SmackLabels::generateAppLabel(req.appName);

        /* NOTE: we don't use pkgLabel here, but generate it for pkgName validation */
        pkgLabel = SmackLabels::generatePkgLabel(req.pkgName);
        LogDebug("Install parameters: appName: " << req.appName << ", pkgName: " << req.pkgName
                 << ", uidstr " << uidstr
                 << ", app label: " << appLabel << ", pkg label: " << pkgLabel
                 << ", target Tizen API ver: " << (req.tizenVersion.empty()?"unknown":req.tizenVersion));

        PrivilegeDb::getInstance().BeginTransaction();
        std::string pkg;
        PrivilegeDb::getInstance().GetAppPkgName(req.appName, pkg);
        if (!pkg.empty() && pkg != req.pkgName) {
            LogError("Application already installed with different package name");
            PrivilegeDb::getInstance().RollbackTransaction();
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        }

        PrivilegeDb::getInstance().AddApplication(req.appName, req.pkgName, uid, req.tizenVersion, req.authorName);
        PrivilegeDb::getInstance().UpdateAppPrivileges(req.appName, uid, req.privileges);
        /* Get all application ids in the package to generate rules withing the package */
        PrivilegeDb::getInstance().GetPkgApps(req.pkgName, pkgContents);
        PrivilegeDb::getInstance().GetAppAuthorId(req.appName, authorId);
        CynaraAdmin::getInstance().UpdateAppPolicy(appLabel, uidstr, req.privileges);

        // if app is targetted to Tizen 2.X, give other 2.X apps RO rules to it's shared dir
        if(isTizen2XVersion(req.tizenVersion))
            PrivilegeDb::getInstance().GetTizen2XAppsAndPackages(req.appName, allTizen2XApps, allTizen2XPackages);

        // WTF? Why this commit is here? Shouldn't it be at the end of this function?
        PrivilegeDb::getInstance().CommitTransaction();
        LogDebug("Application installation commited to database");
    } catch (const PrivilegeDb::Exception::IOError &e) {
        LogError("Cannot access application database: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const PrivilegeDb::Exception::InternalError &e) {
        PrivilegeDb::getInstance().RollbackTransaction();
        LogError("Error while saving application info to database: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const CynaraException::Base &e) {
        PrivilegeDb::getInstance().RollbackTransaction();
        LogError("Error while setting Cynara rules for application: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const SmackException::InvalidLabel &e) {
        PrivilegeDb::getInstance().RollbackTransaction();
        LogError("Error while generating Smack labels: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        PrivilegeDb::getInstance().RollbackTransaction();
        LogError("Memory allocation while setting Cynara rules for application: " << e.what());
        return SECURITY_MANAGER_ERROR_MEMORY;
    }

    try {
        if (!req.appPaths.empty())
            SmackLabels::setupAppBasePath(req.pkgName, appPath);

        // register paths
        for (const auto &appPath : req.appPaths) {
            const std::string &path = appPath.first;
            app_install_path_type pathType = static_cast<app_install_path_type>(appPath.second);
            SmackLabels::setupPath(req.pkgName, path, pathType, authorId);
        }

        LogDebug("Adding Smack rules for new appName: " << req.appName << " with pkgName: "
                << req.pkgName << ". Applications in package: " << pkgContents.size());
        SmackRules::installApplicationRules(req.appName, req.pkgName, authorId, pkgContents, allTizen2XApps, allTizen2XPackages);
    } catch (const SmackException::InvalidParam &e) {
        LogError("Invalid paramater during labeling: " << e.GetMessage());
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;
    } catch (const SmackException::Base &e) {
        LogError("Error while applying Smack policy for application: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SETTING_FILE_LABEL_FAILED;
    } catch (const SecurityManager::Exception &e) {
        LogError("Security Manager exception: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation error: " << e.what());
        return SECURITY_MANAGER_ERROR_MEMORY;
    }

    return SECURITY_MANAGER_SUCCESS;
}

int ServiceImpl::appUninstall(const std::string &appName, uid_t uid)
{
    std::string pkgName;
    std::string tizenVersion;
    std::string smackLabel;
    std::vector<std::string> pkgContents;
    bool removeApp = false;
    bool removePkg = false;
    bool removeAuthor = false;
    std::string uidstr;
    std::vector<std::string> allTizen2XApps;
    int authorId;

    checkGlobalUser(uid, uidstr);

    try {
        PrivilegeDb::getInstance().BeginTransaction();
        PrivilegeDb::getInstance().GetAppPkgName(appName, pkgName);
        if (pkgName.empty()) {
            LogWarning("Application " << appName <<
                " not found in database while uninstalling");
            PrivilegeDb::getInstance().RollbackTransaction();
            return SECURITY_MANAGER_SUCCESS;
        }

        smackLabel = SmackLabels::generateAppLabel(appName);
        LogDebug("Uninstall parameters: appName: " << appName << ", pkgName: " << pkgName
                 << ", uidstr " << uidstr << ", generated smack label: " << smackLabel);

        /* Before we remove the app from the database, let's fetch all apps in the package
            that this app belongs to, this will allow us to remove all rules withing the
            package that the app appears in */
        PrivilegeDb::getInstance().GetAppAuthorId(appName, authorId);
        PrivilegeDb::getInstance().GetPkgApps(pkgName, pkgContents);
        PrivilegeDb::getInstance().UpdateAppPrivileges(appName, uid, std::vector<std::string>());
        PrivilegeDb::getInstance().RemoveApplication(appName, uid, removeApp, removePkg, removeAuthor);

        // if uninstalled app is targetted to Tizen 2.X, remove other 2.X apps RO rules it's shared dir
        PrivilegeDb::getInstance().GetAppVersion(appName, tizenVersion);
        if (isTizen2XVersion(tizenVersion))
            PrivilegeDb::getInstance().GetTizen2XApps(appName, allTizen2XApps);

        CynaraAdmin::getInstance().UpdateAppPolicy(smackLabel, uidstr, std::vector<std::string>());

        PrivilegeDb::getInstance().CommitTransaction();
        LogDebug("Application uninstallation commited to database");
    } catch (const PrivilegeDb::Exception::IOError &e) {
        LogError("Cannot access application database: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const PrivilegeDb::Exception::InternalError &e) {
        PrivilegeDb::getInstance().RollbackTransaction();
        LogError("Error while removing application info from database: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const CynaraException::Base &e) {
        PrivilegeDb::getInstance().RollbackTransaction();
        LogError("Error while setting Cynara rules for application: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const SmackException::InvalidLabel &e) {
        PrivilegeDb::getInstance().RollbackTransaction();
        LogError("Error while generating Smack labels: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        PrivilegeDb::getInstance().RollbackTransaction();
        LogError("Memory allocation while setting Cynara rules for application: " << e.what());
        return SECURITY_MANAGER_ERROR_MEMORY;
    }

    try {
        if (removeApp) {
            LogDebug("Removing smack rules for deleted appName " << appName);
            SmackRules::uninstallApplicationRules(appName);
            LogDebug("Pkg rules are deprecated. We must uninstall them. pkgName " << pkgName);
            SmackRules::uninstallPackageRules(pkgName);
            if (!removePkg) {
                LogDebug("Creating new rules for pkgName " << pkgName);
                SmackRules::updatePackageRules(pkgName, pkgContents, allTizen2XApps);
            }
        }

        if (authorId != -1 && removeAuthor) {
            LogDebug("Removing Smack rules for authorId " << authorId);
            SmackRules::uninstallAuthorRules(authorId);
        }
    } catch (const SmackException::Base &e) {
        LogError("Error while removing Smack rules for application: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SETTING_FILE_LABEL_FAILED;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation error: " << e.what());
        return SECURITY_MANAGER_ERROR_MEMORY;
    }

    return SECURITY_MANAGER_SUCCESS;
}

int ServiceImpl::getPkgName(const std::string &appName, std::string &pkgName)
{
    LogDebug("appName: " << appName);

    try {
        PrivilegeDb::getInstance().GetAppPkgName(appName, pkgName);
        if (pkgName.empty()) {
            LogWarning("Application " << appName << " not found in database");
            return SECURITY_MANAGER_ERROR_NO_SUCH_OBJECT;
        } else {
            LogDebug("pkgName: " << pkgName);
        }
    } catch (const PrivilegeDb::Exception::Base &e) {
        LogError("Error while getting pkgName from database: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    }

    return SECURITY_MANAGER_SUCCESS;
}

int ServiceImpl::getAppGroups(
        const std::string &appName,
        uid_t uid,
        pid_t pid,
        std::unordered_set<gid_t> &gids)
{
    try {
        std::string pkgName;
        std::string smackLabel;
        std::string uidStr = std::to_string(uid);
        std::string pidStr = std::to_string(pid);

        LogDebug("appName: " << appName);

        PrivilegeDb::getInstance().GetAppPkgName(appName, pkgName);
        if (pkgName.empty()) {
            LogWarning("Application " << appName << " not found in database");
            return SECURITY_MANAGER_ERROR_NO_SUCH_OBJECT;
        }
        LogDebug("pkgName: " << pkgName);

        smackLabel = SmackLabels::generateAppLabel(appName);
        LogDebug("smack label: " << smackLabel);

        std::vector<std::string> privileges;
        PrivilegeDb::getInstance().GetPkgPrivileges(pkgName, uid, privileges);
        /*there is also a need of checking, if privilege is granted to all users*/
        size_t tmp = privileges.size();
        PrivilegeDb::getInstance().GetPkgPrivileges(pkgName, getGlobalUserId(), privileges);
        /*privileges needs to be sorted and with no duplications - for cynara sake*/
        std::inplace_merge(privileges.begin(), privileges.begin() + tmp, privileges.end());
        privileges.erase(unique(privileges.begin(), privileges.end()), privileges.end());

        for (const auto &privilege : privileges) {
            std::vector<std::string> gidsTmp;
            PrivilegeDb::getInstance().GetPrivilegeGroups(privilege, gidsTmp);
            if (!gidsTmp.empty()) {
                LogDebug("Considering privilege " << privilege << " with " <<
                    gidsTmp.size() << " groups assigned");
                // TODO: create method in Cynara class for fetching all privileges of an application
                if (Cynara::getInstance().check(smackLabel, privilege, uidStr, pidStr)) {
                    for_each(gidsTmp.begin(), gidsTmp.end(), [&] (std::string group) {
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
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const CynaraException::Base &e) {
        LogError("Error while querying Cynara for permissions: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const SmackException::InvalidLabel &e) {
        LogError("Error while generating Smack labels: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation failed: " << e.what());
        return SECURITY_MANAGER_ERROR_MEMORY;
    }

    return SECURITY_MANAGER_SUCCESS;
}

int ServiceImpl::userAdd(uid_t uidAdded, int userType, uid_t uid)
{
    if (uid != 0)
        return SECURITY_MANAGER_ERROR_AUTHENTICATION_FAILED;

    try {
        CynaraAdmin::getInstance().UserInit(uidAdded, static_cast<security_manager_user_type>(userType));
    } catch (CynaraException::InvalidParam &e) {
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;
    }
    return SECURITY_MANAGER_SUCCESS;
}

int ServiceImpl::userDelete(uid_t uidDeleted, uid_t uid)
{
    int ret = SECURITY_MANAGER_SUCCESS;
    if (uid != 0)
        return SECURITY_MANAGER_ERROR_AUTHENTICATION_FAILED;

    /*Uninstall all user apps*/
    std::vector<std::string> userApps;
    try {
        PrivilegeDb::getInstance().GetUserApps(uidDeleted, userApps);
    } catch (const PrivilegeDb::Exception::Base &e) {
        LogError("Error while getting user apps from database: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    }

    for (auto &app: userApps) {
        if (appUninstall(app, uidDeleted) != SECURITY_MANAGER_SUCCESS) {
        /*if uninstallation of this app fails, just go on trying to uninstall another ones.
        we do not have anything special to do about that matter - user will be deleted anyway.*/
            ret = SECURITY_MANAGER_ERROR_SERVER_ERROR;
        }
    }

    CynaraAdmin::getInstance().UserRemove(uidDeleted);

    return ret;
}

int ServiceImpl::policyUpdate(const std::vector<policy_entry> &policyEntries, uid_t uid, pid_t pid, const std::string &smackLabel)
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
            return SECURITY_MANAGER_ERROR_BAD_REQUEST;
        };

        if (!Cynara::getInstance().check(smackLabel, SELF_PRIVILEGE, uidStr, pidStr)) {
            LogError("Not enough permission to call: " << __FUNCTION__);
            return SECURITY_MANAGER_ERROR_ACCESS_DENIED;
        };

        std::vector<CynaraAdminPolicy> validatedPolicies;

        for (auto &entry : const_cast<std::vector<policy_entry>&>(policyEntries)) {
            bool forAdmin = false;
            CynaraAdminPolicy cyap("", "", "", CYNARA_ADMIN_NONE, "");
            int ret = validatePolicy(entry, uidStr, forAdmin, cyap);

            if (forAdmin && (isAdmin == NOT_CHECKED)) {
                isAdmin = Cynara::getInstance().check(smackLabel, ADMIN_PRIVILEGE, uidStr, pidStr)?IS_ADMIN:IS_NOT_ADMIN;
            };

            if (ret == SECURITY_MANAGER_SUCCESS) {
                if (!forAdmin
                    || (forAdmin && (isAdmin == IS_ADMIN))) {
                    validatedPolicies.push_back(std::move(cyap));
                } else {
                    LogError("Not enough privilege to enforce admin policy");
                    return SECURITY_MANAGER_ERROR_ACCESS_DENIED;
                };

            } else
                return ret;
        };

            // Apply updates
        CynaraAdmin::getInstance().SetPolicies(validatedPolicies);

    } catch (const CynaraException::Base &e) {
        LogError("Error while updating Cynara rules: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation error while updating Cynara rules: " << e.what());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    }

    return SECURITY_MANAGER_SUCCESS;
}

int ServiceImpl::getConfiguredPolicy(bool forAdmin, const policy_entry &filter, uid_t uid, pid_t pid,
    const std::string &smackLabel, std::vector<policy_entry> &policyEntries)
{
    try {
        std::string uidStr = std::to_string(uid);
        std::string pidStr = std::to_string(pid);

        if (!Cynara::getInstance().check(smackLabel, SELF_PRIVILEGE, uidStr, pidStr)) {
            LogError("Not enough permission to call: " << __FUNCTION__);
            return SECURITY_MANAGER_ERROR_ACCESS_DENIED;
        };

        LogDebug("Filter is: C: " << filter.appName
                    << ", U: " << filter.user
                    << ", P: " << filter.privilege
                    << ", current: " << filter.currentLevel
                    << ", max: " << filter.maxLevel
                    );

        std::vector<CynaraAdminPolicy> listOfPolicies;

        //convert appName to smack label
        std::string appLabel = filter.appName.compare(SECURITY_MANAGER_ANY) ? SmackLabels::generateAppLabel(filter.appName) : CYNARA_ADMIN_ANY;
        std::string user = filter.user.compare(SECURITY_MANAGER_ANY) ? filter.user : CYNARA_ADMIN_ANY;
        std::string privilege = filter.privilege.compare(SECURITY_MANAGER_ANY) ? filter.privilege : CYNARA_ADMIN_ANY;

        LogDebug("App: " << filter.appName << ", Label: " << appLabel);

        if (forAdmin) {
            if (!Cynara::getInstance().check(smackLabel, ADMIN_PRIVILEGE, uidStr, pidStr)) {
                LogError("Not enough privilege to access admin enforced policies: " << __FUNCTION__);
                return SECURITY_MANAGER_ERROR_ACCESS_DENIED;
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

            pe.appName = strcmp(policy.client, CYNARA_ADMIN_WILDCARD) ? SmackLabels::generateAppNameFromLabel(policy.client) : SECURITY_MANAGER_ANY;
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
                "[policy_entry] app: " << pe.appName
                << " user: " << pe.user
                << " privilege: " << pe.privilege
                << " current: " << pe.currentLevel
                << " max: " << pe.maxLevel
                );

            policyEntries.push_back(pe);
        };

    } catch (const CynaraException::Base &e) {
        LogError("Error while listing Cynara rules: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const SmackException::InvalidLabel &e) {
        LogError("Error while generating Smack labels: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation error while listing Cynara rules: " << e.what());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    }


    return SECURITY_MANAGER_SUCCESS;
}

int ServiceImpl::getPolicy(const policy_entry &filter, uid_t uid, pid_t pid, const std::string &smackLabel, std::vector<policy_entry> &policyEntries)
{
    try {
        std::string uidStr = std::to_string(uid);
        std::string pidStr = std::to_string(pid);

        if (!Cynara::getInstance().check(smackLabel, SELF_PRIVILEGE, uidStr, pidStr)) {
            LogWarning("Not enough permission to call: " << __FUNCTION__);
            return SECURITY_MANAGER_ERROR_ACCESS_DENIED;
        };

        LogDebug("Filter is: C: " << filter.appName
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

        for (const uid_t &user : listOfUsers) {
            LogDebug("User: " << user);
            std::string userStr = std::to_string(user);
            std::vector<std::string> listOfApps;

            if (filter.appName.compare(SECURITY_MANAGER_ANY)) {
                LogDebug("Limitting Cynara query to app: " << filter.appName);
                listOfApps.push_back(filter.appName);
            } else {
                PrivilegeDb::getInstance().GetUserApps(user, listOfApps);
                LogDebug("Found apps: " << listOfApps.size());
            };

            for (const std::string &appName : listOfApps) {
                LogDebug("App: " << appName);
                std::string smackLabelForApp = SmackLabels::generateAppLabel(appName);
                std::vector<std::string> listOfPrivileges;

                // FIXME: also fetch privileges of global applications
                // FIXME: fetch privileges from cynara, drop PrivilegeDb::GetAppPrivileges
                PrivilegeDb::getInstance().GetAppPrivileges(appName, user, listOfPrivileges);

                if (filter.privilege.compare(SECURITY_MANAGER_ANY)) {
                    LogDebug("Limitting Cynara query to privilege: " << filter.privilege);
                    // FIXME: this filtering should be already performed by method fetching the privileges
                    if (std::find(listOfPrivileges.begin(), listOfPrivileges.end(),
                        filter.privilege) == listOfPrivileges.end()) {
                        LogDebug("Application " << appName <<
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

                    pe.appName = appName;
                    pe.user = userStr;
                    pe.privilege = privilege;

                    pe.currentLevel = CynaraAdmin::getInstance().convertToPolicyDescription(
                        CynaraAdmin::getInstance().GetPrivilegeManagerCurrLevel(
                            smackLabelForApp, userStr, privilege));

                    pe.maxLevel = CynaraAdmin::getInstance().convertToPolicyDescription(
                        CynaraAdmin::getInstance().GetPrivilegeManagerMaxLevel(
                            smackLabelForApp, userStr, privilege));

                    LogDebug(
                        "[policy_entry] app: " << pe.appName
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
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const SmackException::InvalidLabel &e) {
        LogError("Error while generating Smack labels: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation error while listing Cynara rules: " << e.what());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    }

    return SECURITY_MANAGER_SUCCESS;
}

int ServiceImpl::policyGetDesc(std::vector<std::string> &levels)
{
    int ret = SECURITY_MANAGER_SUCCESS;

    try {
        CynaraAdmin::getInstance().ListPoliciesDescriptions(levels);
    } catch (const CynaraException::OutOfMemory &e) {
        LogError("Error - out of memory while querying Cynara for policy descriptions list: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_MEMORY;
    } catch (const CynaraException::InvalidParam &e) {
        LogError("Error - invalid parameter while querying Cynara for policy descriptions list: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;
    } catch (const CynaraException::ServiceNotAvailable &e) {
        LogError("Error - service not available while querying Cynara for policy descriptions list: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_NO_SUCH_SERVICE;
    } catch (const CynaraException::Base &e) {
        LogError("Error while getting policy descriptions list from Cynara: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    }

    return ret;
}

int ServiceImpl::policyGetGroups(std::vector<std::string> &groups)
{
    int ret = SECURITY_MANAGER_SUCCESS;

    try {
        PrivilegeDb::getInstance().GetGroups(groups);
    } catch (const PrivilegeDb::Exception::Base &e) {
        LogError("Error while getting groups from database: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    }

    return ret;
}

int ServiceImpl::appHasPrivilege(
        std::string appName,
        std::string privilege,
        uid_t uid,
        bool &result)
{
    try {
        std::string appLabel = SmackLabels::generateAppLabel(appName);
        std::string uidStr = std::to_string(uid);
        result = Cynara::getInstance().check(appLabel, privilege, uidStr, "");
        LogDebug("result = " << result);
    } catch (const CynaraException::Base &e) {
        LogError("Error while querying Cynara for permissions: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const SmackException::InvalidLabel &e) {
        LogError("Error while generating Smack labels: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation failed: " << e.what());
        return SECURITY_MANAGER_ERROR_MEMORY;
    } catch (...) {
        LogError("Unknown exception thrown");
        return SECURITY_MANAGER_ERROR_UNKNOWN;
    }
    return SECURITY_MANAGER_SUCCESS;
}


int ServiceImpl::dropOnePrivateSharing(
        const std::string &ownerAppName,
        const std::string &ownerPkgName,
        const std::vector<std::string> &ownerPkgContents,
        const std::string &targetAppName,
        const std::string &path)
{
    int errorRet;
    try {
        int targetPathCount, pathCount, ownerTargetCount;
        PrivilegeDb::getInstance().DropPrivateSharing(ownerAppName, targetAppName, path);
        PrivilegeDb::getInstance().GetTargetPathSharingCount(targetAppName, path, targetPathCount);
        PrivilegeDb::getInstance().GetPathSharingCount(path, pathCount);
        PrivilegeDb::getInstance().GetOwnerTargetSharingCount(ownerAppName, targetAppName, ownerTargetCount);
        if (targetPathCount > 0) {
            return SECURITY_MANAGER_SUCCESS;
        }
        if (pathCount < 1) {
            SmackLabels::setupPath(ownerPkgName, path, SECURITY_MANAGER_PATH_RW);
        }
        std::string pathLabel = SmackLabels::generateSharedPrivateLabel(ownerPkgName, path);
        SmackRules::dropPrivateSharingRules(ownerPkgName, ownerPkgContents, targetAppName, pathLabel,
                pathCount < 1, ownerTargetCount < 1);
        return SECURITY_MANAGER_SUCCESS;
    } catch (const SmackException::Base &e) {
        LogError("Error performing smack operation: " << e.GetMessage());
        errorRet = SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation failed: " << e.what());
        errorRet = SECURITY_MANAGER_ERROR_MEMORY;
    } catch (const std::exception &e) {
        LogError("Some exception thrown : " << e.what());
        errorRet = SECURITY_MANAGER_ERROR_UNKNOWN;
    } catch (...) {
        LogError("Unknown exception thrown");
        errorRet = SECURITY_MANAGER_ERROR_UNKNOWN;
    }
    return errorRet;
}

int ServiceImpl::applyPrivatePathSharing(
        const std::string &ownerAppName,
        const std::string &targetAppName,
        const std::vector<std::string> &paths)
{
    int errorRet;
    int sharingAdded = 0;
    std::string ownerPkgName;
    std::string targetPkgName;
    std::vector<std::string> pkgContents;

    try {
        PrivilegeDb::getInstance().GetAppPkgName(ownerAppName, ownerPkgName);
        if (ownerPkgName.empty()) {
            LogError(ownerAppName << " is not an installed application");
            return SECURITY_MANAGER_ERROR_APP_UNKNOWN;
        }

        PrivilegeDb::getInstance().GetAppPkgName(targetAppName, targetPkgName);
        if (targetPkgName.empty()) {
            LogError(targetAppName << " is not an installed application");
            return SECURITY_MANAGER_ERROR_APP_UNKNOWN;
        }

        for(const auto &path : paths) {
            std::string pathLabel = SmackLabels::getSmackLabelFromPath(path);
            if (pathLabel != SmackLabels::generatePkgLabel(ownerPkgName)) {
                std::string generatedPathLabel = SmackLabels::generateSharedPrivateLabel(ownerPkgName, path);
                if (generatedPathLabel != pathLabel) {
                    LogError("Path " << path << " has label " << pathLabel << " and dosen't belong"
                             " to application " << ownerAppName);
                    return SECURITY_MANAGER_ERROR_APP_NOT_PATH_OWNER;
                }
            }
        }
        if (ownerAppName == targetAppName) {
            LogDebug("Owner application is the same as target application");
            return SECURITY_MANAGER_SUCCESS;
        }

        if (ownerPkgName == targetPkgName) {
            LogDebug("Owner and target belong to the same package");
            return SECURITY_MANAGER_SUCCESS;
        }
        ScopedTransaction trans;
        PrivilegeDb::getInstance().GetPkgApps(ownerPkgName, pkgContents);
        for (const auto &path : paths) {
            int targetPathCount, pathCount, ownerTargetCount;
            PrivilegeDb::getInstance().GetTargetPathSharingCount(targetAppName, path, targetPathCount);
            PrivilegeDb::getInstance().GetPathSharingCount(path, pathCount);
            PrivilegeDb::getInstance().GetOwnerTargetSharingCount(ownerAppName, targetAppName, ownerTargetCount);
            std::string pathLabel = SmackLabels::generateSharedPrivateLabel(ownerPkgName, path);
            PrivilegeDb::getInstance().ApplyPrivateSharing(ownerAppName, targetAppName, path, pathLabel);
            sharingAdded++;
            if (targetPathCount > 0) {
                //Nothing to do, only counter needed incrementing
                continue;
            }
            if (pathCount <= 0) {
                SmackLabels::setupSharedPrivatePath(ownerPkgName, path);
            }

            SmackRules::applyPrivateSharingRules(ownerPkgName, pkgContents,
                targetAppName, pathLabel, (pathCount > 0), (ownerTargetCount > 0));
        }
        trans.commit();
        return SECURITY_MANAGER_SUCCESS;
    } catch (const SmackException::Base &e) {
        LogError("Error performing smack operation: " << e.GetMessage());
        errorRet = SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation failed: " << e.what());
        errorRet = SECURITY_MANAGER_ERROR_MEMORY;
    } catch (const std::exception &e) {
        LogError("Some exception thrown : " << e.what());
        errorRet = SECURITY_MANAGER_ERROR_UNKNOWN;
    } catch (...) {
        LogError("Unknown exception thrown");
        errorRet = SECURITY_MANAGER_ERROR_UNKNOWN;
    }

    for (int i = 0; i < sharingAdded; i++) {
        const std::string &path = paths[i];
        dropOnePrivateSharing(ownerAppName, ownerPkgName, pkgContents, targetAppName, path);
    }

    return errorRet;
}

int ServiceImpl::dropPrivatePathSharing(
        const std::string &ownerAppName,
        const std::string &targetAppName,
        const std::vector<std::string> &paths)
{
    int errorRet;
    try {
        std::string ownerPkgName;
        PrivilegeDb::getInstance().GetAppPkgName(ownerAppName, ownerPkgName);
        if (ownerPkgName.empty()) {
            LogError(ownerAppName << " is not an installed application");
            return SECURITY_MANAGER_ERROR_APP_UNKNOWN;
        }

        std::string targetPkgName;
        PrivilegeDb::getInstance().GetAppPkgName(targetAppName, targetPkgName);
        if (targetPkgName.empty()) {
            LogError(targetAppName << " is not an installed application");
            return SECURITY_MANAGER_ERROR_APP_UNKNOWN;
        }

        for(const auto &path : paths) {
            std::string pathLabel = SmackLabels::getSmackLabelFromPath(path);
            if (pathLabel != SmackLabels::generatePkgLabel(ownerPkgName)) {
                std::string generatedPathLabel = SmackLabels::generateSharedPrivateLabel(ownerPkgName, path);
                if (generatedPathLabel != pathLabel) {
                    LogError("Path " << path << " has label " << pathLabel << " and dosen't belong"
                             " to application " << ownerAppName);
                    return SECURITY_MANAGER_ERROR_APP_NOT_PATH_OWNER;
                }
            }
        }

        if (ownerAppName == targetAppName) {
            LogDebug("Owner application is the same as target application");
            return SECURITY_MANAGER_SUCCESS;
        }

        if (ownerPkgName == targetPkgName) {
            LogDebug("Owner and target belong to the same package");
            return SECURITY_MANAGER_SUCCESS;
        }

        std::vector<std::string> pkgContents;
        PrivilegeDb::getInstance().GetPkgApps(ownerPkgName, pkgContents);
        ScopedTransaction trans;
        for (const auto &path : paths) {
            int ret = dropOnePrivateSharing(ownerAppName, ownerPkgName, pkgContents, targetAppName, path);
            if (ret != SECURITY_MANAGER_SUCCESS) {
                return ret;
            }
        }
        trans.commit();
        return SECURITY_MANAGER_SUCCESS;
    } catch (const SmackException::Base &e) {
        LogError("Error performing smack operation: " << e.GetMessage());
        errorRet = SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation failed: " << e.what());
        errorRet = SECURITY_MANAGER_ERROR_MEMORY;
    } catch (const std::exception &e) {
        LogError("Some exception thrown : " << e.what());
        errorRet = SECURITY_MANAGER_ERROR_UNKNOWN;
    } catch (...) {
        LogError("Unknown exception thrown");
        errorRet = SECURITY_MANAGER_ERROR_UNKNOWN;
    }

    return errorRet;
}

} /* namespace SecurityManager */

