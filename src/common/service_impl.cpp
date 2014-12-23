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

#include <dirent.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>

#include <cstring>
#include <algorithm>
#include <fstream>
#include <climits>

#include <dpl/log/log.h>
#include <tzplatform_config.h>
#include <boost/algorithm/string.hpp>

#include "protocols.h"
#include "privilege_db.h"
#include "cynara.h"
#include "smack-common.h"
#include "smack-rules.h"
#include "smack-labels.h"
#include "usertype-profile.h"

#include "service_impl.h"

namespace SecurityManager {
namespace ServiceImpl {

static const std::string privilegesListFileName = "privileges-tizen.list";
static const std::string privilegesListFile = std::string(USERTYPE_POLICY_PATH) +
                                              "/" + privilegesListFileName;
static std::vector<std::string> allPrivileges;

namespace {

inline bool policyValidateForAdmin(
        const std::vector<SecurityManager::PolicyUpdateUnit> &policyUnits, uid_t uid,
        std::string &userStr)
{
    LogDebug("Authenticating and validating policy update request for user with id: " << uid);
    if (policyUnits.size() == 0) {
        LogError("Validation failed: policy update request is empty");
        return SECURITY_MANAGER_API_ERROR_BAD_REQUEST;
    }

    /*
    TODO: check in cynara if user has permission to set the policy
    */

    userStr = std::to_string(static_cast<unsigned int>(uid));
    bool valid = true; // print all validation logs, do not return immediately

    for (auto &unit : policyUnits) {

        // perform additional length check
        if (unit.appId.length() == 0
         || unit.userId.length() == 0
         || unit.privilege.length() == 0) {
            LogError("Error while validating policy update unit, requested by user: " << userStr
                    << ", policy unit: [userId: " << unit.userId << ", appId: " << unit.appId
                    << ", privilege: " << unit.privilege << ", userType: " << unit.userType
                    << ", value: " << unit.value << "]");
            valid = false;
        }

    } // end for

    if (valid == false)
        return SECURITY_MANAGER_API_ERROR_BAD_REQUEST;

    LogDebug("Policy update request authenticated and validated successfully");
    return SECURITY_MANAGER_API_SUCCESS;
}

inline bool policyValidateForSelf(
        const std::vector<SecurityManager::PolicyUpdateUnit> &policyUnits, uid_t uid,
        std::string &userStr)
{
    LogDebug("Authenticating and validating policy update request for user with id: " << uid);
    if (policyUnits.size() == 0) {
        LogError("Validation failed: policy update request is empty");
        return SECURITY_MANAGER_API_ERROR_BAD_REQUEST;
    }

    userStr = std::to_string(static_cast<unsigned int>(uid));
    bool valid = true; // print all validation logs, do not return immediately

    for (auto &unit : policyUnits) {
        /*
        accept only per user privileges,
        uid in update unit has to be the same as the sender uid,
        app cannot be a wildcard,
        privilege cannot be a wildcard
        */
        if (unit.userOrType == UO_IS_TYPE
            || !unit.userId.compare(userStr)
            || unit.appId.compare(SECURITY_MANAGER_ANY)
            || unit.privilege.compare(SECURITY_MANAGER_ANY)) {
            // on auth error, return immediately
            return SECURITY_MANAGER_API_ERROR_AUTHENTICATION_FAILED;
        }

        //TODO: check for each of the privileges if the result is >= than the possible minimum

        // perform additional length check
        if (unit.appId.length() == 0
         || unit.userId.length() == 0
         || unit.privilege.length() == 0) {
            LogError("Error while validating policy update unit, requested by user: " << userStr
                    << ", policy unit: [userId: " << unit.userId << ", appId: " << unit.appId
                    << ", privilege: " << unit.privilege << ", userType: " << unit.userType
                    << ", value: " << unit.value << "]");
            valid = false;
        }

    } // end for

    if (valid == false)
        return SECURITY_MANAGER_API_ERROR_BAD_REQUEST;

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

static inline bool installRequestAuthCheck(const app_inst_req &req, uid_t uid)
{
    struct passwd *pwd;
    do {
        errno = 0;
        pwd = getpwuid(uid);
        if (!pwd && errno != EINTR) {
            LogError("getpwuid failed with '" << uid
                    << "' as parameter: " << strerror(errno));
            return false;
        }
    } while (!pwd);

    std::unique_ptr<char, std::function<void(void*)>> home(
        realpath(pwd->pw_dir, NULL), free);
    if (!home.get()) {
            LogError("realpath failed with '" << pwd->pw_dir
                    << "' as parameter: " << strerror(errno));
            return false;
    }

    for (const auto &appPath : req.appPaths) {
        std::unique_ptr<char, std::function<void(void*)>> real_path(
            realpath(appPath.first.c_str(), NULL), free);
        if (!real_path.get()) {
            LogError("realpath failed with '" << appPath.first.c_str()
                    << "' as parameter: " << strerror(errno));
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

int appInstall(const app_inst_req &req, uid_t uid)
{
    bool pkgIdIsNew = false;
    std::vector<std::string> addedPermissions;
    std::vector<std::string> removedPermissions;

    std::string uidstr;
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
            << ", generated smack label: " << smackLabel);

    // create null terminated array of strings for permissions
    std::unique_ptr<const char *[]> pp_permissions(new const char* [req.privileges.size() + 1]);
    for (size_t i = 0; i < req.privileges.size(); ++i) {
        LogDebug("  Permission = " << req.privileges[i]);
        pp_permissions[i] = req.privileges[i].c_str();
    }
    pp_permissions[req.privileges.size()] = nullptr;

    try {
        std::vector<std::string> oldPkgPrivileges, newPkgPrivileges;

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
        PrivilegeDb::getInstance().GetPkgPrivileges(req.pkgId, uid, oldPkgPrivileges);
        PrivilegeDb::getInstance().AddApplication(req.appId, req.pkgId, uid, pkgIdIsNew);
        PrivilegeDb::getInstance().UpdateAppPrivileges(req.appId, uid, req.privileges);
        PrivilegeDb::getInstance().GetPkgPrivileges(req.pkgId, uid, newPkgPrivileges);
        CynaraAdmin::UpdatePackagePolicy(smackLabel, uidstr, oldPkgPrivileges,
                                         newPkgPrivileges);
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

    if (pkgIdIsNew) {
        LogDebug("Adding Smack rules for new pkgId " << req.pkgId);
        if (!SmackRules::installPackageRules(req.pkgId)) {
            LogError("Failed to apply package-specific smack rules");
            return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
        }
    }

    return SECURITY_MANAGER_API_SUCCESS;
}

int appUninstall(const std::string &appId, uid_t uid)
{
    std::string pkgId;
    std::string smackLabel;
    bool appExists = true;
    bool removePkg = false;
    std::string uidstr;
    checkGlobalUser(uid, uidstr);

    try {
        std::vector<std::string> oldPkgPrivileges, newPkgPrivileges;

        PrivilegeDb::getInstance().BeginTransaction();
        if (!PrivilegeDb::getInstance().GetAppPkgId(appId, pkgId)) {
            LogWarning("Application " << appId <<
                " not found in database while uninstalling");
            PrivilegeDb::getInstance().RollbackTransaction();
            appExists = false;
        } else {

            LogDebug("Uninstall parameters: appId: " << appId << ", pkgId: " << pkgId
                     << ", uidstr " << uidstr << ", generated smack label: " << smackLabel);

            if (!generateAppLabel(pkgId, smackLabel)) {
                LogError("Cannot generate Smack label for package: " << pkgId);
                return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
            }

            PrivilegeDb::getInstance().GetPkgPrivileges(pkgId, uid, oldPkgPrivileges);
            PrivilegeDb::getInstance().UpdateAppPrivileges(appId, uid, std::vector<std::string>());
            PrivilegeDb::getInstance().RemoveApplication(appId, uid, removePkg);
            PrivilegeDb::getInstance().GetPkgPrivileges(pkgId, uid, newPkgPrivileges);
            CynaraAdmin::UpdatePackagePolicy(smackLabel, uidstr, oldPkgPrivileges,
                                             newPkgPrivileges);
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

        if (!generateAppLabel(pkgId, smackLabel)) {
             LogError("Cannot generate Smack label for package: " << pkgId);
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

    switch (userType) {
    case SM_USER_TYPE_SYSTEM:
    case SM_USER_TYPE_ADMIN:
    case SM_USER_TYPE_GUEST:
    case SM_USER_TYPE_NORMAL:
        break;
    default:
        return SECURITY_MANAGER_API_ERROR_INPUT_PARAM;
    }

    //TODO add policy information to cynara regarding user default privileges based on user_type
    (void) uidAdded;
    (void) userType;

    return SECURITY_MANAGER_API_SUCCESS;
}

int userDelete(uid_t uidDeleted, uid_t uid)
{
    int ret = SECURITY_MANAGER_API_SUCCESS;
    if (uid != 0)
        return SECURITY_MANAGER_API_ERROR_AUTHENTICATION_FAILED;

    //TODO remove policy information from cynara

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

    return ret;
}

int reloadUserTypePolicy(uid_t uid)
{
    int ret = SECURITY_MANAGER_API_SUCCESS;
    struct dirent *ent;
    DIR *dir = opendir(USERTYPE_POLICY_PATH);

    if (uid != 0) {
        return SECURITY_MANAGER_API_ERROR_ACCESS_DENIED;
    }

    if (dir != NULL) {
        while ((ent = readdir(dir))) {
            if (ent->d_type == DT_REG) {
                try {
                    std::ostringstream realPath;
                    realPath << USERTYPE_POLICY_PATH << "/" << ent->d_name;
                    std::string path = std::string(ent->d_name);
                    int start_pos = std::string("usertype-").length();
                    int count = path.find(".profile") -  std::string("usertype-").length();
                    std::string userType = path.substr(start_pos, count);
                    LogDebug("Opening usertype profile: " << userType << ", path: " << realPath.str());
                    std::vector<UserTypePrivilege> privileges;
                    UserTypeProfile utp = UserTypeProfile(realPath.str());
                    utp.getPrivilegesList(privileges);
                    CynaraAdmin::DefineUserTypePolicy(userType, privileges);
                } catch (UserTypeProfileException::FileAccessError) {
                    ret = SECURITY_MANAGER_API_ERROR_FILE_NOT_EXIST;
                    break;
                } catch (UserTypeProfileException::FileParsingError) {
                    ret = SECURITY_MANAGER_API_ERROR_FILE_FORMAT_MALFORMED;
                    break;
                } catch (CynaraException::Base) {
                    ret = SECURITY_MANAGER_API_ERROR_UNKNOWN;
                    break;
                };
            };
        };
        closedir(dir);
    } else ret = SECURITY_MANAGER_API_ERROR_FILE_NOT_EXIST;

    return ret;
}

int loadPrivileges(bool reload)
{
    if ((allPrivileges.size() == 0) || (reload)) {
        LogDebug("Loading privileges file '" << privilegesListFileName << "'");
        allPrivileges.clear();
        std::ifstream fs(privilegesListFile);
        if (!fs.is_open())
            return SECURITY_MANAGER_API_ERROR_FILE_NOT_EXIST;
        for (std::string line; std::getline(fs, line); ) {
            boost::algorithm::trim(line);
            if (line.empty() || (line[0] == '\''))
                continue;
            LogDebug(privilegesListFileName << ": " << line);
            allPrivileges.push_back(line);
        }
    } else {
        LogDebug("Privileges list is already loaded and not forced to reload.");
    }
    return allPrivileges.size() > 0 ?
           SECURITY_MANAGER_API_SUCCESS :
           SECURITY_MANAGER_API_ERROR_LOADING_PRIVILEGES_LIST;
}

int getAllSystemPrivileges(std::vector<std::string> &privilegesList)
{
    int ret = SECURITY_MANAGER_API_SUCCESS;

    if (allPrivileges.size() == 0)
        ret = loadPrivileges();
    if (SECURITY_MANAGER_API_SUCCESS == ret)
        privilegesList = allPrivileges;

    return ret;
}

int bucketsInit(uid_t uidInContext)
{
    if (uidInContext != 0)
        return SECURITY_MANAGER_API_ERROR_AUTHENTICATION_FAILED;

    CynaraAdmin::getInstance().InitBuckets();

    return SECURITY_MANAGER_API_SUCCESS;
}

int policyUpdateForAdmin(const std::vector<SecurityManager::PolicyUpdateUnit> &policyUnits, uid_t uid)
{
    std::string userStr;

    // Start with authentication and validation
    int ret = policyValidateForAdmin(policyUnits, uid, userStr);
    if (ret != SECURITY_MANAGER_API_SUCCESS)
        return ret;

    try {
        // Apply updates
        //TODO: change hardcoded name to enum/map value
        CynaraAdmin::getInstance().SetPolicies(policyUnits, "ADMIN");

    } catch (const CynaraException::Base &e) {
        LogError("Error while updating Cynara rules: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation error while updating Cynara rules: " << e.what());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    }

    return SECURITY_MANAGER_API_SUCCESS;
}

int policyUpdateForSelf(const std::vector<SecurityManager::PolicyUpdateUnit> &policyUnits, uid_t uid)
{
    std::string userStr;

    // Start with authentication and validation
    int ret = policyValidateForSelf(policyUnits, uid, userStr);
    if (ret != SECURITY_MANAGER_API_SUCCESS)
        return ret;

    try {
        // Apply updates
        //TODO: change hardcoded name to enum/map value
        CynaraAdmin::getInstance().SetPolicies(policyUnits, "PRIVACY_MANAGER");

    } catch (const CynaraException::Base &e) {
        LogError("Error while updating Cynara rules: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation error while updating Cynara rules: " << e.what());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    }

    return SECURITY_MANAGER_API_SUCCESS;
}

} /* namespace ServiceImpl */
} /* namespace SecurityManager */
