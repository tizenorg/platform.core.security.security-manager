/*
 *  Copyright (c) 2014-2016 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        service_impl.h
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @brief       Implementation of the service methods
 */

#ifndef _SECURITY_MANAGER_SERVICE_IMPL_
#define _SECURITY_MANAGER_SERVICE_IMPL_

#include <unistd.h>
#include <sys/types.h>

#include <unordered_set>

#include "credentials.h"
#include "security-manager.h"
#include "protocols.h"

namespace SecurityManager {

class ServiceImpl {
private:
    static uid_t getGlobalUserId(void);

    static bool isSubDir(const char *parent, const char *subdir);

    static bool getUserAppDir(const uid_t &uid, const app_install_type &installType, std::string &userAppDir);

    static void installRequestMangle(app_inst_req &req, std::string &cynaraUserStr);

    static bool installRequestAuthCheck(const Credentials &creds, const app_inst_req &req);

    static bool installRequestPathsCheck(const app_inst_req &req, std::string &appPath);

    static bool getZoneId(std::string &zoneId);

    int dropOnePrivateSharing(const std::string &ownerAppName,
                              const std::string &ownerPkgName,
                              const std::vector<std::string> &ownerPkgContents,
                              const std::string &targetAppName,
                              const std::string &path);

public:
    ServiceImpl();
    virtual ~ServiceImpl();

    /**
    * Process application installation request.
    *
    * @param[in] creds credentials of the requesting process
    * @param[in] req installation request
    *
    * @return API return code, as defined in protocols.h
    */
    int appInstall(const Credentials &creds, app_inst_req &&req);

    /**
    * Process application uninstallation request.
    *
    * @param[in] creds credentials of the requesting process
    * @param[in] req uninstallation request
    * @param[in] authenticated whether the caller has been already checked against Cynara policy
    *
    * @return API return code, as defined in protocols.h
    */
    int appUninstall(const Credentials &creds, app_inst_req &&req, bool authenticated = false);

    /**
    * Process package id query.
    * Retrieves the package id associated with given application id.
    *
    * @param[in] appName application identifier
    * @param[out] pkgName returned package identifier
    *
    * @return API return code, as defined in protocols.h
    */
    int getPkgName(const std::string &appName, std::string &pkgName);

    /**
    * Process query for supplementary groups allowed for the application.
    * For given \ref appName and \ref uid, calculate allowed privileges that give
    * direct access to file system resources. For each permission Cynara will be
    * queried.
    * Returns set of group ids that are permitted.
    *
    * @param[in]  creds credentials of the requesting process
    * @param[in]  appName application identifier
    * @param[out] gids returned set of allowed group ids
    *
    * @return API return code, as defined in protocols.h
    */
    int getAppGroups(const Credentials &creds, const std::string &appName, std::unordered_set<gid_t> &gids);

    /**
    * Process user adding request.
    *
    * @param[in] creds credentials of the requesting process
    * @param[in] uidAdded uid of newly created user
    * @param[in] userType type of newly created user
    *
    * @return API return code, as defined in protocols.h
    */
    int userAdd(const Credentials &creds, uid_t uidAdded, int userType);

    /**
    * Process user deletion request.
    *
    * @param[in] creds credentials of the requesting process
    * @param[in] uidDeleted uid of removed user
    *
    * @return API return code, as defined in protocols.h
    */
    int userDelete(const Credentials &creds, uid_t uidDeleted);

    /**
    * Update policy in Cynara - proper privilege: http://tizen.org/privilege/internal/usermanagement
    * is needed for this to succeed
    *
    * @param[in] creds credentials of the requesting process
    * @param[in] policyEntries vector of policy chunks with instructions
    *
    * @return API return code, as defined in protocols.h
    */
    int policyUpdate(const Credentials &creds, const std::vector<policy_entry> &policyEntries);

    /**
    * Fetch all configured privileges from user configurable bucket.
    * Depending on forAdmin value: personal user policies or admin enforced
    * policies are returned.
    *
    * @param[in] forAdmin determines if user is asking as ADMIN or not
    * @param[in] filter filter for limiting the query
    * @param[out] policyEntries vector of policy entries with result
    *
    * @return API return code, as defined in protocols.h
    */
    int getConfiguredPolicy(const Credentials &creds, bool forAdmin, const policy_entry &filter, std::vector<policy_entry> &policyEntries);

    /**
    * Fetch all privileges for all apps installed for specific user.
    *
    * @param[in] creds credentials of the requesting process
    * @param[in] filter filter for limiting the query
    * @param[out] policyEntries vector of policy entries with result
    *
    * @return API return code, as defined in protocols.h
    */
    int getPolicy(const Credentials &creds, const policy_entry &filter, std::vector<policy_entry> &policyEntries);

    /**
    * Process getting policy descriptions list.
    *
    * @param[in] descriptions empty vector for descriptions strings
    *
    * @return API return code, as defined in protocols.h
    */
    int policyGetDesc(std::vector<std::string> &descriptions);

    /**
     * Process getting resources group list.
     *
     * @param[out] groups empty vector for group strings
     *
     * @return API return code, as defined in protocols.h
     */
    int policyGetGroups(std::vector<std::string> &groups);

    /**
     * Process checking application's privilege access based on app_name
     *
     * @param[in]  appName application identifier
     * @param[in]  privilege privilege name
     * @param[in]  uid user identifier
     * @param[out] result placeholder for check result
     *
     * @return API return code, as defined in protocols.h
     */
    int appHasPrivilege(std::string appName, std::string privilege, uid_t uid, bool &result);

    /**
     * Process applying private path sharing between applications.
     *
     * @param[in] creds credentials of the requesting process
     * @param[in] ownerAppName application owning paths
     * @param[in] targetAppName application which paths will be shared with
     * @param[in] paths vector of paths to be shared
     *
     * @return API return code, as defined in protocols.h
     */
    int applyPrivatePathSharing(const Credentials &creds,
                                const std::string &ownerAppName,
                                const std::string &targetAppName,
                                const std::vector<std::string> &paths);

    /**
     * Process droping private path sharing between applications.
     *
     * @param[in] creds credentials of the requesting process
     * @param[in] ownerAppName application owning paths
     * @param[in] targetAppName application which paths won't be anymore shared with
     * @param[in] paths vector of paths to be stopped being shared
     * @return API return code, as defined in protocols.h
     */
    int dropPrivatePathSharing(const Credentials &creds,
                               const std::string &ownerAppName,
                               const std::string &targetAppName,
                               const std::vector<std::string> &paths);

    /**
     * Process package paths registration.
     *
     * @param[in] creds credentials of the requesting process
     * @param[in] pkgName package name
     * @param[in] uid uid of the affected user
     * @param[in] paths vector of paths to be registered
     *
     * @return API return code, as defined in protocols.h
     */
    int pathsRegister(const Credentials &creds,
                      const std::string &pkgName,
                      uid_t uid,
                      const pkg_paths &paths);
};

} /* namespace SecurityManager */

#endif /* _SECURITY_MANAGER_SERVICE_IMPL_ */
