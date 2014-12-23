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
 * @file        service_impl.h
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @brief       Implementation of the service methods
 */

#ifndef _SECURITY_MANAGER_SERVICE_IMPL_
#define _SECURITY_MANAGER_SERVICE_IMPL_

#include <unistd.h>
#include <sys/types.h>

#include <string>
#include <vector>
#include <unordered_set>

#include "security-manager.h"

namespace SecurityManager {
namespace ServiceImpl {

/**
 * Process application installation request.
 *
 * @param[in] req installation request
 * @param[in] uid id of the requesting user
 *
 * @return API return code, as defined in security-manager.h
 */
int appInstall(const app_inst_req &req, uid_t uid);

/**
 * Process application uninstallation request.
 *
 * @param[in] req uninstallation request
 * @param[in] uid id of the requesting user
 *
 * @return API return code, as defined in security-manager.h
 */
int appUninstall(const std::string &appId, uid_t uid);

/**
 * Process package id query.
 * Retrieves the package id associated with given application id.
 *
 * @param[in] appId application identifier
 * @param[out] pkgId returned package identifier
 *
 * @return API return code, as defined in security-manager.h
 */
int getPkgId(const std::string &appId, std::string &pkgId);

/**
 * Process query for supplementary groups allowed for the application.
 * For given appId and uid, calculate allowed privileges that give
 * direct access to file system resources. For each permission Cynara will be
 * queried.
 * Returns set of group ids that are permitted.
 *
 * @param[in]  appId application identifier
 * @param[in]  uid id of the requesting user
 * @param[in]  pid id of the requesting process (to construct Cynara session id)
 * @param[out] gids returned set of allowed group ids
 *
 * @return API return code, as defined in security-manager.h
 */
int getAppGroups(const std::string &appId, uid_t uid, pid_t pid, std::unordered_set<gid_t> &gids);

/**
 * Process user adding request.
 *
 * @param[in] uidAdded uid of newly created user
 * @param[in] userType type of newly created user
 * @param[in] uid uid of requesting user
 *
 * @return API return code, as defined in protocols.h
 */
int userAdd(uid_t uidAdded, int userType, uid_t uid);

/**
 * Process user deletion request.
 *
 * @param[in] uidDeleted uid of removed user
 * @param[in] uid uid of requesting user
 *
 * @return API return code, as defined in protocols.h
 */
int userDelete(uid_t uidDeleted, uid_t uid);

/**
 * Load Tizen privileges list
 *
 * @param[in] reload decides if privileges' list should be reloaded.
 *                   It is optional. Default value if false.
 *
 * @return API return code, as defined in protocols.h
 */
int loadPrivileges(bool reload = false);

/**
 * Get Tizen privileges list
 *
 * @param[in] privileges reference to a vector with resulting privileges list
 *
 * @return API return code, as defined in protocols.h
 */
int getAllSystemPrivileges(std::vector<std::string> &privilegesList);

/**
 * Update policy in Cynara using admin entry point - proper privilege is needed for this to succeed
 *
 * @param[in] policyUnits vector of policy chunks with instructions
 * @param[in] uid identifier of requesting user
 * @param[in] pid PID of requesting process
 *
 * @return API return code, as defined in protocols.h
 */
int policyUpdateForAdmin(const std::vector<SecurityManager::PolicyUpdateUnit> &policyUnits, uid_t uid, pid_t pid);

/**
 * Update policy in Cynara using privacy manager entry point - personal privileges per user.
 *
 * @param[in] policyUnits vector of policy chunks with instructions
 * @param[in] uid identifier of requesting user
 *
 * @return API return code, as defined in protocols.h
 */
int policyUpdateForSelf(const std::vector<SecurityManager::PolicyUpdateUnit> &policyUnits, uid_t uid);

} /* namespace ServiceImpl */
} /* namespace SecurityManager */

#endif /* _SECURITY_MANAGER_SERVICE_IMPL_ */
