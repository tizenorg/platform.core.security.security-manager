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

#pragma once

#include <sys/types.h>

#include <protocols.h>
#include <privilege_db.h>

namespace SecurityManager {

uid_t getGlobalUserId(void);

/**
 * Unifies user data of apps installed for all users
 * @param  uid            peer's uid - may be changed during process
 * @param  cynaraUserStr  string to which cynara user parameter will be put
 * @param  reqUid         pointer to requested uid
 */
void checkGlobalUser(uid_t &uid, std::string &cynaraUserStr,
                     uid_t *reqUid = NULL);

/*
 * This function is used to install applications.
 *
 * \param[in] Reference to a db object
 * \param[in] Reference to app_inst_req structure
 * \param[in] uid of the user that performs this request
 * \return API return code or error code
 */
int AppInstall(PrivilegeDb &pdb, const app_inst_req &req, uid_t uid);

} // namespace SecurityManager

