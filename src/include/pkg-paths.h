/*
 *  Copyright (c) 2000 - 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file       pkg-paths.h
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */
#ifndef SECURITY_MANAGER_PKG_PATHS_H_
#define SECURITY_MANAGER_PKG_PATHS_H_

#include "security-manager-types.h"

#ifdef __cplusplus
extern "C" {
#endif


/*
 * This function is responsible for initialize path_req data structure. It uses
 * dynamic allocation inside and user responsibility is to call
 * security_manager_path_req_free() for freeing allocated resources.
 *
 * \param[in] pp_req    Address of pointer for handle path_req structure
 * \return API return code or error code
 */
int security_manager_path_req_new(path_req **pp_req);

/*
 * This function is used to free resources allocated by calling
 * security_manager_path_req_new().
 *  \param[in] p_req    Pointer handling allocated path_req structure
 */
void security_manager_path_req_free(path_req *p_req);

/*
 * This function is used to set up package identifier in path_req structure.
 *
 * \param[in] p_req     Pointer handling path_req structure
 * \param[in] pkg_id    Package identifier
 * \return API return code or error code
 */
int security_manager_path_req_set_pkg_id(path_req *p_req, const char *pkg_id);

/*
 * This function is used to add a package path to path_req structure. It can be
 * called multiple times.
 *
 * \param[in] p_req     Pointer handling path_req structure
 * \param[in] path      Package path
 * \param[in] path_type Package path type
 * \return API return code or error code
 */
int security_manager_path_req_add_path(path_req *p_req, const char *path, const int path_type);

/*
 * This function is used to set up user identifier in path_req structure.
 * This field simplifies support for online and offline modes.
 *
 * \param[in] p_req     Pointer handling path_req structure
 * \param[in] uid       User identifier (UID)
 * \return API return code or error code
 */
int security_manager_path_req_set_uid(path_req *p_req, const uid_t uid);

/*
 * This function is used to register a set of paths for given package using
 * filled up path_req data structure.
 *
 * Required privileges:
 * - http://tizen.org/privilege/notexist (if uid is not set or set to current
 *                                        user's uid)
 * - http://tizen.org/privilege/notexist (if uid is set to some other user's
 *                                        uid)
 *
 * \param[in] p_req     Pointer handling path_req structure
 *
 * \return API return code or error code: it would be
 * - SECURITY_MANAGER_SUCCESS on success,
 * - SECURITY_MANAGER_ERROR_AUTHENTICATION_FAILED when user does not
 * have rights to install requested directories,
 * - SECURITY_MANAGER_ERROR_UNKNOWN on other errors.
 */
int security_manager_paths_register(const path_req *p_req);

#ifdef __cplusplus
}
#endif


#endif /* SECURITY_MANAGER_PKG_PATHS_H_ */
