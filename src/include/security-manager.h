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
 *
 *	Security Manager library header
 */
/*
 * @file        security-manager.h
 * @author      Pawel Polawski (p.polawski@samsung.com)
 * @version     1.0
 * @brief       This file contains header of security-manager API
 */

#ifndef SECURITY_MANAGER_H_
#define SECURITY_MANAGER_H_

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*! \brief return code of API functions */
enum lib_retcode {
    SECURITY_MANAGER_SUCCESS,
    SECURITY_MANAGER_ERROR_UNKNOWN,
    SECURITY_MANAGER_ERROR_INPUT_PARAM,
    SECURITY_MANAGER_ERROR_MEMORY,
    SECURITY_MANAGER_ERROR_REQ_NOT_COMPLETE,
    SECURITY_MANAGER_ERROR_AUTHENTICATION_FAILED
};

/*! \brief accesses types for application installation paths*/
enum app_install_path_type {
    //accessible read-write only for applications with same package id
    SECURITY_MANAGER_PATH_PRIVATE,
    //read-write access for all applications
    SECURITY_MANAGER_PATH_PUBLIC,
    //read only access for all applications
    SECURITY_MANAGER_PATH_PUBLIC_RO,
    //this is only for range limit
    SECURITY_MANAGER_ENUM_END
};

/**
 * This enum has values equivalent to gumd user type.
 * The gum-utils help states that
 * "usertype can be system(1), admin(2), guest(3), normal(4)."
 */
enum security_manager_user_type {
    SM_USER_TYPE_NONE   = 0,/*<-this should not be used, if it is used, there will be an error returned by SM*/
    SM_USER_TYPE_SYSTEM = 1,
    SM_USER_TYPE_ADMIN  = 2,
    SM_USER_TYPE_GUEST  = 3,
    SM_USER_TYPE_NORMAL = 4
};
typedef enum security_manager_user_type security_manager_user_type;

/*! \brief data structure responsible for handling informations
 * required to install / uninstall application */
struct app_inst_req;
typedef struct app_inst_req app_inst_req;

/*! \brief data structure responsible for handling informations
 * required to manage users */
struct user_req;
typedef struct user_req user_req;

/**
 * This function translates lib_retcode error codes to strings describing
 * errors.
 * @param[in] rc error code of lib_retcode type
 * @return string describing error for error code
 */
const char *security_manager_strerror(enum lib_retcode rc);

/*
 * This function is responsible for initialize app_inst_req data structure
 * It uses dynamic allocation inside and user responsibility is to call
 * app_inst_req_free() for freeing allocated resources
 *
 * \param[in] Address of pointer for handle app_inst_req structure
 * \return API return code or error code
 */
int security_manager_app_inst_req_new(app_inst_req **pp_req);

/*
 * This function is used to free resources allocated by calling app_inst_req_new()
 *  \param[in] Pointer handling allocated app_inst_req structure
 */
void security_manager_app_inst_req_free(app_inst_req *p_req);

/*
 * This function is used to set up application identifier in app_inst_req structure
 *
 * \param[in] Pointer handling app_inst_req structure
 * \param[in] Application identifier
 * \return API return code or error code
 */
int security_manager_app_inst_req_set_app_id(app_inst_req *p_req, const char *app_id);

/*
 * This function is used to set up package identifier in app_inst_req structure
 *
 * \param[in] Pointer handling app_inst_req structure
 * \param[in] Package identifier
 * \return API return code or error code
 */
int security_manager_app_inst_req_set_pkg_id(app_inst_req *p_req, const char *pkg_id);

/*
 * This function is used to add privilege to app_inst_req structure,
 * it can be called multiple times
 *
 * \param[in] Pointer handling app_inst_req structure
 * \param[in] Application privilager
 * \return API return code or error code
 */
int security_manager_app_inst_req_add_privilege(app_inst_req *p_req, const char *privilege);

/*
 * This function is used to add application path to app_inst_req structure,
 * it can be called multiple times
 *
 * \param[in] Pointer handling app_inst_req structure
 * \param[in] Application path
 * \param[in] Application path type
 * \return API return code or error code
 */
int security_manager_app_inst_req_add_path(app_inst_req *p_req, const char *path, const int path_type);

/*
 * This function is used to set up user identifier in app_inst_req structure.
 * This field simplifies support for online and offline modes.
 *
 * \param[in] Pointer handling app_inst_req structure
 * \param[in] User identifier (UID)
 * \return API return code or error code
 */
int security_manager_app_inst_req_set_uid(app_inst_req *p_req,
                                          const uid_t uid);

/*
 * This function is used to install application based on
 * using filled up app_inst_req data structure
 *
 * \param[in] Pointer handling app_inst_req structure
 * \return API return code or error code: it would be
 * - SECURITY_MANAGER_SUCCESS on success,
 * - SECURITY_MANAGER_ERROR_AUTHENTICATION_FAILED when user does not
 * have rights to install requested directories,
 * - SECURITY_MANAGER_ERROR_UNKNOWN on other errors.
 */
int security_manager_app_install(const app_inst_req *p_req);

/*
 * This function is used to uninstall application based on
 * using filled up app_inst_req data structure
 *
 * \param[in] Pointer handling app_inst_req structure
 * \return API return code or error code
 */
int security_manager_app_uninstall(const app_inst_req *p_req);

/**
 * Get package id of a given application
 *
 * On successful call pkg_id should be freed by the caller using free() function
 *
 * \param[out] Pointer to package identifier string
 * \param[in]  Application identifier
 * \return API return code or error code
 */
int security_manager_get_app_pkgid(char **pkg_id, const char *app_id);

/**
 * Compute smack label for given application id and set it for
 * currently running process
 *
 * \param[in] Application identifier
 * \return API return code or error code
 */
int security_manager_set_process_label_from_appid(const char *app_id);

/**
 * For given app_id and current user, calculate allowed privileges that give
 * direct access to file system resources. Then add current process to
 * supplementary groups that are assigned to these resources.
 *
 * In Tizen some sensitive resources are being accessed by applications directly.
 * The resources, being file system objects, are owned by dedicated GIDs and only
 * processes in those UNIX groups can access them. This function is used for
 * adding application process to all permitted groups that are assigned to such
 * privileges.
 *
 * \param[in] Application identifier
 * \return API return code or error code
 */
int security_manager_set_process_groups_from_appid(const char *app_id);

/**
 * The above launcher functions, manipulating process Smack label and group,
 * require elevated privileges. Since they will be called by launcher after fork,
 * in the process for the application, privileges should be dropped before
 * running an actual application. This function is a helper for that purpose -
 * it drops capabilities from the process.
 *
 * \return API return code or error code
 */
int security_manager_drop_process_privileges(void);

/**
 * A convenience function for launchers for preparing security context for an
 * application process. It should be called after fork in the new process, before
 * running the application in it.
 * It is aimed to cover most common cases and will internally call other, more
 * specialized security-manager functions for launchers.
 * Currently it just calls:
 * - security_manager_set_process_label_from_appid
 * - security_manager_set_process_groups_from_appid
 * - security_manager_drop_process_privileges
 *
 * \param[in] Application identifier
 * \return API return code or error code
 */
int security_manager_prepare_app(const char *app_id);

/*
 * This function is responsible for initialization of user_req data structure.
 * It uses dynamic allocation inside and user responsibility is to call
 * security_manager_user_req_free() for freeing allocated resources.
 *
 * @param[in] Address of pointer for handle user_req structure
 * @return API return code or error code
 */
int security_manager_user_req_new(user_req **pp_req);

/*
 * This function is used to free resources allocated by
 * security_manager_user_req_new()
 *
 * @param[in] Pointer handling allocated user_req structure
 */
void security_manager_user_req_free(user_req *p_req);

/*
 * This function is used to set up user identifier in user_req structure.
 *
 * @param p_req Structure containing user data filled during this function call
 * @param uid User identifier to be set
 * @return API return code or error code
 */
int security_manager_user_req_set_uid(user_req *p_req, uid_t uid);

/*
 * This function is used to set up user type in user_req structure.
 *
 * @param p_req Structure containing user data filled during this function call
 * @param utype User type to be set
 * @return API return code or error code
 */
int security_manager_user_req_set_user_type(user_req *p_req, security_manager_user_type utype);

/*
 * This function should be called to inform security-manager about adding new user.
 * This function succeeds only when is called by privileged user.
 * Otherwise it just returns SECURITY_MANAGER_ERROR_AUTHENTICATION_FAILED and does nothing.
 *
 * It adds all required privileges to a newly created user.
 * User data are passed through  pointer 'p_req'.
 * @param p_req Structure containing user data filled before calling this
 * uid and user type needs to be filled in p_req structure,
 * otherwise SECURITY_MANAGER_ERROR_INPUT_PARAM will be returned.
 * @return API return code or error code.
 */
int security_manager_user_add(const user_req *p_req);

/*
 * This function should be called to inform security-manager about removing a user.
 * This function succeeds only when is called by privileged user.
 * Otherwise it just returns SECURITY_MANAGER_ERROR_AUTHENTICATION_FAILED and does nothing.
 *
 * It removes all privileges granted to a user that has been granted previously by
 * security_manager_user_add.
 *
 * @param p_req Structure containing user data filled before calling this.
 * uid of user needs to be filled in p_req structure,
 * otherwise SECURITY_MANAGER_ERROR_INPUT_PARAM will be returned.
 * @return API return code or error code
 */
int security_manager_user_delete(const user_req *p_req);


#ifdef __cplusplus
}
#endif

#endif /* SECURITY_MANAGER_H_ */
