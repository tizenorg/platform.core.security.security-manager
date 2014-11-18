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

enum security_manager_user_type {
    SM_USER_TYPE_ANY    = 0, /* To be used as a wildcard in policy updates */
    SM_USER_TYPE_SYSTEM = 1,
    SM_USER_TYPE_ADMIN  = 2,
    SM_USER_TYPE_GUEST  = 3,
    SM_USER_TYPE_NORMAL = 4,
    SM_USER_TYPE_ENUM_END    /* for range checks */
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

/*! \brief data structure responsible for handling policy updates
 *  required to manage users' applications permissions */
struct policy_update_req;
typedef struct policy_update_req policy_update_req;

/*! \brief string to be used in policy update requests to match all possible values of given field.
 *         Use it, for example when it is desired to apply policy change for all users of chosen
 *         type or all apps for selected user. Please see documentation of the
 *         security_manager_policy_update_req_add_unit() function for furhter details.
 */
#define SECURITY_MANAGER_WILDCARD "#"

/*! \brief structure that is used to return the status of applications and permissions */
struct permission_status {
    char *name; /* name of corresponding application or Cynara privilege */
    int status; /* status of permission */
};


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

/**
 * \brief This function is responsible for initialize policy_update_req data structure.
 *
 * It uses dynamic allocation inside and user responsibility is to call
 * policy_update_req_free() for freeing allocated resources.
 *
 * \param[in] Address of pointer for handle policy_update_req structure
 * \return API return code or error code
 */
int security_manager_policy_update_req_new(policy_update_req **pp_req);

/**
 * \brief This function is used to free resources allocated by calling app_inst_req_new().
 *
 * \param[in] Pointer handling allocated policy_update_req structure
 */
void security_manager_policy_update_req_free(policy_update_req *p_req);

/**
 * \brief This generic function is used to add policy update unit to policy_update_req
 *        structure. It allows to enable or disable a privilege for selected user, type
 *        and app_id. It may be used more than once on the allocated policy_update_req
 *        pointer, allowing to fill it with many units defining policy.
 *
 * It is allowed to use SECURITY_MANAGER_WILDCARD and SM_USER_TYPE_ANY as arguments,
 * which makes this function operating in various configurations.
 *
 * \attention This API should be used ONLY BY PRIVILEGED USER. Although this function will not
 *            return any error when unprivileged user tries to break this rule, the authorization
 *            error will be returned from the server when it receives the request.
 *
 * Examples of use cases:
 *  -# No wildcards, all args specified      - add unit updating policy for app belonging\n
 *                                             to given user of specified type.
 *  -# user = SECURITY_MANAGER_WILDCARD      - add unit updating app privilege for all users\n
 *                                             of given type
 *  -# user = SECURITY_MANAGER_WILDCARD and user_type = SMUT_ANY - add unit updating app privilege\n
 *                                                                 for all users of all types
 *  -# user and app_id = SECURITY_MANAGER_WILDCARD               - add unit updating privilege for\n
 *                                                                 all users of given type and for\n
 *                                                                 all apps
 *  -# app_id = SECURITY_MANAGER_WILDCARD    - add unit updating privilege for all apps\n
 *                                             belonging to given user of specified type
 *  -# privilege = SECURITY_MANAGER_WILDCARD - add unit updating all privileges for an app\n
 *                                             belonging to given user of specified type
 *
 * \param[in] Pointer handling allocated policy_update_req structure
 * \param[in] User identifier (use SECURITY_MANAGER_WILDCARD to apply to all users)
 * \param[in] User type (use SM_USER_TYPE_ANY to apply to all user types)
 * \param[in] Application identifier (use SECURITY_MANAGER_WILDCARD to apply to all apps)
 * \param[in] Privilege name (use SECURITY_MANAGER_WILDCARD to apply to all privs)
 * \param[in] Tells if privilege should be allowed or denied
 * \return API return code or error code
 */
int security_manager_policy_update_req_add_unit(policy_update_req *p_req,
                                                const char *user,
                                                const security_manager_user_type user_type,
                                                const char *app_id,
                                                const char *privilege,
                                                const bool allow);

/**
 * \brief This is a simplified version of security_manager_policy_update_req_add_unit() function.
 *
 * It is intended to be used by Privacy Manager application, allowing to enable or disable
 * privileges for the current user.
 *
 * \attention This function does not operate on wildcards, only strict arguments are allowed.
 *
 * \param[in] Pointer handling allocated policy_update_req structure
 * \param[in] Application identifier
 * \param[in] Privilege name
 * \param[in] Tells if privilege should be allowed or denied
 * \return API return code or error code
 */
int security_manager_policy_update_req_add_unit_for_self(policy_update_req *p_req,
                                                         const char *app_id,
                                                         const char *privilege,
                                                         const bool allow);

/**
 * \brief This function is used to send the prepared policy update request.
 *        The request should contain at least one policy_update_unit, otherwise the
 *        SECURITY_MANAGER_ERROR_INPUT_PARAM is returned.
 *
 * \param[in] Pointer handling allocated policy_update_req structure
 * \return API return code or error code
 */
int security_manager_policy_update_req_send(policy_update_req *p_req);

/**
 * \brief This function gets all users registered in the database.
 *
 * It uses dynamic allocation inside and user responsibility is to call
 * users_free() for freeing allocated resources.
 *
 * \attention It should be called by PRIVILEGED USER.
 *
 * \param[in/out] Address of pointer for handle users (c-style strings array)
 * \param[in/out] Pointer where the size of allocated array will be stored
 * \return API return code or error code
 */
int security_manager_get_users(char ***ppp_users, size_t *p_size);

/**
 * \brief This function gets all users of given type.
 *
 * It uses dynamic allocation inside and user responsibility is to call
 * users_free() for freeing allocated resources.
 *
 * \attention It should be called by PRIVILEGED USER.
 *
 * \param[in]     Required user type (cannot be SECURITY_MANAGER_WILDCARD)
 * \param[in/out] Address of pointer for handle users (c-style strings array)
 * \param[in/out] Pointer where the size of allocated array will be stored
 * \return API return code or error code
 */
int security_manager_get_users_of_type(const security_manager_user_type user_type,
                                       char ***ppp_users,
                                       size_t *p_size);

/**
 * \brief This function is used to free resources allocated by calling one of get_users() function.
 *
 * \param[in] Pointer handling allocated users array
 * \param[in] Size of the array
 */
void security_manager_users_free(char **pp_users, size_t size);

/**
 * \brief Function gets all apps that belong to the user passed in argument along with statuses
 *        of user permissions to execute these apps.
 *
 * It uses dynamic allocation inside and user responsibility is to call
 * statuses_free() for freeing allocated resources.
 *
 * \attention It should be called by PRIVILEGED USER. Normal users may get the list of owned apps
 *            by calling security_manager_get_apps_for_self() API function.
 *
 * Returned statuses may be checked using three simple functions:
 * - security_manager_is_permission_allowed()           - checks if execution is fully allowed
 * - security_manager_is_permission_allowed_privately() - checks if execution is allowed in\n
 *                                                        private settings
 * - security_manager_is_permission_allowed_by_admin()  - checks if execution is allowed in\n
 *                                                        device administrator's settings
 *
 * \param[in]     User identifier (cannot be SECURITY_MANAGER_WILDCARD)
 * \param[in/out] Pointer handling allocated permission_status structures array
 * \param[in/out] Pointer where the size of allocated array will be stored.
 * \return API return code or error code
 */
int security_manager_get_user_apps(const char *user,
                                   permission_status **pp_statuses,
                                   size_t *p_size);

/**
 * \brief Function gets all apps that belong to the calling user along with statuses
 *        of user permissions to execute these apps.
 *
 * It uses dynamic allocation inside and user responsibility is to call
 * statuses_free() for freeing allocated resources.
 *
 * Returned statuses may be checked using three simple functions:
 * - security_manager_is_permission_allowed()           - checks if execution is fully allowed
 * - security_manager_is_permission_allowed_privately() - checks if execution is allowed in\n
 *                                                        private settings
 * - security_manager_is_permission_allowed_by_admin()  - checks if execution is allowed in\n
 *                                                        device administrator's settings
 *
 * \param[in/out] Pointer handling allocated permission_status structures array
 * \param[in/out] Pointer where the size of allocated array will be stored.
 * \return API return code or error code
 */
int security_manager_get_apps_for_self(permission_status **pp_statuses, size_t *p_size);

/**
 * \brief Function gets all apps that are installed for all users along with statuses
 *        of these apps' execution permissions. Global apps may be denied for all users by device
 *        administrator only.
 *
 * It uses dynamic allocation inside and user responsibility is to call
 * statuses_free() for freeing allocated resources.
 *
 * Returned statuses may be checked using two simple functions:
 * - security_manager_is_permission_allowed()           - checks if execution is fully allowed
 * - security_manager_is_permission_allowed_by_admin()  - checks if execution is allowed in\n
 *                                                        device administrator's settings
 * - the security_manager_is_permission_allowed_privately() function is not relevant in this case
 *
 * \param[in/out] Pointer handling allocated permission_status structures array
 * \param[in/out] Pointer where the size of allocated array will be stored.
 * \return API return code or error code
 */
int security_manager_get_global_apps(permission_status **pp_statuses, size_t *p_size);

/**
 * \brief Function gets all privileges assigned to the user given in argument along with their
 *        statuses. Privileges are extracted from all applications that belong to the selected user.
 *
 * It uses dynamic allocation inside and user responsibility is to call
 * statuses_free() for freeing allocated resources.
 *
 * \attention It should be called by PRIVILEGED USER. Normal users may list privileges assigned
 *            to owned application using security_manager_get_app_privileges_for_self() API function
 *
 * \attention This function does not operate on wildcards, only strict arguments are allowed.
 *
 * Returned statuses may be checked using two simple functions:
 * - security_manager_is_permission_allowed()           - checks if permission is fully allowed
 * - security_manager_is_permission_allowed_by_admin()  - checks if permission is allowed in\n
 *                                                        device administrator's settings
 * - the security_manager_is_permission_allowed_privately() function is not relevant in this case
 *
 * \param[in]     User identifier
 * \param[in/out] Pointer handling allocated permission_status structures array
 * \param[in/out] Pointer where the size of allocated array will be stored.
 * \return API return code or error code
 */
int security_manager_get_user_privileges(char *user,
                                         permission_status **pp_statuses,
                                         size_t *p_size);

/**
 * \brief Function gets all privileges assigned to the specified application owned by user given in
 *        argument. Statuses of these privileges are returned as well.
 *
 * It uses dynamic allocation inside and user responsibility is to call
 * statuses_free() for freeing allocated resources.
 *
 * \attention It should be called by PRIVILEGED USER. Normal users may list privileges assigned
 *            to owned application using security_manager_get_app_privileges_for_self() API function
 *
 * \attention This function does not operate on wildcards, only strict arguments are allowed.
 *
 * Returned statuses may be checked using three simple functions:
 * - security_manager_is_permission_allowed()           - checks if permission is fully allowed
 * - security_manager_is_permission_allowed_privately() - checks if permission is allowed in\n
 *                                                        private settings
 * - security_manager_is_permission_allowed_by_admin()  - checks if permission is allowed in\n
 *                                                        device administrator's settings
 *
 * \param[in]     User identifier
 * \param[in]     Application identifier
 * \param[in/out] Pointer handling allocated permission_status structures array
 * \param[in/out] Pointer where the size of allocated array will be stored.
 * \return API return code or error code
 */
int security_manager_get_user_app_privileges(char *user,
                                             char *app_id,
                                             permission_status **pp_statuses,
                                             size_t *p_size);

/**
 * \brief Function gets all privileges assigned to the specified application owned by the calling
 *        user. Statuses of these privileges are returned as well.
 *
 * It uses dynamic allocation inside and user responsibility is to call
 * statuses_free() for freeing allocated resources.
 *
 * \attention This function does not operate on wildcards, only strict arguments are allowed.
 *
 * Returned statuses may be checked using three simple functions:
 * - security_manager_is_permission_allowed()           - checks if permission is fully allowed
 * - security_manager_is_permission_allowed_privately() - checks if permission is allowed in\n
 *                                                        private settings
 * - security_manager_is_permission_allowed_by_admin()  - checks if permission is allowed in\n
 *                                                        device administrator's settings
 *
 * \param[in]     Application identifier
 * \param[in/out] Pointer handling allocated permission_status structures array
 * \param[in/out] Pointer where the size of allocated array will be stored.
 * \return API return code or error code
 */
int security_manager_get_app_privileges_for_self(char *app_id,
                                                 permission_status **pp_statuses,
                                                 size_t *p_size);

/**
 * \brief Function gets all privileges assigned to the global application specified in the
 *        argument. Statuses of these privileges are returned as well.
 *
 * It uses dynamic allocation inside and user responsibility is to call
 * statuses_free() for freeing allocated resources.
 *
 * \attention This function does not operate on wildcards, only strict arguments are allowed.
 *
 * Returned statuses may be checked using two simple functions:
 * - security_manager_is_permission_allowed()           - checks if permission is fully allowed
 * - security_manager_is_permission_allowed_by_admin()  - checks if permission is allowed in\n
 *                                                        device administrator's settings
 * - the security_manager_is_permission_allowed_privately() function is not relevant in this case
 *
 * \param[in]     Application identifier
 * \param[in/out] Pointer handling allocated permission_status structures array
 * \param[in/out] Pointer where the size of allocated array will be stored.
 * \return API return code or error code
 */
int security_manager_get_global_app_privileges(char *app_id,
                                               permission_status **pp_statuses,
                                               size_t *p_size);

/**
 * \brief This function is used to free resources allocated in permission_status structure array.
 *
 * \param[in] Pointer handling allocated status array
 * \param[in] Size of the array
 */
void security_manager_statuses_free(permission_status *p_statuses, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* SECURITY_MANAGER_H_ */
