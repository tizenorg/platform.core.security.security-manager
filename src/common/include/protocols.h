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
 * @file        protocols.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       This file contains list of all protocols suported by security-manager.
 */

#ifndef _SECURITY_MANAGER_PROTOCOLS_
#define _SECURITY_MANAGER_PROTOCOLS_

#include "security-manager.h"

#include <sys/types.h>
#include <vector>
#include <string>
#include <dpl/serialization.h>

/**
 * \name Return Codes
 * exported by the foundation API.
 * result codes begin with the start error code and extend into negative direction.
 * @{
*/

/*! \brief   indicating the result of the one specific API is successful */
#define SECURITY_MANAGER_API_SUCCESS 0

/*! \brief   indicating the socket between client and Security Manager has been failed  */
#define SECURITY_MANAGER_API_ERROR_SOCKET -1

/*! \brief   indicating the request to Security Manager is malformed */
#define SECURITY_MANAGER_API_ERROR_BAD_REQUEST -2

/*! \brief   indicating the response from Security Manager is malformed */
#define SECURITY_MANAGER_API_ERROR_BAD_RESPONSE -3

/*! \brief   indicating the requested service does not exist */
#define SECURITY_MANAGER_API_ERROR_NO_SUCH_SERVICE -4

/*! \brief   indicating requesting object is not exist */
#define SECURITY_MANAGER_API_ERROR_NO_SUCH_OBJECT -6

/*! \brief   indicating the authentication between client and server has been failed */
#define SECURITY_MANAGER_API_ERROR_AUTHENTICATION_FAILED -7

/*! \brief   indicating the API's input parameter is malformed */
#define SECURITY_MANAGER_API_ERROR_INPUT_PARAM -8

/*! \brief   indicating the output buffer size which is passed as parameter is too small */
#define SECURITY_MANAGER_API_ERROR_BUFFER_TOO_SMALL -9

/*! \brief   indicating system  is running out of memory state */
#define SECURITY_MANAGER_API_ERROR_OUT_OF_MEMORY -10

/*! \brief   indicating the access has been denied by Security Manager */
#define SECURITY_MANAGER_API_ERROR_ACCESS_DENIED -11

/*! \brief   indicating Security Manager has been failed for some reason */
#define SECURITY_MANAGER_API_ERROR_SERVER_ERROR -12

/*! \brief   indicating getting smack label from socket failed  */
#define SECURITY_MANAGER_API_ERROR_GETTING_SOCKET_LABEL_FAILED -21

/*! \brief   indicating getting smack label from file failed  */
#define SECURITY_MANAGER_API_ERROR_GETTING_FILE_LABEL_FAILED -22

/*! \brief   indicating setting smack label for file failed  */
#define SECURITY_MANAGER_API_ERROR_SETTING_FILE_LABEL_FAILED -23

/*! \brief   indicating file already exists  */
#define SECURITY_MANAGER_API_ERROR_FILE_EXIST -24

/*! \brief   indicating file does not exist  */
#define SECURITY_MANAGER_API_ERROR_FILE_NOT_EXIST -25

/*! \brief   indicating file open error  */
#define SECURITY_MANAGER_API_ERROR_FILE_OPEN_FAILED -26

/*! \brief   indicating file creation error  */
#define SECURITY_MANAGER_API_ERROR_FILE_CREATION_FAILED -27

/*! \brief   indicating file deletion error  */
#define SECURITY_MANAGER_API_ERROR_FILE_DELETION_FAILED -28

/*! \brief   indicating file contents format error  */
#define SECURITY_MANAGER_API_ERROR_FILE_FORMAT_MALFORMED -29

/*! \brief   indicating privileges list loading error */
#define SECURITY_MANAGER_API_ERROR_LOADING_PRIVILEGES_LIST -30

/*! \brief   indicating the error with unknown reason */
#define SECURITY_MANAGER_API_ERROR_UNKNOWN -255
/** @}*/


struct app_inst_req {
    std::string appId;
    std::string pkgId;
    std::vector<std::string> privileges;
    std::vector<std::pair<std::string, int>> appPaths;
    uid_t uid;
};

struct user_req {
    uid_t uid;
    int utype;
};

struct user_object {
    int type;
    char *name;
};

namespace SecurityManager {

extern char const * const SERVICE_SOCKET;

enum class SecurityModuleCall
{
    APP_INSTALL,
    APP_UNINSTALL,
    APP_GET_PKGID,
    APP_GET_GROUPS,
    USER_ADD,
    USER_DELETE,
    RELOAD_POLICY,
    BUCKETS_INIT,
    POLICY_UPDATE_ADMIN,
    POLICY_UPDATE_SELF,
    GET_USER_APPS,
    GET_USER_PRIVS_POLICY,
};

struct PolicyUpdateUnit : ISerializable {
    std::string userId;    // uid converted to string
    std::string appId;     // application identifier
    std::string privilege; // Cynara privilege
    int userType;          // user type - mapped from gumd
    int value;             // policy to be set, corresponds to Cynara's policy result type
    int userOrType;        // denominates a policy for user or user type

    PolicyUpdateUnit() /* needed in Deserialization */
    {}

    PolicyUpdateUnit(const char *userId, const char *appId, const char *privilege,
                       int value)
                      : userId(userId), appId(appId), privilege(privilege),
                        value(value)
    {}

    PolicyUpdateUnit(const user_object *uo, const char *appId, const char *privilege,
                       int value)
                      : appId(appId), privilege(privilege),
                        value(value)
    {
        userId = std::string(uo->name);
        userOrType = uo->type;
    }

    PolicyUpdateUnit(PolicyUpdateUnit &source) = delete; /* no copy constructor */
    PolicyUpdateUnit &operator=(const PolicyUpdateUnit &second) = delete; /* no copy operator */

    /* The move constructor is used when pushing objects to vector */
    PolicyUpdateUnit(PolicyUpdateUnit &&source) : userId(std::move(source.userId)),
                                                  appId(std::move(source.appId)),
                                                  privilege(std::move(source.privilege)),
                                                  userType(source.userType),
                                                  value(source.value),
                                                  userOrType(source.userOrType)
    {}

    /* The move assignment is used when receiving object from buffer */
    PolicyUpdateUnit &operator=(const PolicyUpdateUnit &&second)
    {
        userId = std::move(second.userId);
        appId = std::move(second.appId);
        privilege = std::move(second.privilege);
        userType = second.userType;
        value = second.value;
        userOrType = second.userOrType;
        return *this;
    }

    PolicyUpdateUnit(IStream &stream) {
        Deserialization::Deserialize(stream, userId);
        Deserialization::Deserialize(stream, appId);
        Deserialization::Deserialize(stream, privilege);
        Deserialization::Deserialize(stream, userType);
        Deserialization::Deserialize(stream, value);
        Deserialization::Deserialize(stream, userOrType);
    }

    virtual void Serialize(IStream &stream) const {
        Serialization::Serialize(stream, userId);
        Serialization::Serialize(stream, appId);
        Serialization::Serialize(stream, privilege);
        Serialization::Serialize(stream, userType);
        Serialization::Serialize(stream, value);
        Serialization::Serialize(stream, userOrType);
    }
};
typedef struct PolicyUpdateUnit PolicyUpdateUnit;

struct PolicyEntry : ISerializable {
    std::string appId;	   // name of entry: application or Cynara privilege
    std::string privilege; // name of entry: application or Cynara privilege
    int maxValue;          // holds the maximum policy status type allowed to be set for this entry
    int current;           // holds the current policy status for this entry

    PolicyEntry() : appId(""), privilege(""), maxValue(0), current(0)
    {}

    PolicyEntry(const PolicyEntry &source) = delete; /* no copy constructor */
    PolicyEntry &operator=(const PolicyEntry &second) = delete; /* no copy operator */

    /* The move constructor is used when pushing objects to vector */
    PolicyEntry(const PolicyEntry &&source) : appId(std::move(source.appId)),
                                              privilege(std::move(source.privilege)),
                                              maxValue(source.maxValue),
                                              current(source.current)
    {}

    /* The move assignment is used when receiving object from buffer */
    PolicyEntry &operator=(const PolicyEntry &&second)
    {
        appId = std::move(second.appId);
        privilege = std::move(second.privilege);
        maxValue = second.maxValue;
        current = second.current;
        return *this;
    }

    PolicyEntry(IStream &stream) {
        Deserialization::Deserialize(stream, appId);
        Deserialization::Deserialize(stream, privilege);
        Deserialization::Deserialize(stream, maxValue);
        Deserialization::Deserialize(stream, current);
    }

    virtual void Serialize(IStream &stream) const {
        Serialization::Serialize(stream, appId);
        Serialization::Serialize(stream, privilege);
        Serialization::Serialize(stream, maxValue);
        Serialization::Serialize(stream, current);
    }
};
typedef struct PolicyEntry PolicyEntry;

} // namespace SecurityManager

struct policy_update_req {
    std::vector<SecurityManager::PolicyUpdateUnit> units;
};

#endif // _SECURITY_MANAGER_PROTOCOLS_
