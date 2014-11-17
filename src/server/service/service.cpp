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
 * @file        service.cpp
 * @author      Michal Witanowski <m.witanowski@samsung.com>
 * @author      Jacek Bukarewicz <j.bukarewicz@samsung.com>
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @brief       Implementation of security-manager service.
 */

#include <dpl/log/log.h>
#include <dpl/serialization.h>
#include <tzplatform_config.h>

#include <unordered_set>
#include <sys/types.h>
#include <sys/socket.h>
#include <pwd.h>
#include <limits.h>
#include <cstring>

#include "service.h"
#include "protocols.h"
#include "security-manager.h"
#include "smack-common.h"
#include "smack-rules.h"
#include "smack-labels.h"
#include "privilege_db.h"
#include "service-common.h"

namespace SecurityManager {

const InterfaceID IFACE = 1;

Service::Service()
{
}

GenericSocketService::ServiceDescriptionVector Service::GetServiceDescription()
{
    return ServiceDescriptionVector {
        {SERVICE_SOCKET, "security-manager", IFACE},
    };
}

void Service::accept(const AcceptEvent &event)
{
    LogDebug("Accept event. ConnectionID.sock: " << event.connectionID.sock <<
             " ConnectionID.counter: " << event.connectionID.counter <<
             " ServiceID: " << event.interfaceID);

    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.interfaceID = event.interfaceID;
}

void Service::write(const WriteEvent &event)
{
    LogDebug("WriteEvent. ConnectionID: " << event.connectionID.sock <<
             " Size: " << event.size <<
             " Left: " << event.left);

    if (event.left == 0)
        m_serviceManager->Close(event.connectionID);
}

void Service::process(const ReadEvent &event)
{
    LogDebug("Read event for counter: " << event.connectionID.counter);
    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.buffer.Push(event.rawBuffer);

    // We can get several requests in one package.
    // Extract and process them all
    while (processOne(event.connectionID, info.buffer, info.interfaceID));
}

void Service::close(const CloseEvent &event)
{
    LogDebug("CloseEvent. ConnectionID: " << event.connectionID.sock);
    m_connectionInfoMap.erase(event.connectionID.counter);
}

static bool getPeerID(int sock, uid_t &uid, pid_t &pid) {
    struct ucred cr;
    socklen_t len = sizeof(cr);

    if (!getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &cr, &len)) {
        uid = cr.uid;
        pid = cr.pid;
        return true;
    }

    return false;
}

bool Service::processOne(const ConnectionID &conn, MessageBuffer &buffer,
                                  InterfaceID interfaceID)
{
    LogDebug("Iteration begin. Interface = " << interfaceID);

    //waiting for all data
    if (!buffer.Ready()) {
        return false;
    }

    MessageBuffer send;
    bool retval = false;

    uid_t uid;
    pid_t pid;

    if(!getPeerID(conn.sock, uid, pid)) {
        LogError("Closing socket because of error: unable to get peer's uid and pid");
        m_serviceManager->Close(conn);
        return false;
    }

    if (IFACE == interfaceID) {
        Try {
            // deserialize API call type
            int call_type_int;
            Deserialization::Deserialize(buffer, call_type_int);
            SecurityModuleCall call_type = static_cast<SecurityModuleCall>(call_type_int);

            switch (call_type) {
                case SecurityModuleCall::APP_INSTALL:
                    LogDebug("call_type: SecurityModuleCall::APP_INSTALL");
                    processAppInstall(buffer, send, uid);
                    break;
                case SecurityModuleCall::APP_UNINSTALL:
                    LogDebug("call_type: SecurityModuleCall::APP_UNINSTALL");
                    processAppUninstall(buffer, send, uid);
                    break;
                case SecurityModuleCall::APP_GET_PKGID:
                    processGetPkgId(buffer, send);
                    break;
                case SecurityModuleCall::APP_GET_GROUPS:
                    processGetAppGroups(buffer, send, uid, pid);
                    break;
                default:
                    LogError("Invalid call: " << call_type_int);
                    Throw(ServiceException::InvalidAction);
            }
            // if we reach this point, the protocol is OK
            retval = true;
        } Catch (MessageBuffer::Exception::Base) {
            LogError("Broken protocol.");
        } Catch (ServiceException::Base) {
            LogError("Broken protocol.");
        } catch (std::exception &e) {
            LogError("STD exception " << e.what());
        } catch (...) {
            LogError("Unknown exception");
        }
    }
    else {
        LogError("Wrong interface");
    }

    if (retval) {
        //send response
        m_serviceManager->Write(conn, send.Pop());
    } else {
        LogError("Closing socket because of error");
        m_serviceManager->Close(conn);
    }

    return retval;
}

bool Service::processAppInstall(MessageBuffer &buffer, MessageBuffer &send, uid_t uid)
{
    int ret;
    app_inst_req req;
    // deserialize request data
    Deserialization::Deserialize(buffer, req.uid);
    Deserialization::Deserialize(buffer, req.appId);
    Deserialization::Deserialize(buffer, req.pkgId);
    Deserialization::Deserialize(buffer, req.privileges);
    Deserialization::Deserialize(buffer, req.appPaths);
    req.uid = uid;
    ret = AppInstall(&m_privilegeDb, req);
    Serialization::Serialize(send, ret);
    return ret == SECURITY_MANAGER_API_SUCCESS;
}

bool Service::processAppUninstall(MessageBuffer &buffer, MessageBuffer &send, uid_t uid)
{
    // deserialize request data
    std::string appId;
    std::string pkgId;
    std::string smackLabel;
    std::vector<std::string> appsInPkg;
    bool appExists = true;
    bool removePkg = false;

    Deserialization::Deserialize(buffer, appId);

    try {
        std::vector<std::string> oldPkgPrivileges, newPkgPrivileges;

        m_privilegeDb.BeginTransaction();
        if (!m_privilegeDb.GetAppPkgId(appId, pkgId)) {
            LogWarning("Application " << appId << " not found in database while uninstalling");
            m_privilegeDb.RollbackTransaction();
            appExists = false;
        } else {
            if (!generateAppIdLabel(appId, smackLabel)) {
                LogError("Cannot generate Smack label for application: " << appId);
                goto error_label;
            }

            std::string uidstr = isGlobalUser(uid) ? CYNARA_ADMIN_WILDCARD
                                 : std::to_string(static_cast<unsigned int>(uid));

            LogDebug("Uninstall parameters: appId: " << appId << ", pkgId: " << pkgId
                     << ", uidstr " << uidstr << ", generated smack label: " << smackLabel);

            /* Before we remove the app from the database, let's fetch all apps in the package
                that this app belongs to, this will allow us to remove all rules withing the
                package that the app appears in */
            m_privilegeDb.GetAppIdsForPkgId(pkgId, appsInPkg);
            m_privilegeDb.GetPkgPrivileges(pkgId, uid, oldPkgPrivileges);
            m_privilegeDb.UpdateAppPrivileges(appId, uid, std::vector<std::string>());
            m_privilegeDb.RemoveApplication(appId, uid, removePkg);
            m_privilegeDb.GetPkgPrivileges(pkgId, uid, newPkgPrivileges);

            CynaraAdmin::UpdatePackagePolicy(smackLabel, uidstr, oldPkgPrivileges,
                                             newPkgPrivileges);
            m_privilegeDb.CommitTransaction();
            LogDebug("Application uninstallation commited to database");
        }
    } catch (const PrivilegeDb::Exception::InternalError &e) {
        m_privilegeDb.RollbackTransaction();
        LogError("Error while removing application info from database: " << e.DumpToString());
        goto error_label;
    } catch (const CynaraException::Base &e) {
        m_privilegeDb.RollbackTransaction();
        LogError("Error while setting Cynara rules for application: " << e.DumpToString());
        goto error_label;
    } catch (const std::bad_alloc &e) {
        m_privilegeDb.RollbackTransaction();
        LogError("Memory allocation while setting Cynara rules for application: " << e.what());
        goto error_label;
    }

    if (appExists) {
        if (removePkg) {
            LogDebug("Removing Smack rules for deleted pkgId " << pkgId);
            if (!SmackRules::uninstallPackageRules(pkgId)) {
                LogError("Error on uninstallation of package-specific smack rules");
                goto error_label;
            }
        } else {
            LogDebug ("Removing smack rules for deleted appId " << appId);
            if (!SmackRules::uninstallApplicationRules(appId, pkgId, appsInPkg)) {
                LogError("Error on uninistallation of application-specific smack rules");
                goto error_label;
            }
        }
    }

    // success
    Serialization::Serialize(send, SECURITY_MANAGER_API_SUCCESS);
    return true;

error_label:
    Serialization::Serialize(send, SECURITY_MANAGER_API_ERROR_SERVER_ERROR);
    return false;
}

bool Service::processGetPkgId(MessageBuffer &buffer, MessageBuffer &send)
{
    // deserialize request data
    std::string appId;
    std::string pkgId;

    Deserialization::Deserialize(buffer, appId);
    LogDebug("appId: " << appId);

    try {
        if (!m_privilegeDb.GetAppPkgId(appId, pkgId)) {
            LogWarning("Application " << appId << " not found in database");
            Serialization::Serialize(send, SECURITY_MANAGER_API_ERROR_NO_SUCH_OBJECT);
            return false;
        } else {
            LogDebug("pkgId: " << pkgId);
        }
    } catch (const PrivilegeDb::Exception::InternalError &e) {
        LogError("Error while getting pkgId from database: " << e.DumpToString());
        Serialization::Serialize(send, SECURITY_MANAGER_API_ERROR_SERVER_ERROR);
        return false;
    }

     // success
    Serialization::Serialize(send, SECURITY_MANAGER_API_SUCCESS);
    Serialization::Serialize(send, pkgId);
    return true;
}

bool Service::processGetAppGroups(MessageBuffer &buffer, MessageBuffer &send, uid_t uid, pid_t pid)
{
    std::unordered_set<gid_t> gids;

    try {
        std::string appId;
        std::string pkgId;
        std::string smackLabel;
        std::string uidStr = std::to_string(uid);
        std::string pidStr = std::to_string(pid);

        Deserialization::Deserialize(buffer, appId);
        LogDebug("appId: " << appId);

        if (!m_privilegeDb.GetAppPkgId(appId, pkgId)) {
            LogWarning("Application " << appId << " not found in database");
            Serialization::Serialize(send, SECURITY_MANAGER_API_ERROR_NO_SUCH_OBJECT);
            return false;
        }
        LogDebug("pkgId: " << pkgId);

        if (!generateAppIdLabel(appId, smackLabel)) {
             LogError("Cannot generate Smack label for app: " << appId);
            Serialization::Serialize(send, SECURITY_MANAGER_API_ERROR_NO_SUCH_OBJECT);
            return false;
        }
        LogDebug("smack label: " << smackLabel);

        std::vector<std::string> privileges;
        m_privilegeDb.GetPkgPrivileges(pkgId, uid, privileges);
        for (const auto &privilege : privileges) {
            std::vector<gid_t> gidsTmp;
            m_privilegeDb.GetPrivilegeGids(privilege, gidsTmp);
            if (!gidsTmp.empty()) {
                LogDebug("Considering privilege " << privilege << " with " <<
                    gidsTmp.size() << " groups assigned");
                if (m_cynara.check(smackLabel, privilege, uidStr, pidStr)) {
                    gids.insert(gidsTmp.begin(), gidsTmp.end());
                    LogDebug("Cynara allowed, adding groups");
                } else
                    LogDebug("Cynara denied, not adding groups");
            }
        }
    } catch (const PrivilegeDb::Exception::InternalError &e) {
        LogError("Database error: " << e.DumpToString());
        Serialization::Serialize(send, SECURITY_MANAGER_API_ERROR_SERVER_ERROR);
        return false;
    } catch (const CynaraException::Base &e) {
        LogError("Error while querying Cynara for permissions: " << e.DumpToString());
        Serialization::Serialize(send, SECURITY_MANAGER_API_ERROR_SERVER_ERROR);
        return false;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation failed: " << e.what());
        Serialization::Serialize(send, SECURITY_MANAGER_API_ERROR_OUT_OF_MEMORY);
        return false;
    }

    // success
    Serialization::Serialize(send, SECURITY_MANAGER_API_SUCCESS);
    Serialization::Serialize(send, static_cast<int>(gids.size()));
    for (const auto &gid : gids) {
        Serialization::Serialize(send, gid);
    }
    return true;
}


} // namespace SecurityManager
