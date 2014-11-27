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
 * @file        master-service.cpp
 * @author      Lukasz Kostyra <l.kostyra@samsung.com>
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @brief       Implementation of security-manager master service.
 */

#include <generic-socket-manager.h>

#include <dpl/log/log.h>
#include <dpl/serialization.h>

#include "protocols.h"
#include "cynara.h"
#include "master-service.h"
#include "smack-rules.h"
#include "smack-labels.h"
#include "service_impl.h"

namespace SecurityManager {

const InterfaceID IFACE = 1;

MasterService::MasterService()
{
}

GenericSocketService::ServiceDescriptionVector MasterService::GetServiceDescription()
{
    return ServiceDescriptionVector {
        {MASTER_SERVICE_SOCKET, "security-manager-master", IFACE},
    };
}

bool MasterService::processOne(const ConnectionID &conn, MessageBuffer &buffer,
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

    if (!ServiceImpl::getPeerID(conn.sock, uid, pid)) {
        LogError("Closing socket because of error: unable to get peer's uid and pid");
        m_serviceManager->Close(conn);
        return false;
    }

    if (IFACE == interfaceID) {
        Try {
            // deserialize API call type
            int call_type_int;
            Deserialization::Deserialize(buffer, call_type_int);
            MasterSecurityModuleCall call_type = static_cast<MasterSecurityModuleCall>(call_type_int);

            switch (call_type) {
                case MasterSecurityModuleCall::CYNARA_UPDATE_POLICY:
                    LogDebug("call type MasterSecurityModuleCall::CYNARA_UPDATE_POLICY");
                    processCynaraUpdatePolicy(buffer, send);
                    break;
                case MasterSecurityModuleCall::CYNARA_CHECK:
                    LogDebug("call type MasterSecurityModuleCall::CYNARA_CHECK");
                    processCynaraCheck(buffer, send);
                    break;
                case MasterSecurityModuleCall::CYNARA_USER_INIT:
                    LogDebug("call type MasterSecurityModuleCall::CYNARA_USER_INIT");
                    processCynaraUserInit(buffer, send);
                    break;
                case MasterSecurityModuleCall::CYNARA_USER_REMOVE:
                    LogDebug("call type MasterSecurityModuleCall::CYNARA_USER_REMOVE");
                    processCynaraUserRemove(buffer, send);
                    break;
                case MasterSecurityModuleCall::SMACK_INSTALL_RULES:
                    LogDebug("call type MasterSecurityModuleCall::SMACK_INSTALL_RULES");
                    processSmackInstallRules(buffer, send);
                    break;
                case MasterSecurityModuleCall::SMACK_UNINSTALL_RULES:
                    LogDebug("call type MasterSecurityModuleCall::SMACK_UNINSTALL_RULES");
                    processSmackUninstallRules(buffer, send);
                    break;
                default:
                    LogError("Invalid call: " << call_type_int);
                    Throw(MasterServiceException::InvalidAction);
            }
            // if we reach this point, the protocol is OK
            retval = true;
        } Catch (MessageBuffer::Exception::Base) {
            LogError("Broken protocol.");
        } Catch (MasterServiceException::Base) {
            LogError("Broken protocol.");
        } catch (const std::exception &e) {
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

void MasterService::processCynaraUpdatePolicy(MessageBuffer &buffer, MessageBuffer &send)
{
    int ret = SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    std::string smackLabel;
    std::string uidstr;
    std::vector<std::string> oldAppPrivileges, newAppPrivileges;

    Deserialization::Deserialize(buffer, smackLabel);
    Deserialization::Deserialize(buffer, uidstr);
    Deserialization::Deserialize(buffer, oldAppPrivileges);
    Deserialization::Deserialize(buffer, newAppPrivileges);

    try {
        CynaraAdmin::getInstance().UpdateAppPolicy(smackLabel, uidstr, oldAppPrivileges,
                                                   newAppPrivileges);
    } catch (const CynaraException::Base &e) {
        LogError("Error while setting Cynara rules for application: " << e.DumpToString());
        goto out;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation while setting Cynara rules for application: " << e.what());
        ret = SECURITY_MANAGER_API_ERROR_OUT_OF_MEMORY;
        goto out;
    }

    ret = SECURITY_MANAGER_API_SUCCESS;

out:
    Serialization::Serialize(send, ret);
}

void MasterService::processCynaraCheck(MessageBuffer &buffer, MessageBuffer &send)
{
    int ret = SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    bool allowed = false;
    std::string smackLabel;
    std::string privilege;
    std::string uidStr;
    std::string pidStr;

    Deserialization::Deserialize(buffer, smackLabel);
    Deserialization::Deserialize(buffer, privilege);
    Deserialization::Deserialize(buffer, uidStr);
    Deserialization::Deserialize(buffer, pidStr);

    try {
        allowed = Cynara::getInstance().check(smackLabel, privilege, uidStr, pidStr);
    } catch (const CynaraException::Base &e) {
        LogError("Error while querying Cynara for permissions: " << e.DumpToString());
        goto out;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation failed: " << e.what());
        ret = SECURITY_MANAGER_API_ERROR_OUT_OF_MEMORY;
        goto out;
    }

    ret = SECURITY_MANAGER_API_SUCCESS;
out:
    Serialization::Serialize(send, ret);
    if (ret != SECURITY_MANAGER_API_SUCCESS)
        Serialization::Serialize(send, allowed);
}

void MasterService::processCynaraUserInit(MessageBuffer &buffer, MessageBuffer &send)
{
    int ret = SECURITY_MANAGER_API_ERROR_INPUT_PARAM;
    uid_t uidAdded;
    int userType;

    Deserialization::Deserialize(buffer, uidAdded);
    Deserialization::Deserialize(buffer, userType);

    try {
        CynaraAdmin::getInstance().UserInit(uidAdded,
                                            static_cast<security_manager_user_type>(userType));
    } catch (CynaraException::InvalidParam &e) {
        goto out;
    }

    ret = SECURITY_MANAGER_API_SUCCESS;
out:
    Serialization::Serialize(send, ret);
}

void MasterService::processCynaraUserRemove(MessageBuffer &buffer, MessageBuffer &send)
{
    int ret = SECURITY_MANAGER_API_ERROR_INPUT_PARAM;
    uid_t uidDeleted;

    Deserialization::Deserialize(buffer, uidDeleted);

    try {
        CynaraAdmin::getInstance().UserRemove(uidDeleted);
    } catch (CynaraException::InvalidParam &e) {
        goto out;
    }

    ret = SECURITY_MANAGER_API_SUCCESS;
out:
    Serialization::Serialize(send, ret);
}

void MasterService::processSmackInstallRules(MessageBuffer &buffer, MessageBuffer &send)
{
    int ret = SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    std::string appId, pkgId;
    std::vector<std::string> pkgContents;

    Deserialization::Deserialize(buffer, appId);
    Deserialization::Deserialize(buffer, pkgId);
    Deserialization::Deserialize(buffer, pkgContents);

    LogDebug("Adding Smack rules for new appId: " << appId << " with pkgId: "
            << pkgId << ". Applications in package: " << pkgContents.size());
    if (!SmackRules::installApplicationRules(appId, pkgId, pkgContents)) {
        LogError("Failed to apply package-specific smack rules");
        goto out;
    }

    ret = SECURITY_MANAGER_API_SUCCESS;
out:
    Serialization::Serialize(send, ret);
}

void MasterService::processSmackUninstallRules(MessageBuffer &buffer, MessageBuffer &send)
{
    int ret = SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    std::string appId, pkgId;
    std::vector<std::string> pkgContents;
    bool removePkg = false;

    Deserialization::Deserialize(buffer, appId);
    Deserialization::Deserialize(buffer, pkgId);
    Deserialization::Deserialize(buffer, pkgContents);
    Deserialization::Deserialize(buffer, removePkg);

    if (removePkg) {
        LogDebug("Removing Smack rules for deleted pkgId " << pkgId);
        if (!SmackRules::uninstallPackageRules(pkgId)) {
            LogError("Error on uninstallation of package-specific smack rules");
            goto out;
        }
    }

    LogDebug ("Removing smack rules for deleted appId " << appId);
    if (!SmackRules::uninstallApplicationRules(appId, pkgId, pkgContents)) {
        LogError("Error during uninstallation of application-specific smack rules");
        goto out;
    }

    ret = SECURITY_MANAGER_API_SUCCESS;
out:
    Serialization::Serialize(send, ret);
}

} // namespace SecurityManager
