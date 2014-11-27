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
#include "smack-common.h"
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
                case MasterSecurityModuleCall::SMACK_REGISTER_PATHS:
                    LogDebug("call type MasterSecurityModuleCall::SMACK_REGISTER_PATHS");
                    processSmackRegisterPaths(buffer, send);
                    break;
                case MasterSecurityModuleCall::SMACK_UNINSTALL_PKG_RULES:
                    LogDebug("call type MasterSecurityModuleCall::SMACK_UNINSTALL_PKG_RULES");
                    processSmackUninstallPackageRules(buffer, send);
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
    std::vector<std::string> oldPkgPrivileges, newPkgPrivileges;

    Deserialization::Deserialize(buffer, smackLabel);
    Deserialization::Deserialize(buffer, uidstr);
    Deserialization::Deserialize(buffer, oldPkgPrivileges);
    Deserialization::Deserialize(buffer, newPkgPrivileges);

    try {
        CynaraAdmin::UpdatePackagePolicy(smackLabel, uidstr, oldPkgPrivileges,
                                         newPkgPrivileges);
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
    Serialization::Serialize(send, allowed);
}

void MasterService::processSmackRegisterPaths(MessageBuffer &buffer, MessageBuffer &send)
{
    bool pkgIdIsNew = false;
    std::string pkgId;
    AppPathsType appPaths;

    Deserialization::Deserialize(buffer, pkgId);
    Deserialization::Deserialize(buffer, appPaths);
    Deserialization::Deserialize(buffer, pkgIdIsNew);
    Serialization::Serialize(send, ServiceImpl::registerPaths(pkgId, appPaths, pkgIdIsNew));
}

void MasterService::processSmackUninstallPackageRules(MessageBuffer &buffer, MessageBuffer &send)
{
    int ret = SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    std::string pkgId;

    Deserialization::Deserialize(buffer, pkgId);
    if (!SmackRules::uninstallPackageRules(pkgId)) {
        LogError("Error on uninstallation of package-specific smack rules");
        goto out;
    }

    ret = SECURITY_MANAGER_API_SUCCESS;

out:
    Serialization::Serialize(send, ret);
}

} // namespace SecurityManager
