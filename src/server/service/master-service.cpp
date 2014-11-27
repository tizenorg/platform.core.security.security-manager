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

void MasterService::processSmackInstallRules(MessageBuffer &buffer, MessageBuffer &send)
{
    int ret = SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    std::string appId, pkgId;
    std::vector<std::string> pkgContents;

    Deserialization::Deserialize(buffer, appId);
    Deserialization::Deserialize(buffer, pkgId);
    Deserialization::Deserialize(buffer, pkgContents);

    try {
        LogDebug("Adding Smack rules for new appId: " << appId << " with pkgId: "
                << pkgId << ". Applications in package: " << pkgContents.size());
        SmackRules::installApplicationRules(appId, pkgId, pkgContents);
    } catch (const SmackException::Base &e) {
        LogError("Error while removing Smack rules for application: " << e.DumpToString());
        ret = SECURITY_MANAGER_API_ERROR_SETTING_FILE_LABEL_FAILED;
        goto out;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation error: " << e.what());
        ret =  SECURITY_MANAGER_API_ERROR_OUT_OF_MEMORY;
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

    try {
        if (removePkg) {
            LogDebug("Removing Smack rules for deleted pkgId " << pkgId);
            SmackRules::uninstallPackageRules(pkgId);
        }

        LogDebug ("Removing smack rules for deleted appId " << appId);
        SmackRules::uninstallApplicationRules(appId, pkgId, pkgContents);
    } catch (const SmackException::Base &e) {
        LogError("Error while removing Smack rules for application: " << e.DumpToString());
        ret = SECURITY_MANAGER_API_ERROR_SETTING_FILE_LABEL_FAILED;
        goto out;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation error: " << e.what());
        ret =  SECURITY_MANAGER_API_ERROR_OUT_OF_MEMORY;
        goto out;
    }

    ret = SECURITY_MANAGER_API_SUCCESS;
out:
    Serialization::Serialize(send, ret);
}

} // namespace SecurityManager
