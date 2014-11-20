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

#include <sys/socket.h>

#include <dpl/log/log.h>
#include <dpl/serialization.h>

#include "protocols.h"
#include "service.h"
#include "service_impl.h"

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

void Service::processAppInstall(MessageBuffer &buffer, MessageBuffer &send, uid_t uid)
{
    app_inst_req req;

    Deserialization::Deserialize(buffer, req.appId);
    Deserialization::Deserialize(buffer, req.pkgId);
    Deserialization::Deserialize(buffer, req.privileges);
    Deserialization::Deserialize(buffer, req.appPaths);
    Deserialization::Deserialize(buffer, req.uid);
    Serialization::Serialize(send, ServiceImpl::appInstall(req, uid));
}

void Service::processAppUninstall(MessageBuffer &buffer, MessageBuffer &send, uid_t uid)
{
    std::string appId;

    Deserialization::Deserialize(buffer, appId);
    Serialization::Serialize(send, ServiceImpl::appUninstall(appId, uid));
}

void Service::processGetPkgId(MessageBuffer &buffer, MessageBuffer &send)
{
    std::string appId;
    std::string pkgId;
    int ret;

    Deserialization::Deserialize(buffer, appId);
    ret = ServiceImpl::getPkgId(appId, pkgId);
    Serialization::Serialize(send, ret);
    if (ret == SECURITY_MANAGER_API_SUCCESS)
        Serialization::Serialize(send, pkgId);
}

void Service::processGetAppGroups(MessageBuffer &buffer, MessageBuffer &send, uid_t uid, pid_t pid)
{
    std::string appId;
    std::unordered_set<gid_t> gids;
    int ret;

    Deserialization::Deserialize(buffer, appId);
    ret = ServiceImpl::getAppGroups(appId, uid, pid, gids);
    Serialization::Serialize(send, ret);
    if (ret == SECURITY_MANAGER_API_SUCCESS) {
        Serialization::Serialize(send, static_cast<int>(gids.size()));
        for (const auto &gid : gids) {
            Serialization::Serialize(send, gid);
        }
    }
}


} // namespace SecurityManager
