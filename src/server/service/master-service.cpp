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
 * @author      Lukasz Kostyra <l.kostyra@samsung.com>
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @brief       Implementation of security-manager service.
 */

#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <cstring>
#include <unordered_set>

#include <dpl/log/log.h>
#include <dpl/serialization.h>
#include <tzplatform_config.h>

#include "privilege_db.h"
#include "protocols.h"
#include "security-manager.h"
#include "master-service.h"
#include "smack-common.h"
#include "smack-rules.h"
#include "smack-labels.h"

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

void MasterService::accept(const AcceptEvent &event)
{
    LogDebug("Accept event. ConnectionID.sock: " << event.connectionID.sock <<
             " ConnectionID.counter: " << event.connectionID.counter <<
             " ServiceID: " << event.interfaceID);

    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.interfaceID = event.interfaceID;
}

void MasterService::write(const WriteEvent &event)
{
    LogDebug("WriteEvent. ConnectionID: " << event.connectionID.sock <<
             " Size: " << event.size <<
             " Left: " << event.left);

    if (event.left == 0)
        m_serviceManager->Close(event.connectionID);
}

void MasterService::process(const ReadEvent &event)
{
    LogDebug("Read event for counter: " << event.connectionID.counter);
    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.buffer.Push(event.rawBuffer);

    // We can get several requests in one package.
    // Extract and process them all
    while (processOne(event.connectionID, info.buffer, info.interfaceID));
}

void MasterService::close(const CloseEvent &event)
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


} // namespace SecurityManager
