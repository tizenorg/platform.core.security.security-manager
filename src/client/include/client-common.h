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
 * @file        client-common.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       This file constains implementation of common types
 *              used in security manager.
 */

#ifndef _SECURITY_MANAGER_CLIENT_
#define _SECURITY_MANAGER_CLIENT_

#include <cassert>
#include <functional>

#include <connection.h>
#include <dpl/log/log.h>
#include <message-buffer.h>
#include <protocols.h>
#include <security-manager-types.h>

#define SECURITY_MANAGER_API __attribute__((visibility("default")))
#define SECURITY_MANAGER_UNUSED __attribute__((unused))

namespace SecurityManager {

/*
 * Decorator function that performs frequently repeated exception handling in
 * SS client API functions. Accepts lambda expression as an argument.
 */
int try_catch(const std::function<int()>& func);

class ClientRequest {
private:
    bool m_sent = false;
    int m_status = SECURITY_MANAGER_SUCCESS;
    MessageBuffer m_send, m_recv;

public:
    ClientRequest(SecurityManager::SecurityModuleCall action)
    {
        Serialization::Serialize(m_send, static_cast<int>(action));
    }

    int getStatus()
    {
        return m_status;
    }

    bool failed()
    {
        return m_status == SECURITY_MANAGER_SUCCESS;
    }

    ClientRequest & send()
    {
        assert(!m_sent); // Only one call to send() is expected
        m_sent = true;

        m_status = sendToServer(SERVICE_SOCKET, m_send.Pop(), m_recv);
        if (!failed())
            Deserialization::Deserialize(m_recv, m_status);
        else
            LogError("Error in sendToServer. Error code: " << m_status);

        return *this;
    }

    template <typename... T> ClientRequest & send(const T&... args)
    {
        Serialization::Serialize(m_send, args...);
        return send();
    }

    template <typename T> ClientRequest & recv(T &arg)
    {
        assert(m_sent); // Call to send() must happen before call to recv()
        if (!failed())
            Deserialization::Deserialize(m_recv, arg);
        return *this;
    }
};

} // namespace SecurityManager

#endif // _SECURITY_MANAGER_CLIENT_
