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

#include <functional>

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
public:
    ClientRequest(SecurityModuleCall action);
    int getStatus();
    bool send();
    template <typename... T> bool send(const T&...);
    template <typename T> bool recv(T&);

private:
    MessageBuffer m_send, m_recv;
    int m_status = SECURITY_MANAGER_SUCCESS;
    bool m_statusFetched = false;
};

template <typename... T>
bool ClientRequest::send(const T&... args)
{
    if (m_status != SECURITY_MANAGER_SUCCESS)
        return false;

    Serialization::Serialize(m_send, args...);
    return send();
}

template <typename T>
bool ClientRequest::recv(T& arg)
{
    if (getStatus() != SECURITY_MANAGER_SUCCESS)
        return false;

    Deserialization::Deserialize(m_recv, arg);
    return true;
}

} // namespace SecurityManager

#endif // _SECURITY_MANAGER_CLIENT_
