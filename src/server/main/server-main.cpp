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
 * @file        server-main.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Implementation of security-manager on basis of security-server
 */
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>

#include <dpl/log/log.h>
#include <dpl/singleton.h>
#include <dpl/singleton_safe_impl.h>

#include <socket-manager.h>

#include <service.h>
#include <master-service.h>

IMPLEMENT_SAFE_SINGLETON(SecurityManager::Log::LogSystem);

#define REGISTER_SOCKET_SERVICE(manager, service, allocator) \
    registerSocketService<service>(manager, #service, allocator)

template<typename T>
void registerSocketService(SecurityManager::SocketManager &manager,
                           const std::string& serviceName,
                           const std::function<T*(void)>& serviceAllocator)
{
    T *service = NULL;
    try {
        service = serviceAllocator();
        service->Create();
        manager.RegisterSocketService(service);
        service = NULL;
    } catch (const SecurityManager::Exception &exception) {
        LogError("Error in creating service " << serviceName <<
                 ", details:\n" << exception.DumpToString());
    } catch (const std::exception& e) {
        LogError("Error in creating service " << serviceName <<
                 ", details:\n" << e.what());
    } catch (...) {
        LogError("Error in creating service " << serviceName <<
                 ", unknown exception occured");
    }
    if (service)
        delete service;
}

void printUsage(char* name)
{
    printf("Usage: %s [-m] [-s]\n", name);
}

int main(int argc, char* argv[])
{
    UNHANDLED_EXCEPTION_HANDLER_BEGIN
    {
        // initialize logging
        SecurityManager::Singleton<SecurityManager::Log::LogSystem>::Instance().SetTag("SECURITY_MANAGER");

        // parse arguments
        int opt;
        bool masterMode = false, slaveMode = false;
        int optionIndex = optind ? optind : 1;
        const struct option longOptions[] = {
                {"master", no_argument, 0, 'm'},
                {"slave", no_argument, 0, 's'},
                {0, 0, 0, 0}
        };
        while ((opt = getopt_long(argc, argv, "ms", longOptions, &optionIndex)) != -1) {
            switch (opt) {
            case 'm':
                LogInfo("Master mode enabled.");
                masterMode = true;
                break;
            case 's':
                LogInfo("Slave mode enabled.");
                slaveMode = true;
                break;
            default:
                printUsage(argv[0]);
                LogError("Invalid argument provided.");
                return 1;
            }
        }

        if (masterMode && slaveMode) {
            LogError("Cannot be both master and slave!");
            return 1;
        }

        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGPIPE);
        if (-1 == pthread_sigmask(SIG_BLOCK, &mask, NULL)) {
            LogError("Error in pthread_sigmask");
            return 1;
        }

        LogInfo("Start!");
        SecurityManager::SocketManager manager;

        if (masterMode) {
            auto allocator = []() -> SecurityManager::MasterService* {
                return new SecurityManager::MasterService();
            };
            REGISTER_SOCKET_SERVICE(manager, SecurityManager::MasterService, allocator);
        } else {
            auto allocator = [&slaveMode]() -> SecurityManager::Service* {
                return new SecurityManager::Service(slaveMode);
            };
            REGISTER_SOCKET_SERVICE(manager, SecurityManager::Service, allocator);
        }

        manager.MainLoop();
    }
    UNHANDLED_EXCEPTION_HANDLER_END
    return 0;
}
