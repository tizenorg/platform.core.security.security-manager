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

#include <dpl/log/log.h>
#include <dpl/singleton.h>
#include <dpl/singleton_safe_impl.h>

#include <socket-manager.h>

#include <thread>
#include <service.h>

IMPLEMENT_SAFE_SINGLETON(SecurityManager::Log::LogSystem);

#define REGISTER_SOCKET_SERVICE(manager, service) \
    registerSocketService<service>(manager, #service)

template<typename T>
void registerSocketService(SecurityManager::SocketManager &manager, const std::string& serviceName)
{
    T *service = NULL;
    try {
        service = new T();
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

#include <gio/gio.h>


void on_user_delete (GDBusConnection *connection,
 const gchar *sender_name,
 const gchar *object_path,
 const gchar *interface_name,
 const gchar *signal_name,
 GVariant *parameters,
 gpointer user_data)
{
 (void) connection;
 (void) sender_name;
 (void) object_path;
 (void) interface_name;
 (void) signal_name;
 (void) user_data;
 GVariant *gv_uid;
 gv_uid = g_variant_get_child_value (parameters, 0);
 guint32 uid = g_variant_get_uint32 (gv_uid);


 LogDebug("Dbus handler: User " << static_cast<unsigned int>(uid) << " is going to be deleted from db and cynara");
//TODO do something!
}


void dbusLoop(GMainLoop *loop) {

    GDBusConnection *connection;
    //loop = g_main_loop_new (NULL, FALSE);
    connection = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, NULL);
    (void)//we do not need to unsubscribe as for now
    g_dbus_connection_signal_subscribe (connection,
        "org.tizen.SecurityAccounts.gUserManagement",
        "org.tizen.SecurityAccounts.gUserManagement.UserService",
        "userDeleted",
        "/org/tizen/SecurityAccounts/gUserManagement/User",
        NULL,
        G_DBUS_SIGNAL_FLAGS_NONE,
        on_user_delete,
        NULL,
        NULL);

    LogError("Dbus Context created, attached to socket manager");

    g_main_loop_run(loop);

}

int main(void) {

    UNHANDLED_EXCEPTION_HANDLER_BEGIN
    {
        SecurityManager::Singleton<SecurityManager::Log::LogSystem>::Instance().SetTag("SECURITY_MANAGER");

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
        GMainLoop *loop;
        loop = g_main_loop_new (NULL, FALSE);
        std::thread dbusThread(dbusLoop, loop);

        REGISTER_SOCKET_SERVICE(manager, SecurityManager::Service);

        manager.MainLoop();
        g_main_loop_quit (loop);
        dbusThread.join();
    }
    UNHANDLED_EXCEPTION_HANDLER_END
    return 0;
}
