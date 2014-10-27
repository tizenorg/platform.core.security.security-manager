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
 * @file        service-manager-cmd.cpp
 * @author      Sebastian Grabowski (s.grabowski@samsung.com)
 * @version     1.0
 * @brief       Implementation of security-manager-cmd tool for offline mode
 */
/* vim: set ts=4 et sw=4 tw=78 : */

#include <iostream>
#include <utility>

#include <dpl/log/log.h>
#include <dpl/singleton.h>
#include <dpl/singleton_safe_impl.h>
#include <file-lock.h>
#include <protocols.h>
#include <security-manager.h>

#include <boost/program_options.hpp>
namespace po = boost::program_options;

IMPLEMENT_SAFE_SINGLETON(SecurityManager::Log::LogSystem);

static po::options_description getGenericOptions()
{
    po::options_description opts("Generic options");
    opts.add_options()
         ("help,h", "produce help message")
         ("install,i", "install an application")
         ;
    return opts;
}

static po::options_description getInstallOptions()
{
    po::options_description opts("Install options");
    opts.add_options()
         ("app,a", po::value<std::string>()->required(),
          "application name (required)")
         ("pkg,g", po::value<std::string>()->required(),
          "package name for the application (required)")
         ("path,p", po::value< std::vector<std::string> >()->multitoken()->composing(),
          "path for setting smack labels (may occure more than once)")
         ("privilege,s", po::value< std::vector<std::string> >()->composing(),
          "privilege for the application (may occure more than once)")
         ("uid,u", po::value<uid_t>()->required(),
          "user identifier number (required)")
         ;
    return opts;
}

static po::options_description getAllOptions()
{
    po::options_description opts("Allowed options");
    opts.add(getGenericOptions()).add(getInstallOptions());
    return opts;
}

static void usage(std::string name)
{
    using namespace std;

    cout << endl << name << " usage:" << endl;
    cout << endl << getAllOptions() << endl << endl;
}

static bool parseGenericOptions(int argc, char *argv[], po::variables_map &vm)
{
    bool ifExit = false;

    po::store(po::command_line_parser(argc, argv).
              options(getGenericOptions()).allow_unregistered().run(),
              vm);
    if (vm.count("help")) {
        usage(std::string(argv[0]));
        ifExit = true;
    }

    return ifExit;
}

static bool parseCommandOptions(int argc, char *argv[], std::string cmd,
                                po::options_description opts,
                                po::variables_map &vm)
{
    bool ret = false;

    try {
        const po::positional_options_description p;
        po::store(po::command_line_parser(argc, argv).
                      options(getGenericOptions().add(opts)).positional(p).
                      style((po::command_line_style::unix_style |
                            po::command_line_style::allow_long_disguise) &
                            ~po::command_line_style::allow_guessing).
                      run(),
                  vm);
        //po::store(po::parse_command_line(argc, argv,
        //                                 getGenericOptions().add(opts)), vm);
        po::notify(vm);
        ret = true;
    } catch (const po::error &e) {
        std::cout << "Error parsing " << cmd << " command arguments: " <<
                  e.what() << std::endl;
        LogError("Error parsing " << cmd << " command arguments: " << e.what());
    } catch (const std::exception &e) {
        std::cout << "Unknown error while parsing " << cmd <<
                  " command arguments: " << e.what() << std::endl;
        LogError("Unknown error while parsing " << cmd <<
                 " command arguments: " << e.what());
    }

    return ret;
}

static bool loadPaths(const std::vector<std::string> &paths,
                      struct app_inst_req &req)
{
    if (paths.size() & 1) {
        LogDebug("Wrong paths size: " << paths.size());
        return false;
    }
    req.appPaths.clear();
    for (std::vector<std::string>::size_type i = 0; i < paths.size(); ++i) {
        int pathType;
        if (i & 1) {
            LogDebug("path: " << paths[i - 1]);
            try {
                pathType = std::stoul(paths[i], nullptr);
            } catch (const std::exception &e) {
                LogDebug("Failed to convert path type '" << paths[i] <<
                         "' to a number.");
                req.appPaths.clear();
                return false;
            }
            if (pathType >= SECURITY_MANAGER_ENUM_END) {
                LogError("Invalid path type found.");
                req.appPaths.clear();
                return false;
            }
            LogDebug("path type: " << pathType);
            req.appPaths.push_back(std::make_pair(paths[i - 1], pathType));
        }
    }
    return (!req.appPaths.empty());
}

static bool parseInstallOptions(int argc, char *argv[],
                                struct app_inst_req &req,
                                po::variables_map &vm)
{
    bool ret;
    ret = parseCommandOptions(argc, argv, "install", getInstallOptions(), vm);
    if (!ret)
        return ret;
    try {
        if (vm.count("app"))
            req.appId = vm["app"].as<std::string>();
        if (vm.count("pkg"))
            req.pkgId = vm["pkg"].as<std::string>();
        if (vm.count("path")) {
            const std::vector<std::string> paths =
                vm["path"].as<std::vector<std::string> >();
            if (!loadPaths(paths, req)) {
                LogError("Error in parsing path arguments.");
                return false;
            }
        }
        if (vm.count("privilege")) {
            req.privileges = vm["privilege"].as<std::vector<std::string> >();
            if (req.privileges.empty()) {
                LogError("Error in parsing privilege arguments.");
                return false;
            }
        }
        if (vm.count("uid"))
            req.uid = vm["uid"].as<uid_t>();
    } catch (const std::exception &e) {
        std::cout << "Error while parsing install arguments: " << e.what() <<
                  std::endl;
        LogError("Error while parsing install arguments: " << e.what());
        ret = false;
    }
    return ret;
}

static int installApp(const struct app_inst_req &req)
{
    int ret = EXIT_FAILURE;

    ret = security_manager_app_install(&req);
    if (SECURITY_MANAGER_SUCCESS == ret) {
        std::cout << "Application " << req.appId <<
                  " installed successfully." << std::endl;
        LogDebug("Application " << req.appId <<
                 " installed successfully.");
    } else {
        std::cout << "Failed to install " << req.appId <<
                  " application. Return code: " << ret <<
                  std::endl;
        LogDebug("Failed to install " << req.appId <<
                 " application. Return code: " << ret);
    }
    return ret;
}

static bool parseArguments(int argc, char *argv[], po::variables_map &vm)
{
    LogDebug("argc: " << argc);
    for (int i = 0; i < argc; ++i)
        LogDebug("argv [" << i << "]: " << argv[i]);
    LogDebug("SecurityManager service lock file: "
             << SecurityManager::SERVICE_LOCK_FILE);
    if (argc < 2) {
        std::cout << "Missing arguments." << std::endl;
        usage(std::string(argv[0]));
        return false;
    }
    if (parseGenericOptions(argc, argv, vm))
        return false;
    LogDebug("Generic arguments has been parsed.");
    return true;
}

int main(int argc, char *argv[])
{
    struct app_inst_req *req;
    po::variables_map vm;
    int ret = EXIT_FAILURE;

    UNHANDLED_EXCEPTION_HANDLER_BEGIN
    {
        SecurityManager::Singleton<SecurityManager::Log::LogSystem>::Instance().SetTag("SECURITY_MANAGER_INSTALLER");

        if (security_manager_app_inst_req_new(&req) != SECURITY_MANAGER_SUCCESS)
            return ret;

        if (!parseArguments(argc, argv, vm))
            goto out;
        if (vm.count("install")) {
            LogDebug("Install command.");
            if (parseInstallOptions(argc, argv, *req, vm))
                ret = installApp(*req);
        }
    }
    UNHANDLED_EXCEPTION_HANDLER_END

out:
    security_manager_app_inst_req_free(req);
    return ret;
}

