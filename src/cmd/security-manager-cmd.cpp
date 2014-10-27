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

#include <getopt.h>
#include <iostream>
#include <fstream>
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

enum cmds_e {
    ECMD_INSTALL = 0,
    ECMD_COUNT
};

struct args {
    cmds_e cmd;
    po::variables_map vm;
    std::string appName;
    std::string pkgName;
    uid_t uid;
    std::string privilegesFile;
    std::string appPathsFile;
};

static const std::vector<std::string> cmdsNames = {
    "install",
};

static bool parseCommand(std::string &cmd, struct args &args)
{
    bool ret = false;

    for (int i = 0; i < ECMD_COUNT; ++i) {
        if (cmd.compare(cmdsNames[i]) == 0) {
            args.cmd = static_cast<cmds_e>(i);
            ret = true;
            break;
        }
    }
    return ret;
}

static po::options_description getGenericOptions()
{
    po::options_description opts("Generic options");
    opts.add_options()
         ("help,h", "produce help message")
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
         ("paths,p", po::value<std::string>(),
          "file name with paths for setting smack labels")
         ("privileges,s", po::value<std::string>(),
          "file name with privileges for the application")
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

    cout << endl << name << " usage:" << endl << endl;
    cout << name << " command [options]" << endl << endl;
    cout << "Commands:" << endl;
    for (auto &cmd : cmdsNames)
        cout << "       " << cmd << endl;
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
                      style(po::command_line_style::unix_style |
                            po::command_line_style::allow_long_disguise).
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

static bool parseInstallOptions(int argc, char *argv[], struct args &args,
                                po::variables_map &vm)
{
    bool ret;
    ret = parseCommandOptions(argc, argv, cmdsNames[ECMD_INSTALL],
                              getInstallOptions(), vm);
    if (!ret)
        return ret;
    try {
        if (vm.count("app"))
            args.appName = vm["app"].as<std::string>();
        if (vm.count("pkg"))
            args.pkgName = vm["pkg"].as<std::string>();
        if (vm.count("paths"))
            args.appPathsFile = vm["paths"].as<std::string>();
        if (vm.count("privileges"))
            args.privilegesFile = vm["privileges"].as<std::string>();
        if (vm.count("uid"))
            args.uid = vm["uid"].as<uid_t>();
    } catch (const std::exception &e) {
        std::cout << "Error while parsing install arguments: " << e.what() <<
                  std::endl;
        LogError("Error while parsing install arguments: " << e.what());
        ret = false;
    }
    return ret;
}

static bool loadPrivilegesFromFile(std::string fileName,
                                   std::vector<std::string> &privileges)
{
    if (fileName.empty())
        return true;

    std::ifstream ifs(fileName);

    if (!ifs)
        return false;

    LogDebug("Loading privileges from file: " << fileName);

    privileges.clear();
    for (std::string line; std::getline(ifs, line); )
        privileges.push_back(line);
    ifs.close();

    return (!privileges.empty());
}

static bool loadPathsFromFile(std::string fileName,
                              std::vector<std::pair<std::string, int>> &paths)
{
    if (fileName.empty())
        return true;

    std::ifstream ifs(fileName);

    if (!ifs)
        return false;

    LogDebug("Loading paths from file: " << fileName);

    paths.clear();
    for (std::string line; std::getline(ifs, line); ) {
        unsigned int pathType = 0;
        std::stringstream ss(line);
        std::string sPath, sType;
        ss >> sPath >> sType;

        if (sPath[0] == '#')
            continue;
        if (ss.fail() || !ss.eof()) {
            paths.clear();
            LogError("Syntax error in " << fileName << " file.");
            return false;
        }
        try {
            pathType = std::stoul(sType, nullptr);
        } catch (const std::exception &e) {
            LogDebug("Failed to convert path type '" << sType <<
                     "' to a number.");
            paths.clear();
            return false;
        }
        if (pathType >= SECURITY_MANAGER_ENUM_END) {
            LogError("Invalid path type found.");
            paths.clear();
            return false;
        }
        paths.push_back(std::make_pair(sPath, pathType));
    }
    ifs.close();

    return (!paths.empty());
}

static int installApp(struct args &args)
{
    int ret = EXIT_FAILURE;

    struct app_inst_req req;
    if (!loadPrivilegesFromFile(args.privilegesFile, req.privileges))
        return EXIT_FAILURE;

    if (!loadPathsFromFile(args.appPathsFile, req.appPaths))
        return EXIT_FAILURE;

    req.uid = args.uid;
    req.appId = args.appName;
    req.pkgId = args.pkgName;

    ret = security_manager_app_install(&req);
    if (SECURITY_MANAGER_SUCCESS == ret) {
        std::cout << "Application " << args.appName <<
                  " installed successfully." << std::endl;
        LogDebug("Application " << args.appName <<
                 " installed successfully.");
    } else {
        std::cout << "Failed to install " << args.appName <<
                  " application. Return code: " << ret <<
                  std::endl;
        LogDebug("Failed to install " << args.appName <<
                 " application. Return code: " << ret);
    }
    return ret;
}

static bool parseArguments(int argc, char *argv[], struct args &args)
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

    std::string cmd;
    if (argv[1][0] != '-')
        cmd = std::string(argv[1]);
    if (cmd.empty()) {
        usage(std::string(argv[0]));
        return false;
    }

    if (!parseCommand(cmd, args)) {
        std::cout << "Unkown command." << std::endl;
        usage(std::string(argv[0]));
        return false;
    }

    if (argc > 2) {
        if (parseGenericOptions(argc - 1, &argv[1], args.vm))
            return false;
    } else {
        std::cout << "Missing arguments." << std::endl;
        usage(std::string(argv[0]));
        return false;
    }

    return true;
}

int main(int argc, char *argv[])
{
    UNHANDLED_EXCEPTION_HANDLER_BEGIN
    {
        SecurityManager::Singleton<SecurityManager::Log::LogSystem>::Instance().SetTag("SECURITY_MANAGER_INSTALLER");

        struct args args;
        if (!parseArguments(argc, argv, args))
            return EXIT_FAILURE;
        switch (args.cmd) {
            case ECMD_INSTALL:
                if (!parseInstallOptions(argc - 1, &argv[1], args, args.vm))
                    return EXIT_FAILURE;
                else
                    return installApp(args);
            default:
                return EXIT_FAILURE;
        }
    }
    UNHANDLED_EXCEPTION_HANDLER_END

    return EXIT_FAILURE;
}

