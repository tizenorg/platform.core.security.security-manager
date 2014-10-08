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
#include <service-common.h>
#include <file-lock.h>
#include <security-manager.h>

namespace SecurityManager {
} // namespace SecurityManager

IMPLEMENT_SAFE_SINGLETON(SecurityManager::Log::LogSystem);

static const char *g_shortOptions = "a:g:hu:";

static struct option g_longOptions[] = {
    {"app", required_argument, NULL, 'a'},
    {"paths", required_argument, NULL, 'p'},
    {"pkg", required_argument, NULL, 'g'},
    {"privileges", required_argument, NULL, 's'},
    {"uid", required_argument, NULL, 'u'},
    {"help", no_argument, NULL, 'h'},
    {0, 0, 0, 0}
};

enum cmds_e {
    ECMD_INSTALL = 0,
    ECMD_COUNT
};

struct args {
    cmds_e cmd;
    std::string appName;
    std::string pkgName;
    std::string uidstr;
    uid_t uid;
    std::string privilegesFile;
    std::string appPathsFile;
};

static const std::vector<std::string> cmdsNames = {
    "install",
};

static void usage(char *name)
{
    using namespace std;

    cout << endl << name << " usage:" << endl << endl;
    cout << name << " [options] command" << endl << endl;
    cout << "Commands:" << endl;
    for (auto &cmd : cmdsNames) {
        cout << "       " << cmd << endl;
    }
    cout << endl;
    cout << "Options:" << endl;
    cout << "-a APP --app APP (required)" << endl;
    cout << "        application name" << endl;
    cout << "-p PATHSFILE --paths PATHSFILE (optional)" << endl;
    cout << "        file name with paths for setting smack labels" << endl;
    cout << "-g PKG --pkg PKG (optional)" << endl;
    cout << "        package name for the application." << endl;
    cout << "        If not given it gets the application name." << endl;
    cout << "-s PRIVILEGESFILE --privileges PRIVILEGESFILE (optional)" << endl;
    cout << "        file name with privileges for the application" << endl;
    cout << "-u UID --uid UID (required)" << endl;
    cout << "        user identifier" << endl;
    cout << "-h --help" << endl;
    cout << "        show this help message and exit" << endl;
    cout << endl;
    exit(EXIT_SUCCESS);
}

bool parse_cmds(std::string cmd, struct args &args)
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

static bool parse_args(int argc, char *argv[], struct args &args)
{
    int c, optidx = 0;

    if (argc < 2)
        usage(argv[0]);
    while ((c = getopt_long_only(argc, argv, g_shortOptions, g_longOptions,
                                 &optidx)) != -1) {
        switch (c) {
        case 'a':
            args.appName = std::string(optarg);
            args.pkgName = args.appName;
            break;
        case 'g':
            args.pkgName = std::string(optarg);
            break;
        case 'h':
            usage(argv[0]);
            break;
        case 'p':
            args.appPathsFile = std::string(optarg);
            break;
        case 's':
            args.privilegesFile = std::string(optarg);
            break;
        case 'u':
            args.uidstr = std::string(optarg);
            break;
        case '?':
        default:
            usage(argv[0]);
        }
    }
    if (argc > (optind + 1))
        usage(argv[0]);
    if (optind < argc) {
        if (!parse_cmds(std::string(argv[optind]), args))
            usage(argv[0]);
    } else
        usage(argv[0]);
    if ((args.appName.empty()) || (args.pkgName.empty()))
        usage(argv[0]);
    if (args.uidstr.empty())
        usage(argv[0]);
    return false;
}

/*
void print_helper_msg(void)
{
    std::cout << "Please check if security-manager service is running."
                 << std::endl << "If it is then stop it befor running "
                 "this application." << std::endl;
    std::cout << "If it is not running: please check if the file: " <<
                 std::endl << SecurityManager::SERVICE_LOCK_FILE << std::endl
                 << "is used by any other process - "
                 "if it is not remove that file." << std::endl;
}
*/

bool loadPrivilegesFromFile(std::string fileName,
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

bool loadPathsFromFile(std::string fileName,
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

int main(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;

    UNHANDLED_EXCEPTION_HANDLER_BEGIN
    {
        SecurityManager::Singleton<SecurityManager::Log::LogSystem>::Instance().SetTag("SECURITY_MANAGER_INSTALLER");

        struct args args;

        parse_args(argc, argv, args);
        args.uid = static_cast<uid_t>(std::stoi(args.uidstr, nullptr));

        int i;
        LogDebug("argc: " << argc);
        for (i = 0; i < argc; ++i)
            LogDebug("argv [" << i << "]: " << argv[i]);
        LogDebug("SecurityManager service lock file: "
                 << SecurityManager::SERVICE_LOCK_FILE);

        app_inst_req req;
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
    }
    UNHANDLED_EXCEPTION_HANDLER_END

    return ret;
}

