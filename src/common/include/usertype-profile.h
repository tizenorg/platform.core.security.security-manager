/*
 *  Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        usertype-profile.h
 * @author      Krzysztof Sasiak <k.sasiak@samsung.com>
 * @brief       user type profile class
 */
/* vim: set ts=4 et sw=4 : */

#ifndef _SECURITY_MANAGER_USERTYPE_PROFILE_
#define _SECURITY_MANAGER_USERTYPE_PROFILE_

#include <dpl/exception.h>
#include <vector>

#include <tzplatform_config.h>

const char *const USERTYPE_POLICY_PATH = tzplatform_mkpath(TZ_SYS_SHARE, "security-manager/policy");

namespace SecurityManager {

class UserTypeProfileException
{
public:
    DECLARE_EXCEPTION_TYPE(SecurityManager::Exception, Base)
    DECLARE_EXCEPTION_TYPE(Base, FileNameIsEmpty)
    DECLARE_EXCEPTION_TYPE(Base, FileAccessError)
    DECLARE_EXCEPTION_TYPE(Base, FileParsingError)
};


struct UserTypePrivilege {
    std::string app;
    std::string privilege;
};


class UserTypeProfile {
public:
    UserTypeProfile(const std::string &fileName);
    ~UserTypeProfile(void);
    void getPrivilegesList(std::vector<UserTypePrivilege> &privilegesList);

private:
    void parseFile(void);

    std::string mFileName;
    bool mFileParsed;
    std::vector<UserTypePrivilege> mPrivilegesList;
};

} // namespace SecurityManager

#endif // _SECURITY_MANAGER_USERTYPE_PROFILE_
