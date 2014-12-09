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
 * @file        usertype-profile.cpp
 * @author      Krzysztof Sasiak <k.sasiak@samsung.com>
 * @brief       user type profile class
 */
/* vim: set ts=4 et sw=4 : */

#include <cstring>
#include <boost/algorithm/string.hpp>
#include <fstream>
#include <string>
#include <vector>

#include "usertype-profile.h"

namespace SecurityManager {


UserTypeProfile::UserTypeProfile(const std::string &fileName) : mFileName(fileName), mFileParsed(false)
{
    if (fileName.length() == 0)
        ThrowMsg(UserTypeProfileException::FileNameIsEmpty,
            std::string("File name is empty"));
}

UserTypeProfile::~UserTypeProfile()
{
}


void UserTypeProfile::parseFile()
{
    int i = 0;
    std::string line;
    std::ifstream usertypePolicyFile(mFileName);

    if (!usertypePolicyFile.is_open()) {
        ThrowMsg(UserTypeProfileException::FileAccessError,
            "Cannot open user policy file: " << mFileName);
    }

    while (std::getline(usertypePolicyFile, line)) {
        ++i;
        boost::algorithm::trim(line);
        //skip comments
        if (line[0] == '\'') continue;

        std::vector<std::string> fields;
        boost::split(fields, line, boost::is_any_of("\t "));

        //continue on empty line
        if (fields.size() == 0)
            continue;

        if (fields.size() != 2)
            ThrowMsg(UserTypeProfileException::FileParsingError,
                "Error while parsing policy file: " << mFileName << ", line: " << i);

        UserTypePrivilege privilege;
        privilege.app = boost::algorithm::trim_copy(fields[0]);
        privilege.privilege = boost::algorithm::trim_copy(fields[1]);

        mPrivilegesList.push_back(privilege);
    }
    mFileParsed = true;
}

void UserTypeProfile::getPrivilegesList(std::vector<UserTypePrivilege> &privilegesList)
{
    if (!mFileParsed)
        this->parseFile();

    privilegesList = mPrivilegesList;
}

} // namespace SecurityManager
