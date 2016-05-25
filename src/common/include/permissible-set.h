/*
 *  Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        permissible-set.h
 * @author      Rafał Krypa <r.krypa@samsung.com>
 * @author      Radoslaw Bartosiak <r.bartosiak@samsung.com>
 * @version     1.0
 * @brief       Header with API for adding, deleting and reading permissible names
 * @brief       (names of installed applications)
 */
#ifndef _PERMISSIBLE_SET_H_
#define _PERMISSIBLE_SET_H_

#include <cstdlib>
#include <string>
#include <vector>

#include <dpl/exception.h>
#include <security-manager-types.h>

namespace SecurityManager {
namespace PermissibleSet {

class PermissibleSetException {
public:
    DECLARE_EXCEPTION_TYPE(SecurityManager::Exception, Base)
    DECLARE_EXCEPTION_TYPE(Base, FileLockError)
    DECLARE_EXCEPTION_TYPE(Base, FileOpenError)
    DECLARE_EXCEPTION_TYPE(Base, FileReadError)
    DECLARE_EXCEPTION_TYPE(Base, FileWriteError)
    DECLARE_EXCEPTION_TYPE(Base, FileConfigError)
};
/**
 * Return path to file with current list of application names
 * installed globally or locally for the user.
 *
 * @param[in] uid identifier of the user whose application it should be
 * @param[in] installationType type of installation (global or local)
 * @return path to file with names
 */
std::string getPerrmissibleFileLocation(const uid_t uid, int installationType);
/**
 * Update permissable file with current content of database
 * @throws FileLockError
 * @throws FileOpenError
 * @throws FileWriteError
 *
 * @param[in] uid user id
 * @param[in] installationType type of installation (global or local)
 * @return resulting true on success
 */
void updatePermissibleFile(const uid_t uid, const int installationType);
/**
 * Read names from a file into a vector
 * @throws FileLockError
 * @throws FileOpenError
 * @throws FileReadError
 *
 * @param[in] nameFile contains application names
 * @param[out] names vector to which application names are added
 * @return SECURITY_MANAGER_SUCCESS or error code
 */
void readNamesFromPermissibleFile(const std::string &nameFile, std::vector<std::string> &names);
} // PermissibleSet
} // SecurityManager
#endif /* _PERMISSIBLE_SET_H_ */
