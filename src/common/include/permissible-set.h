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
 * @brief       Header with API for adding, deleting and reading permissible labels
 */
#ifndef _PERMISSIBLE_SET_H_
#define _PERMISSIBLE_SET_H_

#include <string>
#include <security-manager-types.h>

// This is a single-purpose class. Be aware that it inherits from std::vector,
// which doesn't have virtual destructor.
// If you reuse or modify this class, make sure that it's never deleted via a
// pointer to the base class.
template <typename T>
class PtrVector : public std::vector<T *> {
public:
    ~PtrVector() {for (T *ptr : *this) free(ptr);};
};

namespace SecurityManager {
namespace PermissibleSet {
/**
 * Add new permissable label to text file
 *
 * @param[in] label Smack label
 * @param[in] user UID
 * @param[in] installationType type of installation (global or local)
 * @return resulting true on success
 */
bool addLabelToPermissibleSet(const std::string &label, const std::string &user,
        int installationType);
/**
 * Removes label from the text file
 *
 * @param[in] label Smack label
 * @param[in] user UID
 * @param[in] installationType type of installation (global or local)
 * @return resulting true on success
 */
bool deleteLabelFromPermissibleSet(const std::string &label, const std::string &user,
        int installationType);
/**
 * Removes label from the text file
 *
 * @param[in] label_file path to label file
 * @param[out] labels vector with labels present in label_file
 * @return resulting SECURITY_MANAGER_SUCCESS on success or error code
 */
lib_retcode readLabelsFromPermissibleSet(const std::string label_file, PtrVector<char> &labels);
} // PermissibleSet
} // SecurityManager
#endif /* _PERMISSIBLE_SET_H_ */
