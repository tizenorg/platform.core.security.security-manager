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
 * @file        label-files.h
 * @author      Radoslaw Bartosiak (r.bartosiak@samsung.com)
 * @version     1.0
 * @brief       This file contains header of API for adding and deleting labels to files
 */
#ifndef SRC_COMMON_INCLUDE_LABEL_FILES_H_
#define SRC_COMMON_INCLUDE_LABEL_FILES_H_

#include <string>

namespace SecurityManager {
namespace LabelFiles {
/**
 * Add new permissable label to text file
 *
 * @param[in] label Smack label
 * @param[in] user UID
 * @param[in] installationType type of installation (global or local)
 * @return resulting true on success
 */
bool addLabelToPermissibleSet(const std::string &label, const std::string &user, const int installationType);
/**
 * Removes label from the text file
 *
 * @param[in] label Smack label
 * @param[in] user UID
 *  @param[in] installationType type of installation (global or local)
 * @return resulting true on success
 */
bool deleteLabelFromPermissibleSet(const std::string &label, const std::string &user, const int installationType);
}
}
#endif /* SRC_COMMON_INCLUDE_LABEL_FILES_H_ */
