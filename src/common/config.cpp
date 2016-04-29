/*
 *  Copyright (c) 2015-2016 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        config.cpp
 * @author      Zofia Abramowska <z.abramowska@samsung.com>
 * @version     1.0
 * @brief       Setting values of Configuration options
 */

#include <config.h>

namespace SecurityManager {

namespace Config {

const std::string PRIVILEGE_VERSION =
#ifdef PRIVILEGE_VERSION
        PRIVILEGE_VERSION
#else
        "3.0"
#endif
;

const std::string PRIVILEGE_APPINST_USER     = "http://tizen.org/privilege/notexist";
const std::string PRIVILEGE_APPINST_ADMIN    = "http://tizen.org/privilege/notexist";
const std::string PRIVILEGE_USER_ADMIN       = "http://tizen.org/privilege/internal/usermanagement";
const std::string PRIVILEGE_POLICY_USER      = "http://tizen.org/privilege/notexist";
const std::string PRIVILEGE_POLICY_ADMIN     = "http://tizen.org/privilege/internal/usermanagement";
const std::string PRIVILEGE_APPSHARING_ADMIN = "http://tizen.org/privilege/notexist";

const std::string SMACK_APPS_LABELS_USER_FILE ="/smack-apps-labels";
const std::string SMACK_APPS_LABELS_GLOBAL_FILE ="/tmp/smack-global-apps-labels";
};

} /* namespace SecurityManager */
