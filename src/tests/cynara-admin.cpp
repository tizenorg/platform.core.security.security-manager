/*
 *  Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        cynara-admin.cpp
 * @author      Sebastian Grabowski <s.grabowski@samsung.com>
 * @brief       Implementation of unit tests for CynaraAdmin class
 */
/* vim: set ts=4 et sw=4 tw=78 : */

#include "gtest/gtest.h"

#define private public
#include "cynara.h"
#undef private

using namespace SecurityManager;

TEST(CynaraAdminTests, BucketManagement)
{
    const std::string b = "__wiadro_testowe_1_";
    EXPECT_THROW(CynaraAdmin::getInstance().CreateBucket(b,
                 CynaraAdminPolicy::Operation::Delete),
                 CynaraException::InvalidParam);
    EXPECT_THROW(CynaraAdmin::getInstance().CreateBucket(b,
                 CynaraAdminPolicy::Operation::Bucket),
                 CynaraException::InvalidParam);
    EXPECT_NO_THROW({
            CynaraAdmin::getInstance().RemoveBucket(b + 'a');
            });
    ASSERT_NO_THROW({
            CynaraAdmin::getInstance().CreateBucket(b,
                CynaraAdminPolicy::Operation::Deny);
            });
    EXPECT_NO_THROW({
            CynaraAdmin::getInstance().CreateBucket(b,
                CynaraAdminPolicy::Operation::Allow);
            });
    EXPECT_NO_THROW({
            CynaraAdmin::getInstance().CreateBucket(b,
                CynaraAdminPolicy::Operation::None);
            });
    ASSERT_NO_THROW({
            CynaraAdmin::getInstance().RemoveBucket(b);
            });
}

TEST(CynaraAdminTests, EmptyBucket)
{
    const std::string b = "__wiadro_testowe_2_";
    const std::string client = "client";
    const std::string user = "user";
    const std::string privilege = "privilege";
    std::vector<CynaraAdminPolicy> policies;

    policies.push_back(CynaraAdminPolicy(client, user, privilege,
                       CynaraAdminPolicy::Operation::Deny, b));
    EXPECT_NO_THROW({
            CynaraAdmin::getInstance().RemoveBucket(b);
            });
    EXPECT_THROW(CynaraAdmin::getInstance().EmptyBucket(b, false, client, user,
                                                        privilege),
                 CynaraException::BucketNotFound);
    ASSERT_NO_THROW({
            CynaraAdmin::getInstance().CreateBucket(b,
                CynaraAdminPolicy::Operation::Allow);
            });
    EXPECT_NO_THROW({
            CynaraAdmin::getInstance().EmptyBucket(b, false, client, user,
                                                   privilege);
            });
    EXPECT_NO_THROW({
            CynaraAdmin::getInstance().SetPolicies(policies);
            });
    ASSERT_NO_THROW({
            CynaraAdmin::getInstance().RemoveBucket(b);
            });
}

