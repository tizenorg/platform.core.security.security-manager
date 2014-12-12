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
 * @file        cynara.cpp
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @brief       Wrapper class for Cynara interface
 */

#include <cstring>
#include "cynara.h"

#include <dpl/log/log.h>

namespace SecurityManager {

CynaraAdmin::BucketsMap CynaraAdmin::Buckets =
{
    { Bucket::PRIVACY_MANAGER, std::string("PRIVACY_MANAGER")},
    { Bucket::MAIN, std::string("MAIN")},
    { Bucket::USER_TYPE_ADMIN, std::string("USER_TYPE_ADMIN")},
    { Bucket::USER_TYPE_NORMAL, std::string("USER_TYPE_NORMAL")},
    { Bucket::USER_TYPE_GUEST, std::string("USER_TYPE_GUEST") },
    { Bucket::USER_TYPE_SYSTEM, std::string("USER_TYPE_SYSTEM")},
    { Bucket::ADMIN, std::string("ADMIN")},
    { Bucket::MANIFESTS, std::string("MANIFESTS")},
};


CynaraAdminPolicy::CynaraAdminPolicy(const std::string &client, const std::string &user,
        const std::string &privilege, Operation operation,
        const std::string &bucket)
{
    this->client = strdup(client.c_str());
    this->user = strdup(user.c_str());
    this->privilege = strdup(privilege.c_str());
    this->bucket = strdup(bucket.c_str());

    if (this->bucket == nullptr || this->client == nullptr ||
        this->user == nullptr || this->privilege == nullptr) {
        free(this->bucket);
        free(this->client);
        free(this->user);
        free(this->privilege);
        ThrowMsg(CynaraException::OutOfMemory,
                std::string("Error in CynaraAdminPolicy allocation."));
    }

    this->result = static_cast<int>(operation);
    this->result_extra = nullptr;
}

CynaraAdminPolicy::CynaraAdminPolicy(const std::string &client, const std::string &user,
    const std::string &privilege, const std::string &goToBucket,
    const std::string &bucket)
{
    this->bucket = strdup(bucket.c_str());
    this->client = strdup(client.c_str());
    this->user = strdup(user.c_str());
    this->privilege = strdup(privilege.c_str());
    this->result_extra = strdup(goToBucket.c_str());
    this->result = CYNARA_ADMIN_BUCKET;

    if (this->bucket == nullptr || this->client == nullptr ||
        this->user == nullptr || this->privilege == nullptr ||
        this->result_extra == nullptr) {
        free(this->bucket);
        free(this->client);
        free(this->user);
        free(this->privilege);
        free(this->result_extra);
        ThrowMsg(CynaraException::OutOfMemory,
                std::string("Error in CynaraAdminPolicy allocation."));
    }
}

CynaraAdminPolicy::CynaraAdminPolicy(struct cynara_admin_policy &&that)
{
    bucket = that.bucket;
    client = that.client;
    user = that.user;
    privilege = that.privilege;
    result_extra = that.result_extra;
    result = that.result;

    that.bucket = nullptr;
    that.client = nullptr;
    that.user = nullptr;
    that.privilege = nullptr;
    that.result_extra = nullptr;
}

CynaraAdminPolicy::~CynaraAdminPolicy()
{
    free(this->bucket);
    free(this->client);
    free(this->user);
    free(this->privilege);
    free(this->result_extra);
}

static bool checkCynaraError(int result, const std::string &msg)
{
    switch (result) {
        case CYNARA_API_SUCCESS:
        case CYNARA_API_ACCESS_ALLOWED:
            return true;
        case CYNARA_API_ACCESS_DENIED:
            return false;
        case CYNARA_API_OUT_OF_MEMORY:
            ThrowMsg(CynaraException::OutOfMemory, msg);
        case CYNARA_API_INVALID_PARAM:
            ThrowMsg(CynaraException::InvalidParam, msg);
        case CYNARA_API_SERVICE_NOT_AVAILABLE:
            ThrowMsg(CynaraException::ServiceNotAvailable, msg);
        case CYNARA_API_BUCKET_NOT_FOUND:
            ThrowMsg(CynaraException::BucketNotFound, msg);
        default:
            ThrowMsg(CynaraException::UnknownError, msg);
    }
}

static void linkBuckets(const std::string &bucket,
                       const std::string &goToBucket)
{
    std::vector<CynaraAdminPolicy> policies;

    policies.push_back(CynaraAdminPolicy(
                CYNARA_ADMIN_WILDCARD,
                CYNARA_ADMIN_WILDCARD,
                CYNARA_ADMIN_WILDCARD,
                goToBucket,
                bucket
    ));

    CynaraAdmin::getInstance().SetPolicies(policies);
}

CynaraAdmin::CynaraAdmin()
{
    checkCynaraError(
        cynara_admin_initialize(&m_CynaraAdmin),
        "Cannot connect to Cynara administrative interface.");
}

CynaraAdmin::~CynaraAdmin()
{
    cynara_admin_finish(m_CynaraAdmin);
}

CynaraAdmin &CynaraAdmin::getInstance()
{
    static CynaraAdmin cynaraAdmin;
    return cynaraAdmin;
}

void CynaraAdmin::SetPolicies(const std::vector<CynaraAdminPolicy> &policies)
{
    std::vector<const struct cynara_admin_policy *> pp_policies(policies.size() + 1);

    LogDebug("Sending " << policies.size() << " policies to Cynara");
    for (std::size_t i = 0; i < policies.size(); ++i) {
        pp_policies[i] = static_cast<const struct cynara_admin_policy *>(&policies[i]);
        LogDebug("policies[" << i << "] = {" <<
            ".bucket = " << pp_policies[i]->bucket << ", " <<
            ".client = " << pp_policies[i]->client << ", " <<
            ".user = " << pp_policies[i]->user << ", " <<
            ".privilege = " << pp_policies[i]->privilege << ", " <<
            ".result = " << pp_policies[i]->result << ", " <<
            ".result_extra = " << pp_policies[i]->result_extra << "}");
    }

    pp_policies[policies.size()] = nullptr;

    checkCynaraError(
        cynara_admin_set_policies(m_CynaraAdmin, pp_policies.data()),
        "Error while updating Cynara policy.");
}

void CynaraAdmin::UpdatePackagePolicy(
    const std::string &label,
    const std::string &user,
    const std::vector<std::string> &oldPrivileges,
    const std::vector<std::string> &newPrivileges)
{
    std::vector<CynaraAdminPolicy> policies;

    // Perform sort-merge join on oldPrivileges and newPrivileges.
    // Assume that they are already sorted and without duplicates.
    auto oldIter = oldPrivileges.begin();
    auto newIter = newPrivileges.begin();

    while (oldIter != oldPrivileges.end() && newIter != newPrivileges.end()) {
        int compare = oldIter->compare(*newIter);
        if (compare == 0) {
            LogDebug("(user = " << user << " label = " << label << ") " <<
                "keeping privilege " << *newIter);
            ++oldIter;
            ++newIter;
            continue;
        } else if (compare < 0) {
            LogDebug("(user = " << user << " label = " << label << ") " <<
                "removing privilege " << *oldIter);
            policies.push_back(CynaraAdminPolicy(label, user, *oldIter,
                    CynaraAdminPolicy::Operation::Delete));
            ++oldIter;
        } else {
            LogDebug("(user = " << user << " label = " << label << ") " <<
                "adding privilege " << *newIter);
            policies.push_back(CynaraAdminPolicy(label, user, *newIter,
                    CynaraAdminPolicy::Operation::Allow));
            ++newIter;
        }
    }

    for (; oldIter != oldPrivileges.end(); ++oldIter) {
        LogDebug("(user = " << user << " label = " << label << ") " <<
            "removing privilege " << *oldIter);
        policies.push_back(CynaraAdminPolicy(label, user, *oldIter,
                    CynaraAdminPolicy::Operation::Delete));
    }

    for (; newIter != newPrivileges.end(); ++newIter) {
        LogDebug("(user = " << user << " label = " << label << ") " <<
            "adding privilege " << *newIter);
        policies.push_back(CynaraAdminPolicy(label, user, *newIter,
                    CynaraAdminPolicy::Operation::Allow));
    }

    CynaraAdmin::getInstance().SetPolicies(policies);
}

void CynaraAdmin::CreateBucket(
    const std::string &bucketName, CynaraAdminPolicy::Operation defaultPolicy)
{
    switch(defaultPolicy) {
        case CynaraAdminPolicy::Operation::Bucket:
        case CynaraAdminPolicy::Operation::Delete:
            ThrowMsg(CynaraException::InvalidParam, "Unsupported default policy");
            break;
        default:
            checkCynaraError(
                cynara_admin_set_bucket(m_CynaraAdmin, bucketName.c_str(),
                    static_cast<int>(defaultPolicy), ""),
                "Error while creating or updating bucket: " + bucketName);
    }
}

void CynaraAdmin::RemoveBucket(const std::string &bucketName)
{
    int ret = cynara_admin_set_bucket(m_CynaraAdmin, bucketName.c_str(),
                static_cast<int>(CynaraAdminPolicy::Operation::Delete), "");
    if (ret == CYNARA_API_BUCKET_NOT_FOUND)
        LogDebug(__func__ << " - Bucket doesn't exist: " << bucketName);
}

void CynaraAdmin::EmptyBucket(const std::string &bucketName, bool recursive, const std::string &client,
    const std::string &user, const std::string &privilege)
{
    checkCynaraError(
        cynara_admin_erase(m_CynaraAdmin, bucketName.c_str(), static_cast<int>(recursive),
            client.c_str(), user.c_str(), privilege.c_str()),
        "Error while emptying bucket: " + bucketName + ", filter (C, U, P): " +
            client + ", " + user + ", " + privilege);
}

void CynaraAdmin::DefineUserTypePolicy(
    const std::string &usertype,
    const std::vector<UserTypePrivilege> &privileges)
{
    std::vector<CynaraAdminPolicy> policies;

    for (auto & privilege : privileges) {
        policies.push_back(
            CynaraAdminPolicy(privilege.app, CYNARA_ADMIN_WILDCARD, privilege.privilege,
                CynaraAdminPolicy::Operation::Allow, usertype));
    };
    try {
        CynaraAdmin::getInstance().EmptyBucket(usertype, false,
            CYNARA_ADMIN_WILDCARD, CYNARA_ADMIN_WILDCARD, CYNARA_ADMIN_WILDCARD);
    } catch (CynaraException::BucketNotFound) {
        //Bucket didn't exist
    };
    CynaraAdmin::getInstance().CreateBucket(usertype, CynaraAdminPolicy::Operation::Deny);
    CynaraAdmin::getInstance().SetPolicies(policies);
}

void CynaraAdmin::InitBuckets()
{
    CreateBucket(Buckets.at(Bucket::ADMIN), CynaraAdminPolicy::Operation::None);
    CreateBucket(Buckets.at(Bucket::MANIFESTS), CynaraAdminPolicy::Operation::Deny);
    CreateBucket(Buckets.at(Bucket::USER_TYPE_ADMIN), CynaraAdminPolicy::Operation::Deny);
    CreateBucket(Buckets.at(Bucket::USER_TYPE_NORMAL), CynaraAdminPolicy::Operation::Deny);
    CreateBucket(Buckets.at(Bucket::USER_TYPE_GUEST), CynaraAdminPolicy::Operation::Deny);
    CreateBucket(Buckets.at(Bucket::USER_TYPE_SYSTEM), CynaraAdminPolicy::Operation::Deny);
    CreateBucket(Buckets.at(Bucket::MAIN), CynaraAdminPolicy::Operation::Deny);

    linkBuckets(Buckets.at(Bucket::USER_TYPE_ADMIN), Buckets.at(Bucket::ADMIN));
    linkBuckets(Buckets.at(Bucket::USER_TYPE_NORMAL), Buckets.at(Bucket::ADMIN));
    linkBuckets(Buckets.at(Bucket::USER_TYPE_GUEST), Buckets.at(Bucket::ADMIN));
    linkBuckets(Buckets.at(Bucket::USER_TYPE_SYSTEM), Buckets.at(Bucket::ADMIN));
    linkBuckets(Buckets.at(Bucket::MAIN), Buckets.at(Bucket::MANIFESTS));
    linkBuckets(CYNARA_ADMIN_DEFAULT_BUCKET, Buckets.at(Bucket::MAIN));
}

Cynara::Cynara()
{
    checkCynaraError(
        cynara_initialize(&m_Cynara, nullptr),
        "Cannot connect to Cynara policy interface.");
}

Cynara::~Cynara()
{
    cynara_finish(m_Cynara);
}

Cynara &Cynara::getInstance()
{
    static Cynara cynara;
    return cynara;
}

bool Cynara::check(const std::string &label, const std::string &privilege,
        const std::string &user, const std::string &session)
{
    return checkCynaraError(
        cynara_check(m_Cynara,
            label.c_str(), session.c_str(), user.c_str(), privilege.c_str()),
        "Cannot check permission with Cynara.");
}

} // namespace SecurityManager
