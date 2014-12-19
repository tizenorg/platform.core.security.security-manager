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
 * @file        cynara.h
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @brief       Wrapper class for Cynara interface
 */

#ifndef _SECURITY_MANAGER_CYNARA_
#define _SECURITY_MANAGER_CYNARA_

#include "usertype-profile.h"

#include <cynara-client.h>
#include <cynara-admin.h>
#include <dpl/exception.h>
#include <string>
#include <vector>
#include <map>

namespace SecurityManager {

enum class Bucket
{
    PRIVACY_MANAGER,
    MAIN,
    USER_TYPE_ADMIN,
    USER_TYPE_NORMAL,
    USER_TYPE_GUEST,
    USER_TYPE_SYSTEM,
    ADMIN,
    MANIFESTS
};

class CynaraException
{
public:
    DECLARE_EXCEPTION_TYPE(SecurityManager::Exception, Base)
    DECLARE_EXCEPTION_TYPE(Base, OutOfMemory)
    DECLARE_EXCEPTION_TYPE(Base, InvalidParam)
    DECLARE_EXCEPTION_TYPE(Base, ServiceNotAvailable)
    DECLARE_EXCEPTION_TYPE(Base, UnknownError)
    DECLARE_EXCEPTION_TYPE(Base, BucketNotFound)
};

struct CynaraAdminPolicy : cynara_admin_policy
{
    enum class Operation {
        Deny = CYNARA_ADMIN_DENY,
        Allow = CYNARA_ADMIN_ALLOW,
        Delete = CYNARA_ADMIN_DELETE,
        Bucket = CYNARA_ADMIN_BUCKET,
        None = CYNARA_ADMIN_NONE,
    };

    CynaraAdminPolicy(const std::string &client, const std::string &user,
        const std::string &privilege, Operation operation,
        const std::string &bucket = std::string(CYNARA_ADMIN_DEFAULT_BUCKET));

    CynaraAdminPolicy(const std::string &client, const std::string &user,
        const std::string &privilege, const std::string &goToBucket,
        const std::string &bucket = std::string(CYNARA_ADMIN_DEFAULT_BUCKET));

    /* Don't provide copy constructor, it would cause pointer trouble. */
    CynaraAdminPolicy(const CynaraAdminPolicy &that) = delete;

    /* Move constructor is the way to go. */
    CynaraAdminPolicy(CynaraAdminPolicy &&that);

    ~CynaraAdminPolicy();
};

class CynaraAdmin
{
public:

    typedef std::map<Bucket, const char * const > BucketsMap;
    static BucketsMap Buckets;

    virtual ~CynaraAdmin();

    static CynaraAdmin &getInstance();

    /**
     * Update Cynara policies.
     * Caller must have permission to access Cynara administrative socket.
     *
     * @param policies vector of CynaraAdminPolicy objects to send to Cynara
     */
    void SetPolicies(const std::vector<CynaraAdminPolicy> &policies);

    /**
     * Update Cynara policies for the package and the user, using two vectors
     * of privileges: privileges set before (and already enabled in Cynara)
     * and new privileges, to be set in Cynara.
     * Difference will be calculated, removing old unneeded privileges and
     * adding new, previously not enabled privileges.
     * Caller must have permission to access Cynara administrative socket.
     *
     * @param label application Smack label
     * @param user user identifier
     * @param oldPrivileges previously enabled privileges for the package.
     *        Must be sorted and without duplicates.
     * @param newPrivileges currently enabled privileges for the package.
     *        Must be sorted and without duplicates.
     *
     * TODO: drop oldPrivileges argument and get them directly from Cynara.
     * Appropriate Cynara interface is needed first.
     */
    static void UpdatePackagePolicy(const std::string &label, const std::string &user,
        const std::vector<std::string> &oldPrivileges,
        const std::vector<std::string> &newPrivileges);

    /**
     * Define policy for specific user type
     *
     * @param usertype name of the user type for which the policy is defined
     * @param privileges list of user type privileges
     */
    static void DefineUserTypePolicy(const std::string &usertype,
        const std::vector<UserTypePrivilege> &privileges);

    /**
     * Create basic set of buckets according to policies schema -
     * MAIN, USERTYPE_ADMIN, USERTYPE_NORMAL, USERTYPE_GUEST, USERTYPE_SYSTEM,
     * ADMIN, MANIFESTS. PRIVACY_MANAGER is the first bucket in the flow,
     * and it's not created - instead default bucket ("") is used.
     *
     * @param bucket_type type of bucket to create
     */
    void InitBuckets();

private:
    CynaraAdmin();

    /**
     * Create new bucket in Cynara
     *
     * @param bucketName name of the new bucket to be created
     * @param defaultPolicy default policy for bucket
     */
    void CreateBucket(const std::string &bucketName, CynaraAdminPolicy::Operation defaultPolicy);

    /**
     * Remove bucket from Cynara
     *
     * @param bucketName name of the bucket to be removed
     */
    void RemoveBucket(const std::string &bucketName);

    /**
     * Empty bucket using filter - matching rules will be removed
     *
     * @param bucketName name of the bucket to be removed
     * @param recursive flag to remove privileges recursively
     * @param client client name
     * @param user user name
     * @param privilege privilege name
     */
    void EmptyBucket(const std::string &bucketName, bool recursive,
        const std::string &client, const std::string &user, const std::string &privilege);

    struct cynara_admin *m_CynaraAdmin;
};

class Cynara
{
public:
    virtual ~Cynara();

    static Cynara &getInstance();

    /**
     * Ask Cynara for permission.
     *
     * @param label application Smack label
     * @param privilege privilege identifier
     * @param user user identifier (uid)
     * @param session session identifier
     * @return true if access is permitted, false if denied
     */
    bool check(const std::string &label, const std::string &privilege,
        const std::string &user, const std::string &session);

private:
    Cynara();
    struct cynara *m_Cynara;
};

} // namespace SecurityManager

#endif // _SECURITY_MANAGER_CYNARA_
