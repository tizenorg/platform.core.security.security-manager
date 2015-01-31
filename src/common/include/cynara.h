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

#include <cynara-client.h>
#include <cynara-admin.h>
#include <dpl/exception.h>
#include <string>
#include <vector>
#include <map>

#include "security-manager.h"

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
    };

    CynaraAdminPolicy(const std::string &client, const std::string &user,
        const std::string &privilege, int operation,
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

    typedef std::map<Bucket, const std::string > BucketsMap;
    static BucketsMap Buckets;

    typedef  std::map<int, std::string> TypeToDescriptionsMap;
    typedef  std::map<std::string, int> DescriptionsToTypeMap;

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
    void UpdateAppPolicy(const std::string &label, const std::string &user,
        const std::vector<std::string> &oldPrivileges,
        const std::vector<std::string> &newPrivileges);

    /**
     * Depending on user type, create link between MAIN bucket and appropriate
     * USER_TYPE_* bucket for newly added user uid to apply permissions for that
     * user type.
     * @throws CynaraException::InvalidParam.
     *
     * @param uid new user uid
     * @param userType type as enumerated in security-manager.h
     */
    void UserInit(uid_t uid, security_manager_user_type userType);

    /**
     * Removes all entries for a user from cynara database
     *
     * @param uid removed user uid
     */
    void UserRemove(uid_t uid);

    /**
     * List Cynara policies that match selected criteria in given bucket.
     *
     * @param bucketName name of the bucket to search policies in
     * @param appId string with id of app to match in search
     * @param user user string to match in search
     * @param privilege privilege string to match in search
     * @param policies empty vector for results of policies filtering.
     *
     */
    void ListPolicies(const std::string &bucketName,
        const std::string &appId,
        const std::string &user,
        const std::string &privilege,
        std::vector<CynaraAdminPolicy> &policies);

    /**
     * Wrapper for Cynara API function cynara_admin_list_policies_descriptions.
     * It collects all policies descriptions, sorts them and extracts names
     * of policies and returns as std strings.
     *
     * @param policiesDescriptions empty vector for policies descriptions.
     */
    void ListPoliciesDescriptions(std::vector<std::string> &policiesDescriptions);

    /**
     * Function translates internal Cynara policy type integer to string
     * description. Descriptions are retrieved from Cynara using
     * ListPoliciesDescriptions() function. Caller can force refetching of
     * descriptions list from Cynara on each call.
     *
     * @throws std::out_of_range
     *
     * @param policyType Cynara policy result type.
     */
    std::string convertToPolicyDescription(const int policyType, bool forceRefresh = false);

    /**
     * Function translates Cynara policy result string
     * description to internal Cynara policy type integer.
     * Descriptions are retrieved from Cynara using
     * ListPoliciesDescriptions() function. Caller can force refetching of
     * descriptions list from Cynara on each call.
     *
     * @throws std::out_of_range
     *
     * @param policy Cynara policy result string description.
     */
    int convertToPolicyType(const std::string &policy, bool forceRefresh = false);

private:
    static TypeToDescriptionsMap TypeToDescriptionsMapping;
    static DescriptionsToTypeMap DescriptionsToTypeMapping;

    CynaraAdmin();

    /**
     * Empty bucket using filter - matching rules will be removed
     *
     * @param bucketName name of the bucket to be emptied
     * @param recursive flag to remove privileges recursively
     * @param client client name
     * @param user user name
     * @param privilege privilege name
     */
    void EmptyBucket(const std::string &bucketName, bool recursive,
        const std::string &client, const std::string &user, const std::string &privilege);

    /**
     * Get Cynara policies result descriptions and cache them in std::map
     *
     * @param force true if you want to reinitialize mappings
     */
    void FetchCynaraPolicyDescriptions(bool force = false);

    struct cynara_admin *m_CynaraAdmin;
    bool m_policyDescriptionsInitialized;
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
