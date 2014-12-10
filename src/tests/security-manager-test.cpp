/* vim: set ts=4 et sw=4 tw=78 : */

#include <iostream>
#include <fstream>
#include <cstdlib>
#include <cassert>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <vector>
#include <string>
#include "cynara.h"

using namespace std;

#define logd(...) cout << __VA_ARGS__ << endl
#define CYNARA_PATH_DB "/var/cynara/db"

void buckets_mngmnt_test()
{
    using namespace SecurityManager;

    string b = "wiadro1";
    try {
        CynaraAdmin::getInstance().CreateBucket(b,
                CynaraAdminPolicy::Operation::Delete);
        logd("CreateBucket function FAIL.");
    } catch(const CynaraException::Base &e) {
        logd("CreateBucket function OK.");
    }
    try {
        CynaraAdmin::getInstance().CreateBucket(b,
                CynaraAdminPolicy::Operation::Bucket);
        logd("CreateBucket function FAIL.");
    } catch(const CynaraException::Base &e) {
        logd("CreateBucket function OK.");
    }
    try {
        CynaraAdmin::getInstance().CreateBucket(b,
                CynaraAdminPolicy::Operation::Deny);
        logd("CreateBucket function OK.");
        string bf = CYNARA_PATH_DB "/_" + b;
        if (ifstream(bf).good()) {
            logd("CreateBucket verification OK.");
        } else {
            logd("CreateBucket verification FAIL.");
        }
    } catch(const CynaraException::Base &e) {
        logd("CreateBucket function FAIL.");
    }
    try {
        CynaraAdmin::getInstance().RemoveBucket(b);
        logd("RemoveBucket function OK.");
    } catch(const CynaraException::Base &e) {
        logd("RemoveBucket function FAIL.");
    }
    try {
        CynaraAdmin::getInstance().RemoveBucket(b + 'a');
        logd("RemoveBucket function FAIL.");
    } catch(const CynaraException::Base &e) {
        logd("RemoveBucket function OK.");
    }
}

int main(void)
{
    buckets_mngmnt_test();
    return EXIT_SUCCESS;
}

