/* vim: set ts=4 et sw=4 tw=78 : */

#include <iostream>
#include <cstdlib>
#include <cassert>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <file-lock.h>

using namespace std;

#define TEST_LOCK_FILE  "/tmp/test_lock_file.lock"
#define logd(...) cout << __VA_ARGS__ << endl

void lock_child()
{
    SecurityManager::FileLocker nbfl(TEST_LOCK_FILE);
    assert(nbfl.Locked() == false);
    logd("Non-blocking lock in child: " << nbfl.Locked());
}

int main(void)
{
    SecurityManager::FileLocker *fl = new SecurityManager::FileLocker(TEST_LOCK_FILE);
    assert(fl->Locked() == true);
    logd("Non-blocking lock: " << fl->Locked());
    delete fl;

    fl = new SecurityManager::FileLocker(TEST_LOCK_FILE, true);
    assert(fl->Locked() == true);
    logd("Blocking lock: " << fl->Locked());

    pid_t ch = fork();
    switch (ch) {
    case 0:
        lock_child();
        break;
    case -1:
        return EXIT_FAILURE;
        break;
    default:
        int res = -1;
        wait(&res);
        delete fl;
        break;
    }

    return EXIT_SUCCESS;
}

