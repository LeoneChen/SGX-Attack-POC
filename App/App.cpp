#include <iostream>
#include <string>
#include <unistd.h>
#include <sys/syscall.h>
#include "sgx_urts.h"
#include "Enclave_u.h" // Headers for untrusted part (autogenerated by edger8r)

#include <thread>
#include <mutex>
#include <condition_variable>

using namespace std;

# define MAX_PATH FILENAME_MAX
# define ENCLAVE_FILENAME "enclave.signed.so"

std::mutex m;
std::condition_variable cv;
bool ready = false;
bool processed = false;

#define PAUSE_THREAD1                               \
    do {                                            \
        {                                           \
            std::lock_guard <std::mutex> lk(m);     \
            ready = true;                           \
        }                                           \
        cv.notify_one();                            \
        {                                           \
            std::unique_lock <std::mutex> lk(m);    \
            cv.wait(lk, [] { return processed; });  \
        }                                           \
    } while(0)

#define PAUSE_THREAD2_1(lk)                         \
    do {                                            \
        cv.wait(lk, [] { return ready; });          \
    } while(0)

#define PAUSE_THREAD2_2(lk)                         \
    do {                                            \
        processed = true;                           \
        lk.unlock();                                \
        cv.notify_one();                            \
    } while(0)

// ocalls for printing string (C++ ocalls)
void ocall_print_error(const char *str) {
    cerr << str << endl;
}

void ocall_print_string(const char *str) {
    cout << str;
}

void ocall_println_string(const char *str) {
    cout << str << endl;
}

void thread_func(sgx_enclave_id_t eid, const char *dbname) {
    std::unique_lock <std::mutex> lk(m);
    PAUSE_THREAD2_1(lk);

    sgx_status_t ret = SGX_ERROR_UNEXPECTED; // status flag for enclave calls

    cout << "Enter SQL statement to execute or 'quit' to exit: " << endl;
    string input;
    cout << "> ";
    while (getline(cin, input)) {
        if (input == "quit") break;
        const char *sql = input.c_str();
        cout << "[TID: " << syscall(SYS_gettid) << "] ecall_execute_sql" << endl;
        ret = ecall_execute_sql(eid, sql);
        if (ret != SGX_SUCCESS) {
            cerr << "[ecall_execute_sql] Error: 0x" << hex << ret << endl;
            goto out;
        }
        cout << "> ";
    }
    out:
    PAUSE_THREAD2_2(lk);
}

// Application entry
int main(int argc, char *argv[]) {
    const char *dbname = (argc != 2) ? "a.db" : argv[1];

    sgx_enclave_id_t eid = 0;
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED; // status flag for enclave calls
    int updated = 0;

    // Initialize the enclave
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        cerr << "[sgx_create_enclave] Error: 0x" << hex << ret << endl;
        return -1;
    }
    cout << "Info: SQLite SGX enclave successfully created." << endl;

    std::thread trd(thread_func, eid, dbname);

    // Open SQLite database
    cout << "[TID: " << syscall(SYS_gettid) << "] ecall_opendb" << endl;
    ret = ecall_opendb(eid, dbname);
    if (ret != SGX_SUCCESS) {
        cerr << "[ecall_open] Error: 0x" << hex << ret << endl;
        goto out;
    }
    PAUSE_THREAD1;
    // Closing SQLite database inside enclave
    cout << "[TID: " << syscall(SYS_gettid) << "] ecall_closedb" << endl;
    ret = ecall_closedb(eid);
    if (ret != SGX_SUCCESS) {
        cerr << "[ecall_closedb] Error: 0x" << hex << ret << endl;
        goto out;
    }


    trd.join();

//    ecall_show_log(eid);
    out:
    // Destroy the enclave
    sgx_destroy_enclave(eid);
    if (ret != SGX_SUCCESS) {
        cerr << "[sgx_destroy_enclave]Error: 0x" << hex << ret << endl;
        return -1;
    }

    cout << "Info: SQLite SGX enclave successfully returned." << endl;
    return 0;
}
