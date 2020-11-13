#include <iostream>
#include <string>
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

void thread1_func(sgx_enclave_id_t eid, const char *dbname) {
    std::unique_lock <std::mutex> lk(m);
    cv.wait(lk, [] { return ready; });

    sgx_status_t ret = SGX_ERROR_UNEXPECTED; // status flag for enclave calls

    // Open SQLite database
    cout << std::this_thread::get_id() << "ecall_opendb" << endl;
    ret = ecall_opendb(eid, dbname);
    if (ret != SGX_SUCCESS) {
        cerr << "Error: Making an ecall_open()" << endl;
        return;
    }

    cout << "Enter SQL statement to execute or 'quit' to exit: " << endl;
    string input;
    cout << "> ";
    while (getline(cin, input)) {
        if (input == "quit") {
            break;
        }
        const char *sql = input.c_str();
        cout << std::this_thread::get_id() << "ecall_execute_sql" << endl;
        ret = ecall_execute_sql(eid, sql);
        if (ret != SGX_SUCCESS) {
            cerr << "Error: Making an ecall_execute_sql()" << endl;
            return;
        }
        cout << "> ";
    }

    // Closing SQLite database inside enclave
    cout << std::this_thread::get_id() << "ecall_closedb" << endl;
    ret = ecall_closedb(eid);
    if (ret != SGX_SUCCESS) {
        cerr << "Error: Making an ecall_closedb()" << endl;
        return;
    }

    processed = true;
    lk.unlock();
    cv.notify_one();
}

void thread2_func(sgx_enclave_id_t eid, const char *dbname) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED; // status flag for enclave calls

    // Open SQLite database
    cout << std::this_thread::get_id() << "ecall_opendb" << endl;
    ret = ecall_opendb(eid, dbname);
    if (ret != SGX_SUCCESS) {
        cerr << "Error: Making an ecall_open()" << endl;
        return;
    }

    {
        std::lock_guard <std::mutex> lk(m);
        ready = true;
    }

    cv.notify_one();

    // waiting thread1_func end
    {
        std::unique_lock <std::mutex> lk(m);
        cv.wait(lk, [] { return processed; });
    }


    cout << "Enter SQL statement to execute or 'quit' to exit: " << endl;
    string input;
    cout << "> ";
    while (getline(cin, input)) {
        if (input == "quit") {
            break;
        }
        const char *sql = input.c_str();
        cout << std::this_thread::get_id() << "ecall_execute_sql" << endl;
        ret = ecall_execute_sql(eid, sql);
        if (ret != SGX_SUCCESS) {
            cerr << "Error: Making an ecall_execute_sql()" << endl;
            return;
        }
        cout << "> ";
    }

    // Closing SQLite database inside enclave
    cout << std::this_thread::get_id() << "ecall_closedb" << endl;
    ret = ecall_closedb(eid);
    if (ret != SGX_SUCCESS) {
        cerr << "Error: Making an ecall_closedb()" << endl;
        return;
    }
}

// Application entry
int main(int argc, char *argv[]) {
    if (argc != 2) {
        cout << "Usage: " << argv[0] << " <database>" << endl;
        return -1;
    }
    const char *dbname = argv[1];

    sgx_enclave_id_t eid = 0;
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED; // status flag for enclave calls
    int updated = 0;

    // Initialize the enclave
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        cerr << "Error: creating enclave" << endl;
        return -1;
    }
    cout << "Info: SQLite SGX enclave successfully created." << endl;

    std::thread t1(thread1_func, eid, dbname);
    std::thread t2(thread2_func, eid, dbname);

    t1.join();
    t2.join();

    // Destroy the enclave
    sgx_destroy_enclave(eid);
    if (ret != SGX_SUCCESS) {
        cerr << "Error: destroying enclave" << endl;
        return -1;
    }

    cout << "Info: SQLite SGX enclave successfully returned." << endl;
    return 0;
}
