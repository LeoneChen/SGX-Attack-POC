#include "Enclave_u.h"
#include "sgx_urts.h"
#include <stdio.h>
#include <thread>
#include <mutex>
#include <condition_variable>
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

#define ENCLAVE_FILENAME "enclave.signed.so"
sgx_enclave_id_t global_eid = 0;

void ocall_print_string(const char *str) {
    printf("%s", str);
}
void thread1_func(sgx_enclave_id_t eid) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    std::unique_lock <std::mutex> lk(m);
    PAUSE_THREAD2_1(lk);
    printf("===Thread1 Running===\n");
    ret = ecall_malloc_obj2_use_obj1(global_eid);
    if (ret == SGX_ERROR_CHECK_POINT) {
        printf("[ecall_malloc_obj2_use_obj1] SGX_ERROR_CHECK_POINT \n");
        goto out1;
    } else if (ret != SGX_SUCCESS) {
        printf("Error: Making an ecall_malloc_obj2_use_obj1()\n");
        goto out1;
    }
    printf("===Thread1 Exit====\n");
    out1:
    PAUSE_THREAD2_2(lk);
}
int main() {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("Error: creating enclave\n");
        return -1;
    }
    std::thread t1(thread1_func, global_eid);

    ret = ecall_malloc_obj1(global_eid);
    if (ret != SGX_SUCCESS) {
        printf("Error: Making an ecall_malloc_obj1()\n");
        goto out;
    }



    ret = ecall_free_obj1(global_eid);
    if (ret == SGX_ERROR_CHECK_POINT) {
        printf("[ecall_free_obj1] SGX_ERROR_CHECK_POINT \n");
        goto out;
    } else if (ret != SGX_SUCCESS) {
        printf("Error: Making an ecall_free_obj1()\n");
        goto out;
    }
    PAUSE_THREAD1;
    t1.join();

//    ecall_show_log(global_eid);

out:
    ret = sgx_destroy_enclave(global_eid);
    if (ret != SGX_SUCCESS) {
        printf("Error: destroying enclave\n");
        return -1;
    }

    return 0;
}
