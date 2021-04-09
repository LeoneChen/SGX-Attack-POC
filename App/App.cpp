#include "Enclave_u.h"
#include "sgx_urts.h"
#include <stdio.h>

#define ENCLAVE_FILENAME "enclave.signed.so"
sgx_enclave_id_t global_eid = 0;

void ocall_print_string(const char *str) {
    printf("%s", str);
}

int main() {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("Error: creating enclave\n");
        return -1;
    }

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

    ret = ecall_malloc_obj2_use_obj1(global_eid);
    if (ret == SGX_ERROR_CHECK_POINT) {
        printf("[ecall_malloc_obj2_use_obj1] SGX_ERROR_CHECK_POINT \n");
        goto out;
    } else if (ret != SGX_SUCCESS) {
        printf("Error: Making an ecall_malloc_obj2_use_obj1()\n");
        goto out;
    }

//    ecall_show_log(global_eid);

out:
    ret = sgx_destroy_enclave(global_eid);
    if (ret != SGX_SUCCESS) {
        printf("Error: destroying enclave\n");
        return -1;
    }

    return 0;
}
