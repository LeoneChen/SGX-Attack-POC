#include "Enclave_t.h"
#include <string.h>
#include <stdio.h>
#include "../eType.h"

#include "check_point.hpp"

struct eObj *obj, *obj2;

int printf(const char *fmt, ...) {
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int) strnlen(buf, BUFSIZ - 1) + 1;
}

void ecall_malloc_obj1() {
    obj = (struct eObj *) malloc(sizeof(struct eObj));
    obj->flag = 1;
    memcpy(obj->ch, "hello", 6);
    printf("Malloc obj1(%p)=%s\n", obj, obj->ch);
}

void ecall_malloc_obj2_use_obj1() {
    obj2 = (struct eObj *) malloc(sizeof(struct eObj));
    obj2->flag = 1;
    memcpy(obj2->ch, "uaf", 5);
    printf("Malloc obj2(%p)=%s\n", obj2, obj2->ch);

    printf("Use obj1(%p)=%s\n", obj, obj->ch);
}

void ecall_free_obj1() {
    if (obj == 0)
        return;
    free(obj);
    printf("Free obj%d\n", 1);
}

bool filter(cp_info_t info) {
    return (info.interface_type == INTERFACE_ECALL);
}

void ecall_show_log() {
    g_check_point->show_log("Call Permutation", filter);
}
