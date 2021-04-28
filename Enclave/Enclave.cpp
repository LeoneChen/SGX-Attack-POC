#include "Enclave_t.h" // Headers for trusted part (autogenerated by edger8r)
#include "sqlite3.h"
#include <string>

sqlite3* db; // Database connection object

// SQLite callback function for printing results
static int callback(void *NotUsed, int argc, char **argv, char **azColName){
    int i;
    for(i = 0; i < argc; i++){
        std::string azColName_str = azColName[i];
        std::string argv_str = (argv[i] ? argv[i] : "NULL");
        ocall_print_string((azColName_str + " = " + argv_str + "\n").c_str());
    }
    ocall_print_string("\n");
    return 0;
}

void ecall_opendb(const char *dbname){
    int rc; // For return status of SQLite
    rc = sqlite3_open(dbname, &db); // Opening database
    if (rc) {
        ocall_println_string("SQLite error - can't open database connection: ");
        ocall_println_string(sqlite3_errmsg(db));
        return;
    }
    ocall_print_string("Enclave: Created database connection to ");
    ocall_println_string(dbname);
}

void ecall_execute_sql(const char *sql){
    int rc;
    char *zErrMsg = 0;
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
//    if (rc) {
//        ocall_print_string("SQLite error: ");
//        ocall_println_string(sqlite3_errmsg(db));
//        return;
//    }
}

void ecall_closedb(){
    sqlite3_close(db);
//    db = NULL;
    ocall_println_string("Enclave: Closed database connection");
}
