/* SQLITE_TRANSIENT is -1 cast to a function pointer in C; Zig rejects that
 * address as misaligned on some targets, so the value is produced in C. */
#include "sqlite3.h"

sqlite3_destructor_type termgate_sqlite_transient(void)
{
    return SQLITE_TRANSIENT;
}
