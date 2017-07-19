
#include "sqlite3.h"

extern int sql_get_table(sqlite3 *db, const char *sql, char ***pazResult, int *pnRow, int *pnColumn);
extern void AiProtectionMonitor_result(int *tmp, char **result, int rows, int cols, int shift);
extern time_t Date_Of_Timestamp(time_t now);
