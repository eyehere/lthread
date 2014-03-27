/* 
 * This is a test code to figure out that MySQL client is working,
 * and requests are running correctly with lthread.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <mysql.h>

#include "lthread.h"

void run_query(void *arg);

int main(int argc, char **argv) {
	lthread_t *lt;

	if (mysql_library_init(0, NULL, NULL)) {
		fprintf(stderr, "failed to initialize mysql library\n");
		return 1;
	}

	/* many lthreads could be spawned, but mysql is very limited 
	   on connections; 100-150 is the default */
	printf("running lthread...\n");
	if (lthread_create(&lt, run_query, NULL) == -1) {
		fprintf(stderr, "failed to create lthread\n");
		exit(1);
	}
	lthread_run();
	printf("lthread scheduler finished\n");

	mysql_library_end();
	return 0;
}

void run_query(void *arg) {
	MYSQL *conn;
	MYSQL_RES *res;
	MYSQL_ROW row;

	lthread_detach();
	lthread_print_timestamp(__FUNCTION__);
	putchar('\n');

	char *server = "localhost";
	char *user = "lthreaduser";
	char *password = "lthreadpassword";
	char *database = "lthread";
	char sql_req[256] = "SELECT id,entry FROM testing";

	conn = mysql_init(NULL);

	/* Connect to database */
	if (!mysql_real_connect(conn, server,
							user, password, database, 0, NULL, 0)) {
		fprintf(stderr, "%s\n", mysql_error(conn));
		exit(1);
	}

	printf("[*] connected. sql request will be '%s'\n", sql_req);
	if (mysql_query(conn, sql_req)) {
		fprintf(stderr, "%s\n\n", mysql_error(conn));
		exit(1);
	}

	res = mysql_use_result(conn);

	while ((row = mysql_fetch_row(res)) != NULL)
		printf("%s '%s'\n", row[0], row[1]);

	printf("[*] done reading from db\n");
	mysql_free_result(res);
	mysql_close(conn);

	printf("[*] resources freed, exiting\n\n");
	lthread_print_timestamp(__FUNCTION__);
	return;
}
