#include"mysql.h"
#include"trace.h"



void insert_mysql(MYSQL* mysql,char *data)
{
	Trace("begin write to database\n");
	mysql_query(mysql,data);
}
