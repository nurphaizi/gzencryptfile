#define _CRT_SECURE_NO_WARNINGS
#include <sqlite3.h>
#include <cstdio>
#include <iomanip>
#include <memory>
#include <string>
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <ctime>
#include <boost/filesystem.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include "dbSqlite3.h"


namespace sqlite

{
    using namespace boost::filesystem;
    using namespace boost::posix_time;
    static int CREATE_TABLE(void* NotUsed, int argc, char** argv, char** azColName) {
        int i;
        fprintf(stderr, "CREATE_TABLE");
        for (i = 0; i < argc; i++) {
            printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
        }
        printf("\n");
        return 0;
    }

    static int ROW_FOUND(void* data, int argc, char** argv, char** azColName) {
        (*(static_cast<int*>(data)))++;
        return 0;
    }

    static int INSERT_ROW(void* notUsed, int argc, char** argv, char** azColName) {
        int i;
        for (i = 0; i < argc; i++) {
            printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
        }
        printf("\n");
        return 0;

    }
    static int DUMP(void* Data, int argc, char** argv, char** azColName) {
        int i;
        for (i = 0; i < argc; i++) {
            std::string  sColName{ azColName[i] };
            if (sColName == "CREATION_TIME" || sColName == "LAST_WRITE_TIME")
            {   
                time_t t = atoll(argv[i]);
                tm* time = gmtime(&t);
                char buf[70];
                strftime(buf, sizeof(buf), "%x %X", time);
                printf("local:     %s\n", buf);

            }
            else
            printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
        }
        printf("\n");
        return 0;
    }

    SqliteConnection::SqliteConnection(std::string db_filename) :zErrMsg(0), rc(0)
        {
            bool newDb = false;
            databaseFile = db_filename;
            path pathToDBFile(databaseFile);
            if (!exists(pathToDBFile))
            {
                newDb = true;
            }
            rc = sqlite3_open(databaseFile.c_str(), &DB);
            if (rc)
            {
                char msg[1024];
                sprintf_s(msg, "Can't open database: %s\n", sqlite3_errmsg(DB));
                throw std::runtime_error(msg);
            }
            if (newDb)
            {

                sql = "CREATE TABLE CATALOG(" \
                    "ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL," \
                    "NAME TEXT NOT NULL,SIZE REAL," \
                    "CREATION_TIME DATETIME," \
                    "LAST_WRITE_TIME DATETIME )";

                const char* data = "CATALOG created";

                std::shared_ptr<char*> psql = std::make_shared<char*>(new char[sql.length() + 1]);
                strcpy(*psql, sql.c_str());
                printf("CREATE TABLE CATALOG %s \n", *psql);

                rc = sqlite3_exec(DB, *psql, CREATE_TABLE, (void*)data, &zErrMsg);
                if (rc != SQLITE_OK) {
                    printf("SQL error : % s\n", sqlite3_errmsg(DB));
                    char msg[1024];
                    sprintf_s(msg, "SQL error:  %s\n", sqlite3_errmsg(DB));
                    sqlite3_free(zErrMsg);
                    throw std::runtime_error(msg);
                }
            }
        }
    bool SqliteConnection:: fileAllreadyUploaded(const path source_file)
        {
            int result = 0;
            std::stringstream ssql;
            ssql << "SELECT * FROM CATALOG WHERE NAME LIKE \'"<< source_file.filename().string()<<"\'";
            ssql << " AND SIZE = " << file_size(source_file);
            ssql << " AND CREATION_TIME = " << creation_time(source_file);
            sql = ssql.str();
            std::shared_ptr<char*> psql = std::make_shared<char*>(new char[sql.length()+1]);
            strcpy(*psql, sql.c_str());


            rc = sqlite3_exec(DB, *psql, ROW_FOUND, &result, &zErrMsg);

            if (rc != SQLITE_OK) {
                char msg[1024];
                sprintf_s(msg, "SQL ROW SELECT error:  %s\n", sqlite3_errmsg(DB));
                sqlite3_free(zErrMsg);
                throw std::runtime_error(msg);
            }

            return result;
        }

        bool SqliteConnection::insertRow(const path source_file)
        {
            std::stringstream ssql;
            ssql << "INSERT INTO CATALOG (NAME,SIZE,CREATION_TIME,LAST_WRITE_TIME) ";
            ssql << "VALUES (\'" << source_file.filename().string() << "\', ";
            ssql << file_size(source_file) << ",";
            ssql << creation_time(source_file) << ",";
            ssql << last_write_time(source_file) << ")";
            sql = ssql.str();
            std::shared_ptr<char*> psql = std::make_shared<char*>(new char[sql.length() + 1]);
            strcpy(*psql, sql.c_str());
            rc = sqlite3_exec(DB, *psql, INSERT_ROW, 0, &zErrMsg);
            if (rc != SQLITE_OK) {
                char msg[1024];
                sprintf_s(msg, "SQL INSERT ROW error:  %s\n", sqlite3_errmsg(DB));
                sqlite3_free(zErrMsg);
                throw std::runtime_error(msg);
            }
            return true;
        }
        void SqliteConnection::dump()
        {
            const char* data = "Callback function called";
            sql = "SELECT * FROM CATALOG ";
            std::shared_ptr<char*> psql = std::make_shared<char*>(new char[sql.length() + 1]);
            strcpy(*psql, sql.c_str());
            rc = sqlite3_exec(DB, *psql, DUMP, (void*)data, &zErrMsg);
            ptime pt;
            
            if (rc != SQLITE_OK) {
                char msg[1024];
                sprintf_s(msg, "SQL ROW SELECT error:  %s\n", sqlite3_errmsg(DB));
                sqlite3_free(zErrMsg);
                throw std::runtime_error(msg);
            }
        }

        void SqliteConnection::close_Connection()
        {
            sqlite3_close(DB);
        }



    };

