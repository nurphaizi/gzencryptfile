#pragma once
#include <boost/filesystem.hpp>
namespace sqlite
{
    using namespace  boost::filesystem;

    class SqliteConnection
    {
    private:
        sqlite3* DB;
        char* zErrMsg = 0;
        int rc;
        std::string sql;
        std::string databaseFile;
    public:
        SqliteConnection() :zErrMsg(0), rc(0) {};
        SqliteConnection(std::string db_filename);
        bool fileAllreadyUploaded(const path source_file, const char* hash, const int hash_len, const size_t SIZE, const time_t CREATION_TIME, const time_t LAST_WRITE_TIME);
        bool insertRow(const path source_file, const char* hash, const int hash_len, const size_t SIZE, const time_t CREATION_TIME, const time_t LAST_WRITE_TIME);
        void close_Connection();
        void dump();
        ~SqliteConnection() { close_Connection(); };
    };
}
