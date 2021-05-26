#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp >
#include <boost/filesystem.hpp>
#include <map>
#include <string>
#include <iostream>
using namespace boost::filesystem;
using namespace std;
namespace settings
{
    map<string, string>  getSettings(const string app)
    {
        map<string, string> settings;
        using boost::property_tree::ptree;
        ptree pt;
        boost::property_tree::read_xml(app , pt);
        ptree root = pt.get_child("root");
        for (const std::pair<std::string, ptree>& p : root)
        {
            settings[p.first] = p.second.get_value<std::string>();
        }
        return settings;
    }
}


