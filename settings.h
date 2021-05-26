#pragma once
#include <map>
#include <string>
namespace settings
{
    std::map<std::string, std::string>  getSettings(const std::string app);
}