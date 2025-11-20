#ifndef SSD_ERASE_HPP
#define SSD_ERASE_HPP

#include <string>
#include "secure_delete.hpp"

bool is_root_user();

bool perform_hardware_erase(const std::string &device, DeleteOptions &opts);

#endif
