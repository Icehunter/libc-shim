#include "iorewrite.h"

std::vector<std::pair<std::string, std::string>> shim::rewrite_filesystem_access;

void (*shim::path_observer)(const char *path) = nullptr;