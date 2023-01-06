#pragma once

#include <string>
#include <vector>

#include "authtableentry.h"
#include "map.h"
#include "storage.h"

/// Do all of the p1/p2/p3 work for add_user
Storage::result_t add_user_helper(const std::string &user,
                                  const std::string &pass,
                                  Map<std::string, AuthTableEntry> *auth_table,
                                  FILE *&storage_file);

/// Do all of the p1/p2/p3 work for set_user_data
Storage::result_t
set_user_data_helper(const std::string &user, const std::string &pass,
                     const std::vector<uint8_t> &content,
                     Map<std::string, AuthTableEntry> *auth_table,
                     FILE *&storage_file);

/// Do all of the p1/p2/p3 work for auth
Storage::result_t auth_helper(const std::string &user, const std::string &pass,
                              Map<std::string, AuthTableEntry> *auth_table);

/// Do all of the p1/p2/p3 work for get_user_data
Storage::result_t
get_user_data_helper(const std::string &user, const std::string &pass,
                     const std::string &who,
                     Map<std::string, AuthTableEntry> *auth_table);

/// Do all of the p1/p2/p3 work for get_all_users
Storage::result_t
get_all_users_helper(const std::string &user, const std::string &pass,
                     Map<std::string, AuthTableEntry> *auth_table);

/// Do all of the p1/p2/p3 work for save_file
Storage::result_t
save_file_helper(Map<std::string, AuthTableEntry> *auth_table,
                 Map<std::string, std::vector<uint8_t>> *kv_store,
                 const std::string &filename, FILE *&storage_file);

/// Do all of the p1/p2/p3 work for save_file
Storage::result_t
load_file_helper(Map<std::string, AuthTableEntry> *auth_table,
                 Map<std::string, std::vector<uint8_t>> *kv_store,
                 const std::string &filename, FILE *&storage_file);
