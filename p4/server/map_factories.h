#pragma once

#include <string>
#include <vector>

#include "authtableentry.h"
#include "map.h"
#include "quotas.h"

/// Create an instance of HashTable that can be used as an authentication table
///
/// @param _buckets The number of buckets in the table
Map<std::string, AuthTableEntry> *authtable_factory(size_t _buckets);

/// Create an instance of HashTable that can be used as a key/value store
///
/// @param _buckets The number of buckets in the table
Map<std::string, std::vector<uint8_t>> *kvstore_factory(size_t _buckets);

/// Create an instance of HashTable that can be used to hold quotas
///
/// @param _buckets The number of buckets in the table
Map<std::string, Quotas *> *quotatable_factory(size_t _buckets);

/// Create an instance of HashTable that can be used for integer set benchmarks
///
/// @param _buckets The number of buckets in the table
Map<int, int> *intset_factory(size_t _buckets);