#include <cassert>
#include <functional>
#include <iostream>
#include <list>
#include <mutex>
#include <string>
#include <vector>
#include "map.h"

using namespace std;
/// ConcurrentHashMap is a concurrent implementation of the Map interface (a
/// Key/Value store).  It is implemented as a vector of buckets, with one lock
/// per bucket.  Since the number of buckets is fixed, performance can suffer if
/// the thread count is high relative to the number of buckets.  Furthermore,
/// the asymptotic guarantees of this data structure are dependent on the
/// quality of the bucket implementation.  If a vector is used within the bucket
/// to store key/value pairs, then the guarantees will be poor if the key range
/// is large relative to the number of buckets.  If an unordered_map is used,
/// then the asymptotic guarantees should be strong.
///
/// The ConcurrentHashMap is templated on the Key and Value types.
///
/// This map uses std::hash to map keys to positions in the vector.  A
/// production map should use something better.
///
/// This map provides strong consistency guarantees: every operation uses
/// two-phase locking (2PL), and the lambda parameters to methods enable nesting
/// of 2PL operations across maps.
///
/// @param K The type of the keys in this map
/// @param V The type of the values in this map
template <typename K, typename V> class ConcurrentHashMap : public Map<K, V> {
struct ChrisBuck{
  list<pair<K, V>> bucketList;
  mutex lock;
  ChrisBuck(){
    this->bucketList = list<pair<K, V>>();
  };
};
vector<ChrisBuck*> mainList;
public:
  /// Construct by specifying the number of buckets it should have
  ///
  /// @param _buckets The number of buckets
  ConcurrentHashMap(size_t _buckets) {
    for(size_t i = 0; i < _buckets; i++){
      mainList.push_back(new ChrisBuck());
    }
  }

  /// Destruct the ConcurrentHashMap
  virtual ~ConcurrentHashMap() {}

  /// Clear the map.  This operation needs to use 2pl
  virtual void clear() {
    /// Lock then Clear all the buckets
    for(auto &entry : mainList){
      entry->lock.lock();
      entry->bucketList.clear();      
    }
    /// Release all the locks
    for(auto &entry : mainList){
      entry->lock.unlock();      
    }
  }

  /// Insert the provided key/value pair only if there is no mapping for the key
  /// yet.
  ///
  /// @param key        The key to insert
  /// @param val        The value to insert
  /// @param on_success Code to run if the insertion succeeds
  ///
  /// @return true if the key/value was inserted, false if the key already
  ///         existed in the table
  virtual bool insert(K key, V val, std::function<void()> on_success) {
    size_t index = hash<K>{}(key) % mainList.size();
    unique_lock l(mainList[index]->lock);
    bool found = false;
    for(auto &iter : mainList[index]->bucketList){
      if(iter.first == key){
        found = true;
        break;
      }
    }
    if(found){
      return false;
    }else{
      mainList[index]->bucketList.push_back(make_pair(key,val));
      on_success();
      return true;
    }
  }

  /// Insert the provided key/value pair if there is no mapping for the key yet.
  /// If there is a key, then update the mapping by replacing the old value with
  /// the provided value
  ///
  /// @param key    The key to upsert
  /// @param val    The value to upsert
  /// @param on_ins Code to run if the upsert succeeds as an insert
  /// @param on_upd Code to run if the upsert succeeds as an update
  ///
  /// @return true if the key/value was inserted, false if the key already
  ///         existed in the table and was thus updated instead
  virtual bool upsert(K key, V val, std::function<void()> on_ins,
                      std::function<void()> on_upd) {
    size_t index = hash<K>{}(key) % mainList.size();
    unique_lock l(mainList[index]->lock);
    for(auto &iter : mainList[index]->bucketList){
      if(iter.first == key){
        iter.second = val;
        on_upd();
        return false;
      }
    }
    mainList[index]->bucketList.push_back(make_pair(key,val));
    on_ins();
    return true;
  }

  /// Apply a function to the value associated with a given key.  The function
  /// is allowed to modify the value.
  ///
  /// @param key The key whose value will be modified
  /// @param f   The function to apply to the key's value
  ///
  /// @return true if the key existed and the function was applied, false
  ///         otherwise
  virtual bool do_with(K key, std::function<void(V &)> f) {
    size_t index = hash<K>{}(key) % mainList.size();
    unique_lock l(mainList[index]->lock);
    for(auto &iter : mainList[index]->bucketList){
      if(iter.first == key){
        f(iter.second);
        return true;
      }
    }
    return false;
  }

  /// Apply a function to the value associated with a given key.  The function
  /// is not allowed to modify the value.
  ///
  /// @param key The key whose value will be modified
  /// @param f   The function to apply to the key's value
  ///
  /// @return true if the key existed and the function was applied, false
  ///         otherwise
  virtual bool do_with_readonly(K key, std::function<void(const V &)> f) {
    size_t index = hash<K>{}(key) % mainList.size();
    unique_lock l(mainList[index]->lock);
    for(auto &iter : mainList[index]->bucketList){
      if(iter.first == key){
        V copy_of_val = iter.second;
        f(copy_of_val);
        return true;
      }
    }
    return false;
  }

  /// Remove the mapping from a key to its value
  ///
  /// @param key        The key whose mapping should be removed
  /// @param on_success Code to run if the remove succeeds
  ///
  /// @return true if the key was found and the value unmapped, false otherwise
  virtual bool remove(K key, std::function<void()> on_success) {
    size_t index = hash<K>{}(key) % mainList.size();
    unique_lock l(mainList[index]->lock);
    for(auto iter = mainList[index]->bucketList.begin(); iter != mainList[index]->bucketList.end(); iter++){
      if(iter->first == key){
        mainList[index]->bucketList.erase(iter);
        on_success();
        return true;
      }
    }
    return false;
  }

  /// Apply a function to every key/value pair in the map.  Note that the
  /// function is not allowed to modify keys or values.
  ///
  /// @param f    The function to apply to each key/value pair
  /// @param then A function to run when this is done, but before unlocking...
  ///             useful for 2pl
  virtual void do_all_readonly(std::function<void(const K, const V &)> f,
                               std::function<void()> then) {
    // for every bucket, lock that bucket then apply the function to each pair in that bucket
    for(auto &entry : mainList){
      entry->lock.lock();
      for(auto &iter : entry->bucketList){
        K fakeKey = iter.first;
        V fakeVal = iter.second;
        f(fakeKey,fakeVal);
      }
    }
    then();
    /// Release all the locks
    for(auto &entry : mainList){
      entry->lock.unlock();      
    }
  }
};
