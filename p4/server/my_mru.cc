#include <deque>
#include <iostream>
#include<bits/stdc++.h>
#include <mutex>

#include "mru.h"

using namespace std;

/// my_mru maintains a listing of the K most recent elements that have been
/// given to it.  It can be used to produce a "top" listing of the most recently
/// accessed keys.
class my_mru : public mru_manager {

deque<string> dq;
size_t max_size;
mutex mut;

public:
  /// Construct the mru_manager by specifying how many things it should track
  ///
  /// @param elements The number of elements that can be tracked
  my_mru(size_t elements) {
    max_size = elements;
  }

  /// Destruct the mru_manager
  virtual ~my_mru() {}

  /// Insert an element into the mru_manager, making sure that (a) there are no
  /// duplicates, and (b) the manager holds no more than /max_size/ elements.
  ///
  /// @param elt The element to insert
  virtual void insert(const std::string &elt) {
      mut.lock();
      // If elt exists in the deque already, remove it
      deque<string>::iterator index = find(dq.begin(), dq.end(), elt);
      if (index != dq.end()){
        dq.erase(index);
      }
      // If the deque is full, remove the last element
      if (dq.size() >= max_size){
        dq.pop_back();
      }
      // Add the element to the front of the deque
      dq.push_front(elt);
      mut.unlock();
  }

  /// Remove an instance of an element from the mru_manager.  This can leave the
  /// manager in a state where it has fewer than max_size elements in it.
  ///
  /// @param elt The element to remove
  virtual void remove(const std::string &elt) {
    mut.lock();
    deque<string>::iterator itr;
    itr = find(dq.begin(), dq.end(), elt);

    if (itr != dq.end()){
      dq.erase(itr);
    }
    mut.unlock();
  }

  /// Clear the mru_manager
  virtual void clear() { 
    mut.lock();
    dq.clear();
    mut.unlock();
  }

  /// Produce a concatenation of the top entries, in order of popularity
  ///
  /// @return A newline-separated list of values
  virtual std::string get() { 
    mut.lock();
    string res = "";
    deque<string>::iterator itr = dq.begin();
    while (itr != dq.end()){
      res += *itr + "\n";
      itr++;
    }
    mut.unlock();
    return res;
  }
};

/// Construct the mru_manager by specifying how many things it should track
///
/// @param elements The number of elements that can be tracked in MRU fashion
///
/// @return An mru manager object
mru_manager *mru_factory(size_t elements) { return new my_mru(elements); }