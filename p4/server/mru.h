#pragma once

#include <memory>
#include <string>

/// mru_manager is an interface for an object that is capable of listing the K
/// most recent elements that have been given to it.  It can be used to produce
/// a "top" listing of the most recently accessed keys.
class mru_manager {
public:
  /// Destruct the mru_manager
  virtual ~mru_manager() {}

  /// Insert an element into the mru_manager, making sure that (a) there are no
  /// duplicates, and (b) the manager holds no more than /max_size/ elements.
  ///
  /// @param elt The element to insert
  virtual void insert(const std::string &elt) = 0;

  /// Remove an instance of an element from the mru_manager.  This can leave the
  /// manager in a state where it has fewer than max_size elements in it.
  ///
  /// @param elt The element to remove
  virtual void remove(const std::string &elt) = 0;

  /// Clear the mru_manager
  virtual void clear() = 0;

  /// Produce a concatenation of the top entries, in order of popularity
  ///
  /// @return A newline-separated list of values
  virtual std::string get() = 0;
};

/// Construct the mru_manager by specifying how many things it should track
///
/// @param elements The number of elements that can be tracked in MRU fashion
///
/// @return An mru manager object
mru_manager *mru_factory(size_t elements);