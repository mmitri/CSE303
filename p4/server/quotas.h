#pragma once

#include "quota_tracker.h"

/// Quotas holds all of the quotas associated with a user
struct Quotas {
  quota_tracker *uploads;   // The user's upload quota
  quota_tracker *downloads; // The user's download quota
  quota_tracker *requests;  // The user's requests quota

  /// Destruct the Quotas object
  ~Quotas() {
    delete uploads;
    delete downloads;
    delete requests;
  }
};
