// http://www.cplusplus.com/reference/ctime/time/ is helpful here
#include <deque>
#include <iostream>
#include <memory>
#include <time.h>

#include "quota_tracker.h"

using namespace std;

/// quota_tracker stores time-ordered information about events.  It can count
/// events within a pre-set, fixed time threshold, to decide if a new event can
/// be allowed without violating a quota.
class my_quota_tracker : public quota_tracker {

  deque<pair<size_t, time_t>> dq;
  double threshold;
  double duration;
public:
  /// Construct a tracker that limits usage to quota_amount per quota_duration
  /// seconds
  ///
  /// @param amount   The maximum amount of service
  /// @param duration The time over which the service maximum can be spread out
  my_quota_tracker(size_t amount, double duration) {
    this->duration = duration;
    threshold = amount;
  }

  /// Destruct a quota tracker
  virtual ~my_quota_tracker() {}

  /// Decide if a new event is permitted, and if so, add it.  The attempt is
  /// allowed if it could be added to events, while ensuring that the sum of
  /// amounts for all events within the duration is less than q_amnt.
  ///
  /// @param amount The amount of the new request
  ///
  /// @return false if the amount could not be added without violating the
  ///         quota, true if the amount was added while preserving the quota
  virtual bool check_add(size_t amount) {
    bool result = false;
    // Get current time
    time_t timenow;
    time(&timenow);
    // Go through deque to add up the number of items within the alloted time
    deque<pair<size_t, time_t>>::iterator iter;
    iter = dq.begin();
    int amountInDuration = 0;
    while (iter != dq.end()){
      if (iter->second + duration >= timenow){
        amountInDuration += iter->first;
      }
      // else{
      //   dq.erase(iter--);
      // }
      iter++;
    }
    // If allowed, push it to the front
    if (amountInDuration + amount <= threshold){
      dq.push_front(pair(amount, timenow));
      result = true;
    }
    
    // Remove all old entries
    iter = dq.begin();
    while(iter != dq.end()){
      if (iter->second + duration < timenow){
        dq.erase(iter);
      }
      else{
        iter++;
      }
    }

    return result;
  }
};

/// Construct a tracker that limits usage to quota_amount per quota_duration
/// seconds
///
/// @param amount   The maximum amount of service
/// @param duration The time over which the service maximum can be spread out
quota_tracker *quota_factory(size_t amount, double duration) {
  return new my_quota_tracker(amount, duration);
}