// http://www.cplusplus.com/reference/ctime/time/ is helpful here
#include <deque>
#include <iostream>
#include <memory>

#include "quota_tracker.h"

using namespace std;

/// quota_tracker stores time-ordered information about events.  It can count
/// events within a pre-set, fixed time threshold, to decide if a new event can
/// be allowed without violating a quota.
class my_quota_tracker : public quota_tracker {
  //Maximum Threshold
  size_t max_threshold;
  //Maximum duration
  double max_duration;
  //data structure
  deque<pair<time_t, double>> quota;

public:
  /// Construct a tracker that limits usage to quota_amount per quota_duration
  /// seconds
  ///
  /// @param amount   The maximum amount of service
  /// @param duration The time over which the service maximum can be spread out
  my_quota_tracker(size_t amount, double duration) {
    max_threshold = amount;
    max_duration = duration;
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
   //erase all the old events that is over the max_duration time
   auto p = quota.rbegin();
   while(p != quota.rend()){
    if(difftime(time(NULL), p->first) > max_duration){
      quota.pop_back();
    }
    else{
      //if the current one is within the max_duarion, we do not check the rest
      break;
    }
    p++;
   }
   //check max_threshold and insert
   size_t current_threshold = amount;
   auto d = quota.begin();
   while(d != quota.end()){
    current_threshold += d->second;
    d ++;
   }
   if(current_threshold > max_threshold){
    return false;
   }
   else{
    quota.push_front(make_pair(time(NULL), amount));
    return true;
   }
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