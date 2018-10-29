#include "NetworkTime.h"
#include "assert-macros.h"
#include "time-utils.h"

using namespace nl;
using namespace wpantund;

NetworkTime::NetworkTime():
    mHaveNetworkTime(false),
    mLastUpdateAtMonoTimeUs(0),
    mLastNetworkTime(0),
    mLastNetworkTimeStatus(NETWORK_TIME_UNSYNCHRONIZED) {

}

void NetworkTime::handle_network_time_update(uint64_t network_time, NetworkTimeStatus status) {
    mLastNetworkTime = network_time;
    mLastNetworkTimeStatus = status;
    mLastUpdateAtMonoTimeUs = time_get_monotonic_us();
    mHaveNetworkTime = true;
}

bool NetworkTime::have_network_time() const {
    return mHaveNetworkTime;
}

bool NetworkTime::get_network_time(uint64_t &network_time, NetworkTimeStatus &status, uint64_t& updated_at_mono_time_us, uint64_t& now_mono_time_us) const {
    bool result = false;

    if (mHaveNetworkTime) {
        const uint64_t mono_time_us = time_get_monotonic_us();
        if (mono_time_us >= mLastUpdateAtMonoTimeUs) {
            network_time = mLastNetworkTime + (mono_time_us - mLastUpdateAtMonoTimeUs);
            status = mLastNetworkTimeStatus;
            now_mono_time_us = mono_time_us;
            updated_at_mono_time_us = mLastUpdateAtMonoTimeUs;
            result = true;
        } else {
            // Ideally assert if asserts are enabled, otherwise return false
            assert(false);
        }        
    }
    
    return result;
}