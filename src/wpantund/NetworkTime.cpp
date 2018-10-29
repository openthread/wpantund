#include "NetworkTime.h"
#include "assert-macros.h"
#include "time-utils.h"

using namespace nl;
using namespace wpantund;

NetworkTime::NetworkTime():
    mHaveNetworkTime(false),
    mLastUpdateAtSysMonoTimeUs(0),
    mLastNetworkTime(0),
    mLastNetworkTimeStatus(NETWORK_TIME_UNSYNCHRONIZED) {

}

void NetworkTime::handle_network_time_update(uint64_t network_time, NetworkTimeStatus status) {
    mLastNetworkTime = network_time;
    mLastNetworkTimeStatus = status;
    mLastUpdateAtSysMonoTimeUs = time_get_monotonic_us();
    mHaveNetworkTime = true;
}

bool NetworkTime::have_network_time() const {
    return mHaveNetworkTime;
}

bool NetworkTime::get_network_time(uint64_t &network_time, NetworkTimeStatus &status) const {
    if (mHaveNetworkTime) {
        const uint64_t sys_mono_time_us = time_get_monotonic_us();
        assert(sys_mono_time_us >= mLastUpdateAtSysMonoTimeUs);

        network_time = mLastNetworkTime + (sys_mono_time_us - mLastUpdateAtSysMonoTimeUs);
        status = mLastNetworkTimeStatus;
    }
    
    return mHaveNetworkTime;
}