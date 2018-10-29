#ifndef __wpantund_NCPTime__
#define __wpantund_NCPTime__

#include <stdint.h>

namespace nl {
namespace wpantund {

class NetworkTime {
public:
    enum NetworkTimeStatus {
        NETWORK_TIME_UNSYNCHRONIZED,
        NETWORK_TIME_RESYNC_NEEDED,
        NETWORK_TIME_SYNCHRONIZED
    };
public:
    NetworkTime();

public:
    void handle_network_time_update(uint64_t network_time, NetworkTimeStatus status);
    bool have_network_time() const;
    bool get_network_time(uint64_t &network_time, NetworkTimeStatus &status) const;

private:
    bool mHaveNetworkTime;
    uint64_t mLastUpdateAtSysMonoTimeUs;
    uint64_t mLastNetworkTime;
    NetworkTimeStatus mLastNetworkTimeStatus;
};

}; // namespace wpantund
}; // namespace nl
#endif /* defined(__wpantund_NetworkTime__) */