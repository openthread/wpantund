#ifndef SIGNALS_H_
#define SIGNALS_H_

#include <string>
#include <boost/function.hpp>
#include <boost/any.hpp>

#include <netinet/in.h>

#include "Data.h"
#include "NCPTypes.h"
#include "NetworkInstance.h"
#include "time-utils.h"

namespace nl {
namespace wpantund {

#define DEFINE_SIGNAL(NAME, ...) \
class NAME \
{ \
	typedef boost::function<void( __VA_ARGS__ )> func_type; \
public: \
	NAME(void); \
	~NAME(void); \
	void connect(func_type func); \
	void disconnect(func_type func); \
	void operator()( __VA_ARGS__ ); \
	void *internal; \
}

DEFINE_SIGNAL(OnNetWake, uint8_t data, cms_t ms_remaining);

DEFINE_SIGNAL(OnPropertyChanged, const std::string& key, const boost::any& value);

DEFINE_SIGNAL(OnEnergyScanResult, const EnergyScanResultEntry& entry);

DEFINE_SIGNAL(OnNetScanBeacon, const WPAN::NetworkInstance& instance);

DEFINE_SIGNAL(OnMfgRXPacket, Data, uint8_t, int8_t);

DEFINE_SIGNAL(SignalWithStatus, int);

DEFINE_SIGNAL(AddressWasAdded, in6_addr const&, int);

DEFINE_SIGNAL(AddressWasRemoved, const struct in6_addr&, int);

DEFINE_SIGNAL(LinkStateChanged, bool, bool);

}; // namespace wpantund
}; // namespace nl

#endif // SIGNALS_H_
