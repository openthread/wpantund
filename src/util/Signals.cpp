#include "Signals.h"

#include <netinet/in.h>
#include <boost/signals2/signal.hpp>

namespace nl {
namespace wpantund {

#define IMPLEMENT_SIGNAL(NAME, ...) \
typedef boost::signals2::signal<void( __VA_ARGS__ )> NAME##Signal;\
NAME::NAME(void)\
{\
	internal = new NAME##Signal;\
}\
NAME::~NAME(void)\
{\
	delete static_cast<NAME##Signal*>(internal);\
}\
\
void NAME::connect(func_type func)\
{\
	static_cast<NAME##Signal *>(internal)->connect(func);\
}\
void NAME::disconnect(func_type func)\
{\
	static_cast<NAME##Signal *>(internal)->disconnect(&func);\
}

IMPLEMENT_SIGNAL(OnNetWake, uint8_t, cms_t)
void OnNetWake::operator()(uint8_t data, cms_t ms_remaining)
{
	(*static_cast<OnNetWakeSignal *>(internal))(data, ms_remaining);
}

IMPLEMENT_SIGNAL(OnPropertyChanged, const std::string&, const boost::any&)
void OnPropertyChanged::operator()(const std::string& key, const boost::any& value)
{
	(*static_cast<OnPropertyChangedSignal *>(internal))(key, value);
}

IMPLEMENT_SIGNAL(OnEnergyScanResult, const EnergyScanResultEntry&)
void OnEnergyScanResult::operator()(const EnergyScanResultEntry& entry)
{
	(*static_cast<OnEnergyScanResultSignal *>(internal))(entry);
}

IMPLEMENT_SIGNAL(OnNetScanBeacon, const WPAN::NetworkInstance& instance)
void OnNetScanBeacon::operator()(const WPAN::NetworkInstance& instance)
{
	(*static_cast<OnNetScanBeaconSignal *>(internal))(instance);
}

IMPLEMENT_SIGNAL(OnMfgRXPacket, Data, uint8_t, int8_t)
void OnMfgRXPacket::operator()(Data arg1, uint8_t arg2, int8_t arg3)
{
	(*static_cast<OnMfgRXPacketSignal *>(internal))(arg1, arg2, arg3);
}

IMPLEMENT_SIGNAL(SignalWithStatus, int)
void SignalWithStatus::operator()(int status)
{
	(*static_cast<SignalWithStatusSignal *>(internal))(status);
}

IMPLEMENT_SIGNAL(AddressWasAdded, struct in6_addr const&, int)
void AddressWasAdded::operator()(struct in6_addr const& arg1, int arg2)
{
	(*static_cast<AddressWasAddedSignal *>(internal))(arg1, arg2);
}

IMPLEMENT_SIGNAL(AddressWasRemoved, const in6_addr&, int)
void AddressWasRemoved::operator()(const in6_addr& arg1, int arg2)
{
	(*static_cast<AddressWasRemovedSignal *>(internal))(arg1, arg2);
}

IMPLEMENT_SIGNAL(LinkStateChanged, bool, bool)
void LinkStateChanged::operator()(bool arg1, bool arg2)
{
	(*static_cast<LinkStateChangedSignal *>(internal))(arg1, arg2);
}

}; // namespace wpantund
}; // namespace nl
