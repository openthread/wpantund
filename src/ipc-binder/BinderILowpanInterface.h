/*
 *
 * Copyright (C) 2017 Nest Labs, Inc.
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *    Description:
 *      Header for Thread-safe IBinder class wrapper for NCPControlInterface.
 *
 */

#ifndef BINDER_I_LOWPAN_INTERFACE_HEADER_INCLUDED
#define BINDER_I_LOWPAN_INTERFACE_HEADER_INCLUDED

#include <android/net/lowpan/ILowpanInterface.h>
#include <android/net/lowpan/BnLowpanInterface.h>
#include <binder/IBinder.h>
#include <set>
#include <mutex>

typedef ::android::base::unique_fd ScopedFd;

namespace nl {
namespace wpantund {

class BinderIPCServer;
class CallbackArguments;
class NCPControlInterface;

class BinderILowpanInterface : public ::android::net::lowpan::BnLowpanInterface, public ::android::IBinder::DeathRecipient {
public:
	BinderILowpanInterface(BinderIPCServer &ipcServer, NCPControlInterface *interface);
	virtual ~BinderILowpanInterface();

	virtual ::android::binder::Status getName(::std::string* _aidl_return) override;
	virtual ::android::binder::Status getNcpVersion(::std::string* _aidl_return) override;
	virtual ::android::binder::Status getDriverVersion(::std::string* _aidl_return) override;
	virtual ::android::binder::Status getSupportedChannels(::std::vector<::android::net::lowpan::LowpanChannelInfo>* _aidl_return) override;
	virtual ::android::binder::Status getSupportedNetworkTypes(::std::vector<::std::string>* _aidl_return) override;
	virtual ::android::binder::Status getMacAddress(::std::vector<uint8_t>* _aidl_return) override;
	virtual ::android::binder::Status isEnabled(bool* _aidl_return) override;
	virtual ::android::binder::Status setEnabled(bool enabled) override;
	virtual ::android::binder::Status isUp(bool* _aidl_return) override;
	virtual ::android::binder::Status isCommissioned(bool* _aidl_return) override;
	virtual ::android::binder::Status isConnected(bool* _aidl_return) override;
	virtual ::android::binder::Status getState(::std::string* _aidl_return) override;
	virtual ::android::binder::Status getRole(::std::string* _aidl_return) override;
	virtual ::android::binder::Status getPartitionId(::std::string* _aidl_return) override;
	virtual ::android::binder::Status getExtendedAddress(::std::vector<uint8_t>* _aidl_return) override;
	virtual ::android::binder::Status getLowpanIdentity(::android::net::lowpan::LowpanIdentity* _aidl_return) override;
	virtual ::android::binder::Status getLowpanCredential(::android::net::lowpan::LowpanCredential* _aidl_return) override;
	virtual ::android::binder::Status getLinkAddresses(::std::vector<::std::string>* _aidl_return) override;
	virtual ::android::binder::Status getLinkNetworks(::std::vector<::android::net::IpPrefix>* _aidl_return) override;
	virtual ::android::binder::Status join(const ::android::net::lowpan::LowpanProvision& provision) override;
	virtual ::android::binder::Status form(const ::android::net::lowpan::LowpanProvision& provision) override;
	virtual ::android::binder::Status attach(const ::android::net::lowpan::LowpanProvision& provision) override;
	virtual ::android::binder::Status leave() override;
	virtual ::android::binder::Status reset() override;
	virtual ::android::binder::Status startCommissioningSession(const ::android::net::lowpan::LowpanBeaconInfo& beaconInfo) override;
	virtual ::android::binder::Status closeCommissioningSession() override;
	virtual ::android::binder::Status sendToCommissioner(const ::std::vector<uint8_t>& packet) override;
	virtual ::android::binder::Status beginLowPower() override;
	virtual ::android::binder::Status pollForData() override;
	virtual ::android::binder::Status onHostWake() override;
	virtual ::android::binder::Status addListener(const ::android::sp<::android::net::lowpan::ILowpanInterfaceListener>& listener) override;
	virtual ::android::binder::Status removeListener(const ::android::sp<::android::net::lowpan::ILowpanInterfaceListener>& listener) override;
	virtual ::android::binder::Status startNetScan(const ::android::binder::Map& properties, const ::android::sp<::android::net::lowpan::ILowpanNetScanCallback>& listener) override;
	virtual ::android::binder::Status stopNetScan() override;
	virtual ::android::binder::Status startEnergyScan(const ::android::binder::Map& properties, const ::android::sp<::android::net::lowpan::ILowpanEnergyScanCallback>& listener) override;
	virtual ::android::binder::Status stopEnergyScan() override;
	virtual ::android::binder::Status addOnMeshPrefix(const ::android::net::IpPrefix& prefix, int32_t flags) override;
	virtual ::android::binder::Status removeOnMeshPrefix(const ::android::net::IpPrefix& prefix) override;
	virtual ::android::binder::Status addExternalRoute(const ::android::net::IpPrefix& prefix, int32_t flags) override;
	virtual ::android::binder::Status removeExternalRoute(const ::android::net::IpPrefix& prefix) override;

	void onPropertyChanged(const std::string& key, const boost::any& value);
	void onNetScanBeacon(const WPAN::NetworkInstance& network);
	void onEnergyScanResult(const EnergyScanResultEntry& entry);

	virtual void binderDied(const ::android::wp<::android::IBinder>& who) override;

	void onNetScanFinished(int status);
	void onEnergyScanFinished(int status);

private:
	::android::binder::Status fetchProperty(const std::string& key, boost::any& out);
	::android::binder::Status fetchPropertyToBinderValue(const std::string& key, ::android::binder::Value& value);
	::android::binder::Status setProperty(const std::string& key, const boost::any& value);


private:
	BinderIPCServer& mIpcServer;
	NCPControlInterface& mInterface;

	std::mutex mMutex;

	std::set<::android::sp<::android::net::lowpan::ILowpanInterfaceListener>> mListeners;

	::android::sp<::android::net::lowpan::ILowpanNetScanCallback> mNetScanListener;
	volatile int mNetScanStatus;
	::android::sp<::android::net::lowpan::ILowpanEnergyScanCallback> mEnergyScanListener;
	volatile int mEnergyScanStatus;
}; // class BinderILowpanInterface

} // namespace wpantund
} // namespace nl

#endif // BINDER_I_LOWPAN_INTERFACE_HEADER_INCLUDED
