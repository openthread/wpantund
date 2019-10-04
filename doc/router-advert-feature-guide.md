# `wpantund` ICMPv6 Router Advertisement Feature #

The `"Router Advertisement"` feature enables `wpantund` to emit periodic Neighbor Discovery ICMPv6 Router Advertisement (RA) messages announcing routes on other network interfaces related to Thread network routes.

The routes included in RA message mirror all the routes added on the host primary interface corresponding to the Thread network:
- Host routes associated with off-mesh routes within the Thread network (when `Daemon:OffMeshRoute:AutoAddOnInterface` feature is enabled).
- Host routes associated with on-mesh prefixes within the Thread network (when `Daemon:OnMeshPrefix:AutoAddAsInterfaceRoute` feature is enabled).
- The list of interface routes is available form wpan property `IPv6:Routes`.

The wpantund RA feature can be enabled through property `RouterAdvert:Enable` (by default it is disabled) and its behavior can modified through a group of wpan properties (all starting with `RouterAdvert:` prefix).

- `RouterAdvert:Enable` can be used to enable or disable the whole feature (default is false, i.e., disabled)
- `RouterAdvert:Netifs` defines the list of netif names to send RA messages on. This is a list-based property (we can set the entire list using space separated interface names, or use `add` or `remove` commands to update the list item by item). On start the list is empty.
- `RouterAdvert:TxPeriod` the tx period of RA messages in units of seconds. Minimum period is 4 seconds, max period is 1800 seconds. The period is set to min or max if the value being set is out of the supported range. On start it is set to 10 seconds.
- `RouterAdvert:DefaultRoute:Lifetime` specifies the lifetime value in RA header (non-zero indicates that we are a default route). By default it is set to zero (i.e. not a default route).
- `RouterAdvert:DefaultRoute:Preference` specifies the default route preference. Positive value indicates high, zero indicates medium, and negative indicates low preference. Default value is zero (medium).

# Example of behavior

We enable the feature:

	wpanctl:wpan1> set RouterAdvert:Enable true

Add the netif names we want ICMPv6 RA messages to be sent on (this is a list):

	wpanctl:wpan1> add RouterAdvert:Netifs wpan1
	wpanctl:wpan1> get RouterAdvert:Netifs
	RouterAdvert:Netifs = [
		"wpan1"
	]

When a route is added on host, the same route is announced through the RA message:

	wpanctl:wpan1> add-prefix fd00:1234:: -l 64 -o -c
	Successfully added prefix "fd00:1234::" len:64 stable:0 [on-mesh:1 def-route:0 config:1 dhcp:0 slaac:0 pref:0 prio:med]
	wpanctl:wpan1>
	wpanctl:wpan1>

	wpanctl:wpan1> get IPv6:Routes
	IPv6:Routes = [
		"fd00:1234::/64             metric:256   "
	]

Output of `tcpdump` on the interface shows the RA message:

	sudo tcpdump -n -i wpan1 icmp6 -vv -X

	11:01:58.991522 IP6 (flowlabel 0xba663, hlim 1, next-header ICMPv6 (58) payload length: 40) fe80::4801:7e22:7895:a656 > ff02::1: [icmp6 sum ok] ICMP6, router advertisement, length 40
		hop limit 255, Flags [none], pref medium, router lifetime 0s, reachable time 3600s, retrans time 0s
		  source link-address option (1), length 8 (1): 00:00:00:00:00:00
		    0x0000:  0000 0000 0000
		  route info option (24), length 16 (2):  fd00:1234::/64, pref=medium, lifetime=3600s
		    0x0000:  4000 0000 0e10 fd00 1234 0000 0000
		0x0000:  600b a663 0028 3a01 fe80 0000 0000 0000  `..c.(:.........
		0x0010:  4801 7e22 7895 a656 ff02 0000 0000 0000  H.~"x..V........
		0x0020:  0000 0000 0000 0001 8600 13af ff00 0000  ................
		0x0030:  0000 0e10 0000 0000 0101 0000 0000 0000  ................
		0x0040:  1802 4000 0000 0e10 fd00 1234 0000 0000  ..@........4....

We can add or remove interface names to `RouterAdvert:Netifs` property. The RA messages are sent over all given interfaces:

	wpanctl:wpan1> add RouterAdvert:Netifs eno1

	wpanctl:wpan1>
	wpanctl:wpan1> get RouterAdvert:Netifs
	RouterAdvert:Netifs = [
		"eno1"
		"wpan1"
	]

	sudo tcpdump -n -i eno1 icmp6 -vv -X

	11:22:23.785865 IP6 (flowlabel 0xbcd66, hlim 1, next-header ICMPv6 (58) payload length: 40) fe80::6d87:d70b:c949:762a > ff02::1: [icmp6 sum ok] ICMP6, router advertisement, length 40
		hop limit 255, Flags [none], pref medium, router lifetime 0s, reachable time 3600s, retrans time 0s
		  source link-address option (1), length 8 (1): ec:b1:d7:2f:7c:b9
		    0x0000:  ecb1 d72f 7cb9
		  route info option (24), length 16 (2):  fd00:1234::/64, pref=medium, lifetime=3600s
		    0x0000:  4000 0000 0e10 fd00 1234 0000 0000
		0x0000:  600b cd66 0028 3a01 fe80 0000 0000 0000  `..f.(:.........
		0x0010:  6d87 d70b c949 762a ff02 0000 0000 0000  m....Iv*........
		0x0020:  0000 0000 0000 0001 8600 341c ff00 0000  ..........4.....
		0x0030:  0000 0e10 0000 0000 0101 ecb1 d72f 7cb9  ............./|.
		0x0040:  1802 4000 0000 0e10 fd00 1234 0000 0000  ..@........4....

The `wpantund` logs indicate when a RA message is sent over an interface:

	wpantund[69029]: Sent ICMP6 RouterAdvert on "eno1" (1 route info options)
	wpantund[69029]: Sent ICMP6 RouterAdvert on "wpan1" (1 route info options)

The entire list of interfaces can be set in one command (via space separated list of names).

	wpanctl:wpan1> set RouterAdvert:Netifs  "wpan1 eno1"

	wpanctl:wpan1> get RouterAdvert:Netifs
	RouterAdvert:Netifs = [
		"eno1"
		"wpan1"
	]

RA messages are sent every `RouterAdvert:TxPeriod` seconds or when a route is added/removed (some state changes)

	wpanctl:wpan1> set RouterAdvert:TxPeriod 4

When a route is added/removed (state changes), a new RA is sent immediately.

	wpanctl:wpan1> add-prefix fd00:baba:cafe:: -l 48 -o -c
	Successfully added prefix "fd00:baba:cafe::" len:48 stable:0 [on-mesh:1 def-route:0 config:1 dhcp:0 slaac:0 pref:0 prio:med]

	wpanctl:wpan1> get IPv6:Routes
	IPv6:Routes = [
		"fd00:baba:cafe::/48        metric:256   "
		"fd00:1234::/64             metric:256   "
	]

`tcpdump` output now contains two route info options and is sent every 4 seconds:

	11:07:04.441659 IP6 (flowlabel 0xba663, hlim 1, next-header ICMPv6 (58) payload length: 56) fe80::4801:7e22:7895:a656 > ff02::1: [icmp6 sum ok] ICMP6, router advertisement, length 56
		hop limit 255, Flags [none], pref medium, router lifetime 0s, reachable time 3600s, retrans time 0s
		  source link-address option (1), length 8 (1): 00:00:00:00:00:00
		    0x0000:  0000 0000 0000
		  route info option (24), length 16 (2):  fd00:baba:cafe::/48, pref=medium, lifetime=3600s
		    0x0000:  3000 0000 0e10 fd00 baba cafe 0000
		  route info option (24), length 16 (2):  fd00:1234::/64, pref=medium, lifetime=3600s
		    0x0000:  4000 0000 0e10 fd00 1234 0000 0000
		0x0000:  600b a663 0038 3a01 fe80 0000 0000 0000  `..c.8:.........
		0x0010:  4801 7e22 7895 a656 ff02 0000 0000 0000  H.~"x..V........
		0x0020:  0000 0000 0000 0001 8600 3ad2 ff00 0000  ..........:.....
		0x0030:  0000 0e10 0000 0000 0101 0000 0000 0000  ................
		0x0040:  1802 3000 0000 0e10 fd00 baba cafe 0000  ..0.............
		0x0050:  1802 4000 0000 0e10 fd00 1234 0000 0000  ..@........4....

	11:07:08.445622 IP6 (flowlabel 0xba663, hlim 1, next-header ICMPv6 (58) payload length: 56) fe80::4801:7e22:7895:a656 > ff02::1: [icmp6 sum ok] ICMP6, router advertisement, length 56
		hop limit 255, Flags [none], pref medium, router lifetime 0s, reachable time 3600s, retrans time 0s
		  source link-address option (1), length 8 (1): 00:00:00:00:00:00
		    0x0000:  0000 0000 0000
		  route info option (24), length 16 (2):  fd00:baba:cafe::/48, pref=medium, lifetime=3600s
		    0x0000:  3000 0000 0e10 fd00 baba cafe 0000
		  route info option (24), length 16 (2):  fd00:1234::/64, pref=medium, lifetime=3600s
		    0x0000:  4000 0000 0e10 fd00 1234 0000 0000
		0x0000:  600b a663 0038 3a01 fe80 0000 0000 0000  `..c.8:.........
		0x0010:  4801 7e22 7895 a656 ff02 0000 0000 0000  H.~"x..V........
		0x0020:  0000 0000 0000 0001 8600 3ad2 ff00 0000  ..........:.....
		0x0030:  0000 0e10 0000 0000 0101 0000 0000 0000  ................
		0x0040:  1802 3000 0000 0e10 fd00 baba cafe 0000  ..0.............
		0x0050:  1802 4000 0000 0e10 fd00 1234 0000 0000  ..@........4....


The property `RouterAdvert:DefaultRoute:Lifetime` specifies the lifetime value in RA header (non-zero value indicates that this router is a default route):

	wpanctl:wpan1> set RouterAdvert:DefaultRoute:Lifetime 1000

	11:10:05.929627 IP6 (flowlabel 0xba663, hlim 1, next-header ICMPv6 (58) payload length: 56) fe80::4801:7e22:7895:a656 > ff02::1: [icmp6 sum ok] ICMP6, router advertisement, length 56
		hop limit 255, Flags [none], pref medium, router lifetime 1000s, reachable time 3600s, retrans time 0s
		  source link-address option (1), length 8 (1): 00:00:00:00:00:00
		    0x0000:  0000 0000 0000

The property `RouterAdvert:DefaultRoute:Preference` determines default route preference. Positive value indicates high, zero indicates medium, and negative indicates low preference.

	wpanctl:wpan1> set RouterAdvert:DefaultRoute:Preference 1

	11:12:19.989599 IP6 (flowlabel 0xba663, hlim 1, next-header ICMPv6 (58) payload length: 56) fe80::4801:7e22:7895:a656 > ff02::1: [icmp6 sum ok] ICMP6, router advertisement, length 56
		hop limit 255, Flags [none], pref high, router lifetime 1000s, reachable time 3600s, retrans time 0s

	wpanctl:wpan1> set RouterAdvert:DefaultRoute:Preference -v -1

	11:13:08.078489 IP6 (flowlabel 0xba663, hlim 1, next-header ICMPv6 (58) payload length: 56) fe80::4801:7e22:7895:a656 > ff02::1: [icmp6 sum ok] ICMP6, router advertisement, length 56
		hop limit 255, Flags [none], pref low, router lifetime 1000s, reachable time 3600s, retrans time 0s

Limitations:
- The current implementation does not support replying to Router Solicitation messages.
