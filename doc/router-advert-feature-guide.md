# `wpantund` ICMPv6 Router Advertisement Feature #

The `"Router Advertisement"` feature enables `wpantund` to emit periodic Neighbor Discovery ICMPv6 Router Advertisement (RA) messages announcing routes on other network interfaces related to Thread network routes.

The emitted RA can inlcude a set of prefixes (determined by user) or annoucne a default route.

When "Route Info" option is enabled, the routes included in RA message mirror all the routes added on the host primary interface corresponding to the Thread network:
- Host routes associated with off-mesh routes within the Thread network (when `Daemon:OffMeshRoute:AutoAddOnInterface` feature is enabled).
- Host routes associated with on-mesh prefixes within the Thread network (when `Daemon:OnMeshPrefix:AutoAddAsInterfaceRoute` feature is enabled).
- The list of interface routes is available form wpan property `IPv6:Routes`.

The wpantund RA feature can be enabled through property `RouterAdvert:Enable` (by default it is disabled) and its behavior can modified through a group of wpan properties (all starting with `RouterAdvert:` prefix).

- `RouterAdvert:Enable` can be used to enable or disable the whole feature (default is false, i.e., disabled)
- `RouterAdvert:Netifs` defines the list of netif names to send RA messages on. This is a list-based property (we can set the entire list using space separated interface names, or use `add` or `remove` commands to update the list item by item). On start the list is empty.
- `RouterAdvert:TxPeriod` the tx period of RA messages in units of seconds. Minimum period is 4 seconds, max period is 1800 seconds. The period is set to min or max if the value being set is out of the supported range. On start it is set to 10 seconds.
- `RouterAdvert:DefaultRoute:Lifetime` specifies the lifetime value in RA header (non-zero indicates that we are a default route). By default it is set to zero (i.e. not a default route).
- `RouterAdvert:DefaultRoute:Preference` specifies the default route preference. Positive value indicates high, zero indicates medium, and negative indicates low preference. Default value is zero (medium).
- `RouterAdvert:AddRouteInfoOption` can be used to enable or disable adding of "Route Info" option in RA. When set to false, the emitted RAs would not contain any "Route Info" options. By default it is enabled (set to true).
- `RouterAdvert:Prefixes` specifies the list of prefixes which are included in the RA message. This is a list-based property (we can set the entire list or use `add` or `remove` command to update the list item by item). When adding to the list, we can specify the length,  valid and preferred lifetime, and associated flags (on-link and auto-config). A set of wpan properties are defined to help specify these. The value specified through these properties would apply to any next prefix added/removed to the list:

  - `RouterAdvert:Prefix:PrefixLength`  in bits 0-128 - default is 64.
  - `RouterAdvert:Prefix:ValidLifetime` in seconds - default is 3600.
  - `RouterAdvert:Prefix:PreferredLifetime` in seconds - default is 3600.
  - `RouterAdvert:Prefix:Flag:OnLink` boolean value for on-link flag - default is true.
  - `RouterAdvert:Prefix:Flag:AutoConfig` boolean value for auto-config flag - default is true.

When issuing a wpantund `leave` command, the list of prefixes and netifs for router advertisement will be cleared.

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

	11:01:58.991522 IP6 (flowlabel 0xba663, hlim 255, next-header ICMPv6 (58) payload length: 40) fe80::4801:7e22:7895:a656 > ff02::1: [icmp6 sum ok] ICMP6, router advertisement, length 40
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

	11:22:23.785865 IP6 (flowlabel 0xbcd66, hlim 255, next-header ICMPv6 (58) payload length: 40) fe80::6d87:d70b:c949:762a > ff02::1: [icmp6 sum ok] ICMP6, router advertisement, length 40
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

	11:07:04.441659 IP6 (flowlabel 0xba663, hlim 255, next-header ICMPv6 (58) payload length: 56) fe80::4801:7e22:7895:a656 > ff02::1: [icmp6 sum ok] ICMP6, router advertisement, length 56
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

	11:07:08.445622 IP6 (flowlabel 0xba663, hlim 255, next-header ICMPv6 (58) payload length: 56) fe80::4801:7e22:7895:a656 > ff02::1: [icmp6 sum ok] ICMP6, router advertisement, length 56
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

	11:10:05.929627 IP6 (flowlabel 0xba663, hlim 255, next-header ICMPv6 (58) payload length: 56) fe80::4801:7e22:7895:a656 > ff02::1: [icmp6 sum ok] ICMP6, router advertisement, length 56
		hop limit 255, Flags [none], pref medium, router lifetime 1000s, reachable time 3600s, retrans time 0s
		  source link-address option (1), length 8 (1): 00:00:00:00:00:00
		    0x0000:  0000 0000 0000

The property `RouterAdvert:DefaultRoute:Preference` determines default route preference. Positive value indicates high, zero indicates medium, and negative indicates low preference.

	wpanctl:wpan1> set RouterAdvert:DefaultRoute:Preference 1

	11:12:19.989599 IP6 (flowlabel 0xba663, hlim 255, next-header ICMPv6 (58) payload length: 56) fe80::4801:7e22:7895:a656 > ff02::1: [icmp6 sum ok] ICMP6, router advertisement, length 56
		hop limit 255, Flags [none], pref high, router lifetime 1000s, reachable time 3600s, retrans time 0s

	wpanctl:wpan1> set RouterAdvert:DefaultRoute:Preference -v -1

	11:13:08.078489 IP6 (flowlabel 0xba663, hlim 255, next-header ICMPv6 (58) payload length: 56) fe80::4801:7e22:7895:a656 > ff02::1: [icmp6 sum ok] ICMP6, router advertisement, length 56
		hop limit 255, Flags [none], pref low, router lifetime 1000s, reachable time 3600s, retrans time 0s


The command below show an example of how to add a prefix to RA.

	wpanctl:wpan1> get RouterAdvert:Prefixes
	RouterAdvert:Prefixes = []

We first set all related parameters using `RouterAdvert:Prefix:<Name>` properties:

	wpanctl:wpan1> set RouterAdvert:Prefix:ValidLifetime 3000
	wpanctl:wpan1> set RouterAdvert:Prefix:PreferredLifetime 5000
	wpanctl:wpan1> set RouterAdvert:Prefix:PrefixLength 64
	wpanctl:wpan1> set RouterAdvert:Prefix:Flag:OnLink false
	wpanctl:wpan1> set RouterAdvert:Prefix:Flag:AutoConfig false
	wpanctl:wpan1> add RouterAdvert:Prefixes fd00:7777::
	wpanctl:wpan1>
	wpanctl:wpan1> get RouterAdvert:Prefixes
	RouterAdvert:Prefixes = [
		"prefix: fd00:7777::/64, flags:[ ], valid lifetime:3000, preferred lifetime:5000"
	]

tcpdump shows the prefix option:

	20:57:26.624969 IP6 (flowlabel 0x034c9, hlim 255, next-header ICMPv6 (58) payload length: 56) fe80::70c8:17e:f25a:6733 > ff02::1: [icmp6 sum ok] ICMP6, router advertisement, length 56
		hop limit 255, Flags [none], pref medium, router lifetime 0s, reachable time 3600s, retrans time 0s
		  source link-address option (1), length 8 (1): 00:00:00:00:00:00
		    0x0000:  0000 0000 0000
		  prefix info option (3), length 32 (4): fd00:7777::/64, Flags [none], valid time 3000s, pref. time 5000s
		    0x0000:  4000 0000 0bb8 0000 1388 0000 0000 fd00
		    0x0010:  7777 0000 0000 0000 0000 0000 0000
		0x0000:  6000 34c9 0038 3aff fe80 0000 0000 0000  `.4..8:.........
		0x0010:  70c8 017e f25a 6733 ff02 0000 0000 0000  p..~.Zg3........
		0x0020:  0000 0000 0000 0001 8600 cb64 ff00 0000  ...........d....
		0x0030:  0000 0e10 0000 0000 0101 0000 0000 0000  ................
		0x0040:  0304 4000 0000 0bb8 0000 1388 0000 0000  ..@.............
		0x0050:  fd00 7777 0000 0000 0000 0000 0000 0000  ..ww............

Adding a new prefix with a different set of parameters:

	wpanctl:wpan1> set RouterAdvert:Prefix:Flag:AutoConfig true
	wpanctl:wpan1> set RouterAdvert:Prefix:Flag:OnLink true
	wpanctl:wpan1> set RouterAdvert:Prefix:PreferredLifetime 2500
	wpanctl:wpan1> set RouterAdvert:Prefix:PreferredLifetime 3000
	wpanctl:wpan1> set RouterAdvert:Prefix:PrefixLength 48
	wpanctl:wpan1> add RouterAdvert:Prefixes fd00:4321::

	wpanctl:wpan1> get RouterAdvert:Prefixes
	RouterAdvert:Prefixes = [
		"prefix: fd00:7777::/64, flags:[ ], valid lifetime:3000, preferred lifetime:5000"
		"prefix: fd00:4321::/48, flags:[ on-link auto ], valid lifetime:3000, preferred lifetime:3000"
	]

tcpdump

	20:59:56.041669 IP6 (flowlabel 0x034c9, hlim 255, next-header ICMPv6 (58) payload length: 88) fe80::70c8:17e:f25a:6733 > ff02::1: [icmp6 sum ok] ICMP6, router advertisement, length 88
		hop limit 255, Flags [none], pref medium, router lifetime 0s, reachable time 3600s, retrans time 0s
		  source link-address option (1), length 8 (1): 00:00:00:00:00:00
		    0x0000:  0000 0000 0000
		  prefix info option (3), length 32 (4): fd00:7777::/64, Flags [none], valid time 3000s, pref. time 5000s
		    0x0000:  4000 0000 0bb8 0000 1388 0000 0000 fd00
		    0x0010:  7777 0000 0000 0000 0000 0000 0000
		  prefix info option (3), length 32 (4): fd00:4321::/48, Flags [onlink, auto], valid time 3000s, pref. time 3000s
		    0x0000:  30c0 0000 0bb8 0000 0bb8 0000 0000 fd00
		    0x0010:  4321 0000 0000 0000 0000 0000 0000
		0x0000:  6000 34c9 0058 3aff fe80 0000 0000 0000  `.4..X:.........
		0x0010:  70c8 017e f25a 6733 ff02 0000 0000 0000  p..~.Zg3........
		0x0020:  0000 0000 0000 0001 8600 3fee ff00 0000  ..........?.....
		0x0030:  0000 0e10 0000 0000 0101 0000 0000 0000  ................
		0x0040:  0304 4000 0000 0bb8 0000 1388 0000 0000  ..@.............
		0x0050:  fd00 7777 0000 0000 0000 0000 0000 0000  ..ww............
		0x0060:  0304 30c0 0000 0bb8 0000 0bb8 0000 0000  ..0.............
		0x0070:  fd00 4321 0000 0000 0000 0000 0000 0000  ..C!............

Removing a prefix (when removing prefix only prefix length paramter is required along with the pregfix itself)

	wpanctl:wpan1> set RouterAdvert:Prefix:PrefixLength 48
	wpanctl:wpan1> remove RouterAdvert:Prefixes fd00:4321::
	wpanctl:wpan1> get RouterAdvert:Prefixes
	RouterAdvert:Prefixes = [
		"prefix: fd00:7777::/64, flags:[ ], valid lifetime:3000, preferred lifetime:5000"
	]

tcpdump

	21:25:43.421691 IP6 (flowlabel 0x034c9, hlim 255, next-header ICMPv6 (58) payload length: 56) fe80::70c8:17e:f25a:6733 > ff02::1: [icmp6 sum ok] ICMP6, router advertisement, length 56
		hop limit 255, Flags [none], pref medium, router lifetime 0s, reachable time 3600s, retrans time 0s
		  source link-address option (1), length 8 (1): 00:00:00:00:00:00
		    0x0000:  0000 0000 0000
		  prefix info option (3), length 32 (4): fd00:7777::/64, Flags [none], valid time 3000s, pref. time 5000s
		    0x0000:  4000 0000 0bb8 0000 1388 0000 0000 fd00
		    0x0010:  7777 0000 0000 0000 0000 0000 0000
		0x0000:  6000 34c9 0038 3aff fe80 0000 0000 0000  `.4..8:.........
		0x0010:  70c8 017e f25a 6733 ff02 0000 0000 0000  p..~.Zg3........
		0x0020:  0000 0000 0000 0001 8600 cb64 ff00 0000  ...........d....
		0x0030:  0000 0e10 0000 0000 0101 0000 0000 0000  ................
		0x0040:  0304 4000 0000 0bb8 0000 1388 0000 0000  ..@.............
		0x0050:  fd00 7777 0000 0000 0000 0000 0000 0000  ..ww............

The `RouterAdvert:AddRouteInfoOption` can be used to disable adding of ant "Route Info" option to RA:

    # Add a prefix to RA and also a Thread on-mesh prefix (which will add a corresponding route on host):
	wpanctl:wpan1> set RouterAdvert:Netifs wpan1
	wpanctl:wpan1> set RouterAdvert:Prefixes fd00:cafe:beef::
	wpanctl:wpan1> get RouterAdvert:Prefixes
	RouterAdvert:Prefixes = [
		"prefix: fd00:cafe:beef::/64, flags:[ on-link auto ], valid lifetime:3600, preferred lifetime:3600"
	]
	wpanctl:wpan1> add-prefix fd00:abba:: -o -c
	Successfully added prefix "fd00:abba::" len:64 stable:0 [on-mesh:1 def-route:0 config:1 dhcp:0 slaac:0 pref:0 prio:med]

	wpanctl:wpan1> get IPv6:Routes
	IPv6:Routes = [
		"fd00:abba::/64             metric:256   "
	]

	wpanctl:wpan1> set RouterAdvert:Enable true

tcpdump shows prefix info and two route option.

(NOTE: Since we are seing RA with `fd00:cafe:beef::` on wpan1 interface with on-link and auto-config flags, linux itself added an address with this prefix on `wpan1` interface which in turn was pushed to NCP by wpantund and its prefix added to list of on-mesh prefixes within Thread network. This in turn caused it to be added as a router info option as well)


	21:33:00.653646 IP6 (flowlabel 0x3d2ab, hlim 255, next-header ICMPv6 (58) payload length: 88) fe80::a4ab:2dcb:6a20:ca2b > ff02::1: [icmp6 sum ok] ICMP6, router advertisement, length 88
		hop limit 255, Flags [none], pref medium, router lifetime 0s, reachable time 3600s, retrans time 0s
		  source link-address option (1), length 8 (1): 00:00:00:00:00:00
		    0x0000:  0000 0000 0000
		  prefix info option (3), length 32 (4): fd00:cafe:beef::/64, Flags [onlink, auto], valid time 3600s, pref. time 3600s
		    0x0000:  40c0 0000 0e10 0000 0e10 0000 0000 fd00
		    0x0010:  cafe beef 0000 0000 0000 0000 0000
		  route info option (24), length 16 (2):  fd00:abba::/64, pref=medium, lifetime=3600s
		    0x0000:  4000 0000 0e10 fd00 abba 0000 0000
		  route info option (24), length 16 (2):  fd00:cafe:beef::/64, pref=medium, lifetime=3600s
		    0x0000:  4000 0000 0e10 fd00 cafe beef 0000
		0x0000:  6003 d2ab 0058 3aff fe80 0000 0000 0000  `....X:.........
		0x0010:  a4ab 2dcb 6a20 ca2b ff02 0000 0000 0000  ..-.j..+........
		0x0020:  0000 0000 0000 0001 8600 846f ff00 0000  ...........o....
		0x0030:  0000 0e10 0000 0000 0101 0000 0000 0000  ................
		0x0040:  0304 40c0 0000 0e10 0000 0e10 0000 0000  ..@.............
		0x0050:  fd00 cafe beef 0000 0000 0000 0000 0000  ................
		0x0060:  1802 4000 0000 0e10 fd00 abba 0000 0000  ..@.............
		0x0070:  1802 4000 0000 0e10 fd00 cafe beef 0000  ..@.............

Now setting `RouterAdvert:AddRouteInfoOption` to `false` removes all route info options:

	set RouterAdvert:AddRouteInfoOption false


	21:33:43.462431 IP6 (flowlabel 0x3d2ab, hlim 255, next-header ICMPv6 (58) payload length: 56) fe80::a4ab:2dcb:6a20:ca2b > ff02::1: [icmp6 sum ok] ICMP6, router advertisement, length 56
		hop limit 255, Flags [none], pref medium, router lifetime 0s, reachable time 3600s, retrans time 0s
		  source link-address option (1), length 8 (1): 00:00:00:00:00:00
		    0x0000:  0000 0000 0000
		  prefix info option (3), length 32 (4): fd00:cafe:beef::/64, Flags [onlink, auto], valid time 3600s, pref. time 3600s
		    0x0000:  40c0 0000 0e10 0000 0e10 0000 0000 fd00
		    0x0010:  cafe beef 0000 0000 0000 0000 0000
		0x0000:  6003 d2ab 0038 3aff fe80 0000 0000 0000  `....8:.........
		0x0010:  a4ab 2dcb 6a20 ca2b ff02 0000 0000 0000  ..-.j..+........
		0x0020:  0000 0000 0000 0001 8600 805f ff00 0000  ..........._....
		0x0030:  0000 0e10 0000 0000 0101 0000 0000 0000  ................
		0x0040:  0304 40c0 0000 0e10 0000 0e10 0000 0000  ..@.............
		0x0050:  fd00 cafe beef 0000 0000 0000 0000 0000  ................


Limitations:
- The current implementation does not support replying to Router Solicitation messages.
