dnl #
dnl # Copyright (c) 2016 Nest Labs, Inc.
dnl # All rights reserved.
dnl #
dnl # Licensed under the Apache License, Version 2.0 (the "License");
dnl # you may not use this file except in compliance with the License.
dnl # You may obtain a copy of the License at
dnl #
dnl #    http://www.apache.org/licenses/LICENSE-2.0
dnl #
dnl # Unless required by applicable law or agreed to in writing, software
dnl # distributed under the License is distributed on an "AS IS" BASIS,
dnl # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
dnl # See the License for the specific language governing permissions and
dnl # limitations under the License.
dnl #

AC_DEFUN([NL_DEBUG], [
	AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug[=verbose|symbols]],
				[enable compiling with debugging information and symbols]),
				[],
				[enable_debug=no])

	if test "x$enable_debug" '!=' "xno"
	then
		CXXFLAGS="$CXXFLAGS -g"
		CFLAGS="$CFLAGS -g"

		if test "x$enable_debug" '!=' "xsymbols"
		then CPPFLAGS="$CPPFLAGS -DDEBUG=1 -DDEBUG_LEVEL=2"
		fi

		if test "x$enable_debug" = "xverbose"
		then CPPFLAGS="$CPPFLAGS -DVERBOSE_DEBUG=1"
		fi
	fi


	AM_CONDITIONAL([DEBUG],[test "x$enable_debug" '!=' "xno" && test "x$enable_debug" '!=' "xsymbols"])
	AM_CONDITIONAL([VERBOSE_DEBUG],[test "x$enable_debug" = "xverbose"])
])

AC_DEFUN([CHECK_MISSING_FUNC], [
    AC_CHECK_FUNC($1, [], [
        nl_cv_missing_$1=yes
        MISSING_CPPFLAGS="${MISSING_CPPFLAGS} "'-include $(top_srcdir)/src/missing/$1/$1.h'
        MISSING_LIBADD="${MISSING_LIBADD} "'$(top_builddir)/src/missing/$1/lib$1.la'
    ])
    AM_CONDITIONAL(m4_toupper(MISSING_$1), [test "${nl_cv_missing_$1}" = "yes"])
])
AC_SUBST(MISSING_CPPFLAGS)
AC_SUBST(MISSING_LIBADD)

AC_DEFUN([NL_CHECK_LINKER_ARG], [
	prev_LDFLAGS="${LDFLAGS}"
	LDFLAGS="$1"
	AC_MSG_CHECKING([if linker supports "$1"])
	AC_LINK_IFELSE([$2],
		[
			LDFLAGS="${prev_LDFLAGS}"
			AC_MSG_RESULT([yes])
			$3
		],
		[
			LDFLAGS="${prev_LDFLAGS}"
			AC_MSG_RESULT([no])
			$4
		]
	)
	unset prev_LDFLAGS
])

AC_DEFUN([NL_EXPORT_DYNAMIC], [
	prev_LDFLAGS="${LDFLAGS}"
	LDFLAGS="-Wl,--export-dynamic"
	AC_LANG_PUSH(C)
	AC_MSG_CHECKING([linker flags needed for programs to export symbols])
	AC_LINK_IFELSE(
		AC_LANG_PROGRAM,
		[EXPORT_DYNAMIC_LDFLAGS="$LDFLAGS"],
		[EXPORT_DYNAMIC_LDFLAGS=""]
	)
	LDFLAGS="${prev_LDFLAGS}"
	unset prev_LDFLAGS
	AC_MSG_RESULT([\"$EXPORT_DYNAMIC_LDFLAGS\"])
	AC_SUBST(EXPORT_DYNAMIC_LDFLAGS)
	AC_LANG_POP(C)
])

AC_DEFUN([NL_FUZZ_SOURCE],[AC_LANG_SOURCE([[#include <stdint.h>
#include <stdlib.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) { return 0; }]])])

AC_DEFUN([NL_FUZZ_TARGETS],[
AC_ARG_ENABLE(
   fuzz-targets,
   AC_HELP_STRING(
       [--enable-fuzz-targets],
       [Enable all fuzz targets.]
   )
)
AM_CONDITIONAL([ENABLE_FUZZ_TARGETS],[(case "${enable_fuzz_targets}" in yes) true ;; *) false ;; esac)])

if test "x$enable_fuzz_targets" = "xyes"
then
	if test "${FUZZ_CFLAGS+set}" != "set"
	then
	AC_PROG_CXX()
	AC_LANG_PUSH(C++)
	AC_CHECK_LIB(Fuzzer,main,[],AC_MSG_ERROR([Cannot find libFuzzer]))
	NL_CHECK_LINKER_ARG(
		[-fsanitize=fuzzer,address],[NL_FUZZ_SOURCE],
		[
			FUZZ_CFLAGS=${FUZZ_CFLAGS--fsanitize=fuzzer,address}
			FUZZ_CXXFLAGS=${FUZZ_CXXFLAGS-$FUZZ_CFLAGS}
			FUZZ_LDFLAGS=${FUZZ_LDFLAGS-$FUZZ_CFLAGS}
			FUZZ_LIBS=${FUZZ_LIBS-}
		],
		[
			NL_CHECK_LINKER_ARG(
				[-fsanitize-coverage=edge,indirect-calls,8bit-counters -fsanitize=address -lFuzzer],[NL_FUZZ_SOURCE],
				[
					FUZZ_CFLAGS=${FUZZ_CFLAGS--fsanitize-coverage=edge,indirect-calls,8bit-counters -fsanitize=address}
					FUZZ_CXXFLAGS=${FUZZ_CXXFLAGS-$FUZZ_CFLAGS}
					FUZZ_LDFLAGS=${FUZZ_LDFLAGS-$FUZZ_CFLAGS}
					FUZZ_LIBS=${FUZZ_LIBS--lFuzzer}
				],
				AC_MSG_ERROR([Cannot figure out how to enable libFuzzer])
			)
		]
	)
	AC_LANG_POP(C++)
	fi
	FUZZ_CPPFLAGS="${FUZZ_CPPFLAGS} -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1"
fi

AC_SUBST(FUZZ_CFLAGS)
AC_SUBST(FUZZ_CXXFLAGS)
AC_SUBST(FUZZ_CPPFLAGS)
AC_SUBST(FUZZ_LDFLAGS)
AC_SUBST(FUZZ_LIBS)
])

AC_DEFUN([NL_CHECK_BOOST_SIGNALS2], [
	AC_LANG_PUSH([C++])

	AC_ARG_VAR([BOOST_CXXFLAGS], [C compiler flags for boost])
	AC_ARG_VAR([BOOST_LIBS], [linker flags for boost])

	boost_internal_cxxflags="-I$(cd $srcdir && pwd)/third_party/boost -DBOOST_NO_CXX11_VARIADIC_TEMPLATES -DBOOST_NO_CXX11_HDR_ARRAY -DBOOST_NO_CXX11_HDR_CODECVT -DBOOST_NO_CXX11_HDR_CONDITION_VARIABLE -DBOOST_NO_CXX11_HDR_FORWARD_LIST -DBOOST_NO_CXX11_HDR_INITIALIZER_LIST -DBOOST_NO_CXX11_HDR_MUTEX -DBOOST_NO_CXX11_HDR_RANDOM -DBOOST_NO_CXX11_HDR_RATIO -DBOOST_NO_CXX11_HDR_REGEX -DBOOST_NO_CXX11_HDR_SYSTEM_ERROR -DBOOST_NO_CXX11_HDR_THREAD -DBOOST_NO_CXX11_HDR_TUPLE -DBOOST_NO_CXX11_HDR_TYPEINDEX -DBOOST_NO_CXX11_HDR_UNORDERED_MAP -DBOOST_NO_CXX11_HDR_UNORDERED_SET -DBOOST_NO_CXX11_NUMERIC_LIMITS -DBOOST_NO_CXX11_ALLOCATOR -DBOOST_NO_CXX11_SMART_PTR -DBOOST_NO_CXX11_HDR_FUNCTIONAL -DBOOST_NO_CXX11_STD_ALIGN -DBOOST_NO_CXX11_ADDRESSOF -DBOOST_NO_CXX11_DECLTYPE_N3276 -Wp,-w"

	AC_ARG_WITH(
		[boost],
		AC_HELP_STRING([--with-boost=internal], [Use internal copy of boost])
	)

	with_boost=${with_boost-yes}

	case ${with_boost} in
		no)
			$2
			;;
		internal)
			BOOST_CXXFLAGS="${boost_internal_cxxflags}"
			$1
			;;
		yes)
			if test -z "${BOOST_CXXFLAGS}"
			then
				# If BOOST_CFLAGS was set for some reason, merge them into BOOST_CXXFLAGS.
				test -n "${BOOST_CFLAGS}" && BOOST_CXXFLAGS="${BOOST_CXXFLAGS} ${BOOST_CFLAGS}"

				# Go ahead and add the BOOST_CPPFLAGS into CFLAGS for now.
				nl_check_boost_signals2_CXXFLAGS="${CXXFLAGS}"
				nl_check_boost_signals2_CPPFLAGS="${CPPFLAGS}"
				CXXFLAGS+=" ${BOOST_CXXFLAGS}"
				CPPFLAGS+=" ${BOOST_CXXFLAGS}"

				AC_CHECK_HEADERS([boost/signals2/signal.hpp], [$1],[

					# Sometimes boost explicitly needs this flag to work.
					AX_CHECK_COMPILE_FLAG([-std=c++11], [
						CXXFLAGS="$CXXFLAGS -std=c++11"
						CPPFLAGS="$CPPFLAGS -std=c++11"
						BOOST_CXXFLAGS="$BOOST_CXXFLAGS -std=c++11"
					], [$2])

					## Clear the cache entry we that we try again
					unset ac_cv_header_boost_signals2_signal_hpp

					AC_CHECK_HEADERS([boost/signals2/signal.hpp], [$1], [
						with_boost=internal
						BOOST_CXXFLAGS="${boost_internal_cxxflags}"
						CXXFLAGS="${nl_check_boost_signals2_CXXFLAGS} ${BOOST_CXXFLAGS}"
						CPPFLAGS="${nl_check_boost_signals2_CPPFLAGS} ${BOOST_CXXFLAGS}"
						unset ac_cv_header_boost_signals2_signal_hpp
						AC_CHECK_HEADERS([boost/signals2/signal.hpp], [
							$1
							with_boost=internal
						], [
							$2
						])
					])
				])

				CXXFLAGS="${nl_check_boost_signals2_CXXFLAGS}"
				unset nl_check_boost_signals2_CXXFLAGS

				CPPFLAGS="${nl_check_boost_signals2_CPPFLAGS}"
				unset nl_check_boost_signals2_CPPFLAGS
			fi

			;;
		*)
			BOOST_CXXFLAGS="-I${with_boost}"
			;;
	esac

	AC_SUBST(BOOST_CXXFLAGS)
	AC_SUBST(BOOST_LIBS)

	AC_LANG_POP([C++])
])

AC_DEFUN([NL_CHECK_BOOST_CHRONO], [
	AC_LANG_PUSH([C++])

	AC_ARG_VAR([BOOST_CXXFLAGS], [C compiler flags for boost])
	AC_ARG_VAR([BOOST_LIBS], [linker flags for boost])

	boost_internal_cxxflags="-I$(cd $srcdir && pwd)/third_party/boost -DBOOST_NO_CXX11_VARIADIC_TEMPLATES -DBOOST_NO_CXX11_HDR_ARRAY -DBOOST_NO_CXX11_HDR_CODECVT -DBOOST_NO_CXX11_HDR_CONDITION_VARIABLE -DBOOST_NO_CXX11_HDR_FORWARD_LIST -DBOOST_NO_CXX11_HDR_INITIALIZER_LIST -DBOOST_NO_CXX11_HDR_MUTEX -DBOOST_NO_CXX11_HDR_RANDOM -DBOOST_NO_CXX11_HDR_RATIO -DBOOST_NO_CXX11_HDR_REGEX -DBOOST_NO_CXX11_HDR_SYSTEM_ERROR -DBOOST_NO_CXX11_HDR_THREAD -DBOOST_NO_CXX11_HDR_TUPLE -DBOOST_NO_CXX11_HDR_TYPEINDEX -DBOOST_NO_CXX11_HDR_UNORDERED_MAP -DBOOST_NO_CXX11_HDR_UNORDERED_SET -DBOOST_NO_CXX11_NUMERIC_LIMITS -DBOOST_NO_CXX11_ALLOCATOR -DBOOST_NO_CXX11_SMART_PTR -DBOOST_NO_CXX11_HDR_FUNCTIONAL -DBOOST_NO_CXX11_STD_ALIGN -DBOOST_NO_CXX11_ADDRESSOF -DBOOST_NO_CXX11_DECLTYPE_N3276 -Wp,-w"

	AC_ARG_WITH(
		[boost],
		AC_HELP_STRING([--with-boost=internal], [Use internal copy of boost])
	)

	with_boost=${with_boost-yes}

	case ${with_boost} in
		no)
			$2
			;;
		internal)
			BOOST_CXXFLAGS="${boost_internal_cxxflags}"
			$1
			;;
		yes)
			if test -z "${BOOST_CXXFLAGS}"
			then
				# If BOOST_CFLAGS was set for some reason, merge them into BOOST_CXXFLAGS.
				test -n "${BOOST_CFLAGS}" && BOOST_CXXFLAGS="${BOOST_CXXFLAGS} ${BOOST_CFLAGS}"

				# Go ahead and add the BOOST_CPPFLAGS into CFLAGS for now.
				nl_check_boost_chrono_CXXFLAGS="${CXXFLAGS}"
				nl_check_boost_chrono_CPPFLAGS="${CPPFLAGS}"
				CXXFLAGS+=" ${BOOST_CXXFLAGS}"
				CPPFLAGS+=" ${BOOST_CXXFLAGS}"

				AC_CHECK_HEADERS([boost/chrono/chrono.hpp], [$1],[

					# Sometimes boost explicitly needs this flag to work.
					AX_CHECK_COMPILE_FLAG([-std=c++11], [
						CXXFLAGS="$CXXFLAGS -std=c++11"
						CPPFLAGS="$CPPFLAGS -std=c++11"
						BOOST_CXXFLAGS="$BOOST_CXXFLAGS -std=c++11"
					], [$2])

					## Clear the cache entry we that we try again
					unset ac_cv_header_boost_chrono_chrono_hpp

					AC_CHECK_HEADERS([boost/chrono/chrono.hpp], [$1], [
						with_boost=internal
						BOOST_CXXFLAGS="${boost_internal_cxxflags}"
						CXXFLAGS="${nl_check_boost_chrono_CXXFLAGS} ${BOOST_CXXFLAGS}"
						CPPFLAGS="${nl_check_boost_chrono_CPPFLAGS} ${BOOST_CXXFLAGS}"
						unset ac_cv_header_boost_chrono_chrono_hpp
						AC_CHECK_HEADERS([boost/chrono/chrono.hpp], [
							$1
							with_boost=internal
						], [
							$2
						])
					])
				])

				CXXFLAGS="${nl_check_boost_chrono_CXXFLAGS}"
				unset nl_check_boost_chrono_CXXFLAGS

				CPPFLAGS="${nl_check_boost_chrono_CPPFLAGS}"
				unset nl_check_boost_chrono_CPPFLAGS
			fi

			;;
		*)
			BOOST_CXXFLAGS="-I${with_boost}"
			;;
	esac

	AC_SUBST(BOOST_CXXFLAGS)
	AC_SUBST(BOOST_LIBS)

	AC_LANG_POP([C++])
])

AC_DEFUN([NL_CHECK_READLINE], [
	AC_LANG_PUSH([C])

	readline_required=no

	AC_ARG_WITH(
		[readline],
		AC_HELP_STRING([--without-readline], [Don't use libreadline or libedit])
	)

	if test "${with_readline}" '!=' "no"
	then
		if test "${with_readline}" '=' "yes"
		then unset with_readline;
			readline_required=yes
		fi

		temp_LIBS="${LIBS}"
		temp_CPPFLAGS="${CPPFLAGS}"
		LIBS="${LIBREADLINE_LIBS}"
		CPPFLAGS="${LIBREADLINE_CPPFLAGS} ${LIBREADLINE_CFLAGS}"

		AC_CHECK_HEADER(
			[readline/readline.h],
			[
				AC_SEARCH_LIBS(waddstr, [ncurses cursesX curses])
				AC_SEARCH_LIBS(tgetstr, [tinfo])
				AC_SEARCH_LIBS(
					[readline],
					[${with_readline-readline edit}],
					[with_readline=yes]
				)
			]
		)

		if test "x$with_readline" = "xyes"
		then
			LIBREADLINE_LIBS="${LIBS}"
			LIBREADLINE_CPPFLAGS="${CPPFLAGS}"
			AC_DEFINE([HAVE_LIBREADLINE], [1], [Define to 1 if we have libreadline or libedit])
		fi

		CPPFLAGS="${temp_CPPFLAGS}"
		LIBS="${temp_LIBS}"
	else
		LIBREADLINE_LIBS=""
		LIBREADLINE_CPPFLAGS=""
	fi

	AC_SUBST(LIBREADLINE_LIBS)
	AC_SUBST(LIBREADLINE_CPPFLAGS)
	AM_CONDITIONAL([HAVE_LIBREADLINE],[test "x$with_readline" = "xyes"])

	if test "x$with_readline" = "xyes"
	then true; $1
	elif test "x$readline_required" = "xyes"
	then false; AC_MSG_ERROR(["libreadline or libedit was explicitly requested but was unable to figure out how to use either"])
	else false; $2
	fi

	AC_LANG_POP([C])
])

AC_DEFUN([NL_CHECK_DBUS], [
	PKG_CHECK_MODULES(DBUS, dbus-1 >= 1.4, [$1], [$2])
	AC_SUBST(DBUS_CFLAGS)
	AC_SUBST(DBUS_LIBS)

	AC_ARG_WITH(dbusconfdir,
		AC_HELP_STRING([--with-dbusconfdir=PATH], [path to D-Bus config directory]),
		[path_dbusconf=${withval}],
		[
			if test "$prefix" = "`$PKG_CONFIG --variable=prefix dbus-1`"
			then path_dbusconf="`$PKG_CONFIG --variable=sysconfdir dbus-1`"
			fi
		]
	)
	if (test -z "${path_dbusconf}"); then
		if test "${prefix}" = "/usr/local" && test "${sysconfdir}" = '${prefix}/etc' && test -d /etc/dbus-1/system.d
		then DBUS_CONFDIR='/etc/dbus-1/system.d'
		else DBUS_CONFDIR='${sysconfdir}/dbus-1/system.d'
		fi
	else
		[path_dbusconf="$(echo ${path_dbusconf} | sed 's:^'"${prefix}"':${prefix}:')" ; ]
		[path_dbusconf="$(echo ${path_dbusconf} | sed 's:^'"${sysconfdir}"':${sysconfdir}:')" ; ]
		DBUS_CONFDIR="${path_dbusconf}/dbus-1/system.d"
	fi
	AC_SUBST(DBUS_CONFDIR)

	AC_ARG_WITH(dbusdatadir, AC_HELP_STRING([--with-dbusdatadir=PATH],
		[path to D-Bus data directory]), [path_dbusdata=${withval}],
		[
			if test "$prefix" = "`$PKG_CONFIG --variable=prefix dbus-1`"
			then path_dbusdata="`$PKG_CONFIG --variable=datadir dbus-1`"
			fi
		]
	)
	if (test -z "${path_dbusdata}"); then
		DBUS_DATADIR='${datadir}/dbus-1/system-services'
	else
		[path_dbusconf="$(echo ${path_dbusdata} | sed 's:^'"${prefix}"':${prefix}:')" ; ]
		[path_dbusconf="$(echo ${path_dbusdata} | sed 's:^'"${datadir}"':${datadir}:')" ; ]
		DBUS_DATADIR="${path_dbusdata}/dbus-1/system-services"
	fi
	AC_SUBST(DBUS_DATADIR)
])

AC_DEFUN([NL_CHECK_LIBDL], [
	HAVE_LIBDL=false
	AC_ARG_WITH(libdl,AC_HELP_STRING([--without-libdl], [Do not use libdl]))
	if test "${with_libdl-yes}" '!=' 'no'; then :
		AC_CHECK_HEADER(
			[dlfcn.h],
			AC_CHECK_LIB([dl], [dlsym], [
				HAVE_LIBDL=true
				LIBDL_LIBS="-ldl"
			],
				AC_CHECK_LIB([ltdl], [dlsym], [
					HAVE_LIBDL=true
					LIBDL_LIBS="-lltdl"
				])
			)
		)
	fi
	AC_SUBST(LIBDL_LIBS)
])


AC_DEFUN([NL_CHECK_CONNMAN], [
	AC_ARG_WITH(
		[connman],
		[AC_HELP_STRING([--without-connman], [Don't build connman plugin])],
		[
			if test "x${with_connman}" '=' "xyes" -o "x${with_connman}" '=' "xforce"
			then require_connman=yes
			fi
		]
	)

	if test "x${with_connman}" '==' "xforce"
	then
		with_connman=yes
		if test "x${CONNMAN_LIBS}" == "x"
		then CONNMAN_LIBS="-module -avoid-version -export-symbols-regex connman_plugin_desc"
		fi
	elif test "x${with_connman}" '!=' "xno"
	then
		if test "x${with_connman}" '==' "xforce"
		then
			true
		elif test "x${CONNMAN_CFLAGS}" '==' "x"
		then
			PKG_CHECK_MODULES(
				[CONNMAN],
				[connman >= 1.0],
				[with_connman=yes],
				[with_connman=no]
			)
		else
			# CONNMAN_CFLAGS was given manually.
			prev_CPPFLAGS="${CPPFLAGS}"
			CPPFLAGS="${CPPFLAGS} ${CONNMAN_CFLAGS}"
			AC_CHECK_HEADERS([connman/plugin.h],[with_connman=yes],[with_connman=no])
			CPPFLAGS="${prev_CPPFLAGS}"
			unset prev_CPPFLAGS

			if test "x${CONNMAN_LIBS}" == "x"
			then CONNMAN_LIBS="-module -avoid-version -export-symbols-regex connman_plugin_desc"
			fi
		fi
	fi

	if test "x${with_connman}" == "xyes" -a "x${GLIB_CFLAGS}" '==' "x"
	then PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.28, [],[AC_MSG_ERROR(["Found ConnMan headers but couldn't find GLIB"])])
	fi

	AC_SUBST(CONNMAN_CFLAGS)
	AC_SUBST(CONNMAN_LIBS)
	AC_SUBST(GLIB_CFLAGS)
	AC_SUBST(GLIB_LIBS)

	if test "x${with_connman}" != "xno"
	then {
		GLIB_CFLAGS="${GLIB_CFLAGS} -DGLIB_VERSION_MAX_ALLOWED=138240 -DGLIB_VERSION_MIN_REQUIRED=138240"

		$1
	}
	elif test "x$require_connman" = "xyes"
	then false; AC_MSG_ERROR(["ConnMan plugin was explicitly requested but cannot find ConnMan headers"])
	else false; $2
	fi
])

dnl Unix Pseudoterminal Support
AC_DEFUN([NL_CHECK_PTS], [
	AC_CHECK_LIB([util], [forkpty])
	AC_CHECK_HEADERS([pty.h util.h phy.h])
	AM_CONDITIONAL([_XOPEN_SOURCE],[true])
	AC_CHECK_FUNCS([forkpty ptsname], [$1], [$2])
])

AC_DEFUN([NL_APPEND_NETWORK_TIME_RECEIVED_MONOTONIC_TIMESTAMP], [
AC_ARG_ENABLE(
append-network-time-received-timestamp,
	AC_HELP_STRING(
		[--enable-append-network-time-received-timestamp],
		[Append received monotonic timestamp to incoming network time]
	)
)
AM_CONDITIONAL([APPEND_NETWORK_TIME_RECEIVED_MONOTONIC_TIMESTAMP],[(case "${enable_append_network_time_received_timestamp}" in yes) true ;; *) false ;; esac)])
])