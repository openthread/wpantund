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

AC_DEFUN([NL_EXPORT_DYNAMIC], [
	prev_LDFLAGS="${LDFLAGS}"
	LDFLAGS="-Wl,--export-dynamic"
	AC_LANG_PUSH([C])
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
	AC_LANG_POP([C])
])

AC_DEFUN([NL_CHECK_BOOST_SIGNALS2], [
	AC_LANG_PUSH([C++])

	AC_ARG_VAR([BOOST_CXXFLAGS], [C compiler flags for boost])
	AC_ARG_VAR([BOOST_LIBS], [linker flags for boost])

	if [ -z "${BOOST_CXXFLAGS}" ]
	then
		# If BOOST_CFLAGS was set for some reason, merge them into BOOST_CXXFLAGS.
		test -n "${BOOST_CFLAGS}" && BOOST_CXXFLAGS="${BOOST_CXXFLAGS} ${BOOST_CFLAGS}"

		# Go ahead and add the BOOST_CPPFLAGS into CFLAGS for now.
		nl_check_boost_signals2_CXXFLAGS="${CXXFLAGS}"
		nl_check_boost_signals2_CPPFLAGS="${CPPFLAGS}"
		CXXFLAGS="${BOOST_CXXFLAGS}"
		CPPFLAGS="${BOOST_CXXFLAGS}"

		AC_CHECK_HEADERS([boost/signals2/signal.hpp], [$1],[

			# Sometimes boost explicitly needs this flag to work.
			AX_CHECK_COMPILE_FLAG([-std=c++11], [
				CXXFLAGS="$CXXFLAGS -std=c++11"
				CPPFLAGS="$CPPFLAGS -std=c++11"
				BOOST_CXXFLAGS="$BOOST_CXXFLAGS -std=c++11"
			], [$2])

			## Clear the cache entry we that we try again
			unset ac_cv_header_boost_signals2_signal_hpp

			AC_CHECK_HEADERS([boost/signals2/signal.hpp], [$1], [$2])
		])

		CXXFLAGS="${nl_check_boost_signals2_CXXFLAGS}"
		unset nl_check_boost_signals2_CXXFLAGS

		CPPFLAGS="${nl_check_boost_signals2_CPPFLAGS}"
		unset nl_check_boost_signals2_CPPFLAGS
	fi

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
			if test "x${with_connman}" '=' "xyes"
			then require_connman=yes
			fi
		]
	)

	if test "x${with_connman}" '!=' "xno"
	then
		if test "x${CONNMAN_CFLAGS}" '==' "x"
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
			AC_CHECK_HEADERS([connman/version.h],[with_connman=yes],[with_connman=no])
			CPPFLAGS="${prev_CPPFLAGS}"
			unset prev_CPPFLAGS

			if test "x${CONNMAN_LIBS}" == "x"
			then CONNMAN_LIBS="-module -avoid-version -export-symbols-regex connman_plugin_desc"
			fi
		fi
	fi

	AC_SUBST(CONNMAN_CFLAGS)
	AC_SUBST(CONNMAN_LIBS)

	if test "x${with_connman}" = "xyes"
	then {
		$1
	}
	elif test "x$require_connman" = "xyes"
	then false; AC_MSG_ERROR(["ConnMan plugin was explicitly requested, but can't find ConnMan headers"])
	else false; $2
	fi
])

AC_DEFUN([NL_CHECK_GLIB], [
	PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.28, [$1], [$2])

	GLIB_CFLAGS="${GLIB_CFLAGS} -DGLIB_VERSION_MAX_ALLOWED=138240 -DGLIB_VERSION_MIN_REQUIRED=138240"

	AC_SUBST(GLIB_CFLAGS)
	AC_SUBST(GLIB_LIBS)
])

dnl Unix Pseudoterminal Support
AC_DEFUN([NL_CHECK_PTS], [
	AC_CHECK_LIB([util], [forkpty])
	AC_CHECK_HEADERS([pty.h util.h phy.h])
	AM_CONDITIONAL([_XOPEN_SOURCE],[true])
	AC_CHECK_FUNCS([forkpty ptsname], [$1], [$2])
])
