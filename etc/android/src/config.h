/* src/config.h.  Generated from config.h.in by configure.  */
/* src/config.h.in.  Generated from configure.ac by autoheader.  */

/* Define to 0 to explicitly prevent squelching assert printouts */
#define ASSERT_MACROS_SQUELCH 0

/* Define to 1 to have assertmacros.h use syslog */
#define ASSERT_MACROS_USE_SYSLOG 1

/* Define to 1 if you have the `alloca' function. */
/* #undef HAVE_ALLOCA */

/* Define to 1 if you have the <asm/sigcontext.h> header file. */
#define HAVE_ASM_SIGCONTEXT_H 1

/* Define to 1 if you have the <boost/signals2/signal.hpp> header file. */
/* #undef HAVE_BOOST_SIGNALS2_SIGNAL_HPP */

/* Define to 1 if you have the `clock_gettime' function. */
#define HAVE_CLOCK_GETTIME 1

/* Define to 1 if you have the <connman/version.h> header file. */
/* #undef HAVE_CONNMAN_VERSION_H */

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <errno.h> header file. */
#define HAVE_ERRNO_H 1

/* Define to 1 if you have the <execinfo.h> header file. */
/* #undef HAVE_EXECINFO_H */

/* Define to 1 if you have the `fgetln' function. */
#define HAVE_FGETLN 1

/* Define to 1 if you have the `forkpty' function. */
/* #undef HAVE_FORKPTY */

/* Define to 1 if you have the `getdtablesize' function. */
/* #undef HAVE_GETDTABLESIZE */

/* Define to 1 if you have the `getloadavg' function. */
/* #undef HAVE_GETLOADAVG */

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if we have libreadline or libedit */
/* #undef HAVE_LIBREADLINE */

/* Define to 1 if you have the `util' library (-lutil). */
/* #undef HAVE_LIBUTIL */

/* Define to 1 if you have the `memcmp' function. */
#define HAVE_MEMCMP 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `memset' function. */
#define HAVE_MEMSET 1

/* Define to 1 if you have the <phy.h> header file. */
/* #undef HAVE_PHY_H */

/* Define to 1 if you have the `ptsname' function. */
#define HAVE_PTSNAME 1

/* Define to 1 if you have the <pty.h> header file. */
/* #undef HAVE_PTY_H */

/* Define to 1 if you have the <pwd.h> header file. */
#define HAVE_PWD_H 1

/* Define to 1 if you have the `snprintf' function. */
#define HAVE_SNPRINTF 1

/* Define to 1 if you have the <stdbool.h> header file. */
#define HAVE_STDBOOL_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `stpncpy' function. */
#define HAVE_STPNCPY 1

/* Define to 1 if you have the `strdup' function. */
#define HAVE_STRDUP 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strlcat' function. */
#define HAVE_STRLCAT 1

/* Define to 1 if you have the `strlcpy' function. */
#define HAVE_STRLCPY 1

/* Define to 1 if you have the `strndup' function. */
#define HAVE_STRNDUP 1

/* Define to 1 if you have the `strtol' function. */
#define HAVE_STRTOL 1

/* Define to 1 if you have the <sys/prctl.h> header file. */
#define HAVE_SYS_PRCTL_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/un.h> header file. */
#define HAVE_SYS_UN_H 1

/* Define to 1 if you have the <sys/wait.h> header file. */
#define HAVE_SYS_WAIT_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the <util.h> header file. */
#define HAVE_UTIL_H 1

/* Define to 1 if you have the `vsnprintf' function. */
#define HAVE_VSNPRINTF 1

/* Define to 1 if you have the `vsprintf' function. */
#define HAVE_VSPRINTF 1

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* Name of package */
#define PACKAGE "wpantund"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "wpantund-devel@googlegroups.com"

/* Define to the full name of this package. */
#define PACKAGE_NAME "wpantund"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "wpantund 0.07.00"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "wpantund"

/* Define to the home page for this package. */
#define PACKAGE_URL "https://github.com/openthread/wpantund/"

/* Define to the version of this package. */
#define PACKAGE_VERSION "0.07.00"

/* Define to the sub-directory for plugins. */
#define PKGLIBEXECDIR "/usr/local/libexec/wpantund"

/* Define to the install prefix */
#define PREFIX "/usr/local"

/* Source version */
#define SOURCE_VERSION "0.07.00-177-g0b70ed2"

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define to the sub-directory for system settings. */
#define SYSCONFDIR "/usr/local/etc"

/* Define to 1 if you can safely include both <sys/time.h> and <time.h>. */
#define TIME_WITH_SYS_TIME 1

/* Version number of package */
#define VERSION "0.07.00"

/* Set to the name of the default NCP plugin */
#define WPANTUND_DEFAULT_NCP_PLUGIN "spinel"

/* Set to 1 if we are statically linking the plugin/ */
#define WPANTUND_PLUGIN_STATICLY_LINKED 1

/* Needed by C++ */
#define __STDC_CONSTANT_MACROS 1

/* Needed by C++ */
#define __STDC_LIMIT_MACROS 1

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef ssize_t */

/* Define to empty if the keyword `volatile' does not work. Warning: valid
   code using `volatile' can become incorrect without. Disable with care. */
/* #undef volatile */
