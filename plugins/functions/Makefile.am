EXTRA_DIST =					\
	CMakeLists.txt

AM_CPPFLAGS =					\
	-I$(top_builddir)			\
	-I$(top_srcdir)/include			\
	-I$(top_srcdir)/lib

AM_LDFLAGS =					\
	-avoid-version				\
	-module					\
	-no-undefined

LIBS =						\
	$(top_builddir)/lib/libgroonga.la

function_plugins_LTLIBRARIES =
function_plugins_LTLIBRARIES += vector.la
function_plugins_LTLIBRARIES += string.la
function_plugins_LTLIBRARIES += number.la
function_plugins_LTLIBRARIES += time.la

include vector_sources.am
include string_sources.am
include number_sources.am
include time_sources.am

number_la_LIBADD = -lm
