# - Try to find the CHECK libraries
#  Once done this will define
#
#  CHECK_FOUND - system has check
#  CHECK_INCLUDE_DIRS - the check include directory
#  CHECK_LIBRARIES - check library
#
#  Copyright (c) 2007 Daniel Gollub <gollub@b1-systems.de>
#  Copyright (c) 2007-2009 Bjoern Ricks  <bjoern.ricks@gmail.com>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.


INCLUDE( FindPkgConfig )

IF ( Check_FIND_REQUIRED )
	SET( _pkgconfig_REQUIRED "REQUIRED" )
ELSE( Check_FIND_REQUIRED )
	SET( _pkgconfig_REQUIRED "" )
ENDIF ( Check_FIND_REQUIRED )

IF ( CHECK_MIN_VERSION )
	pkg_search_module( CHECK ${_pkgconfig_REQUIRED} check>=${CHECK_MIN_VERSION} )
ELSE ( CHECK_MIN_VERSION )
	pkg_search_module( CHECK ${_pkgconfig_REQUIRED} check )
ENDIF ( CHECK_MIN_VERSION )

# Hide advanced variables from CMake GUIs
MARK_AS_ADVANCED( CHECK_INCLUDE_DIRS CHECK_LIBRARIES )

