# - Try to find the Open ssl library (ssl)
#
# Once done this will define
#
#  SSL_FOUND - System has gnutls
#  SSL_INCLUDE_DIR - The gnutls include directory
#  SSL_LIBRARIES - The libraries needed to use gnutls
#  SSL_DEFINITIONS - Compiler switches required for using gnutls


if (SSL_INCLUDE_DIR AND SSL_LIBRARIES)
	# in cache already
	SET(SSL_FIND_QUIETLY TRUE)
endif (SSL_INCLUDE_DIR AND SSL_LIBRARIES)

find_path(SSL_INCLUDE_DIR openssl/opensslv.h)

find_library(SSL_LIBRARIES crypto)

include(FindPackageHandleStandardArgs)

# handle the QUIETLY and REQUIRED arguments and set SSL_FOUND to TRUE if
# all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(SSL DEFAULT_MSG SSL_LIBRARIES SSL_INCLUDE_DIR)

mark_as_advanced(SSL_INCLUDE_DIR SSL_LIBRARIES)
