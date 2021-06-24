cmake_minimum_required(VERSION 3.5)
project(pam_visa C)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
set(CMAKE_CXX_STANDARD 11)

find_package(PAM REQUIRED)
find_package(SSL REQUIRED)

file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/build)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build)

enable_testing()
add_subdirectory(tests)

file(GLOB_RECURSE SOURCES src/*.c src/.h)

set(CMAKE_SHARED_MODULE_PREFIX "")


add_library(${PROJECT_NAME} MODULE ${SOURCES})

target_link_libraries(
    ${PROJECT_NAME}
    ${PAM_LIBRARIES}
    ${SSL_LIBRARIES}
)


# install the module in the same place where all the other modules should be
# NOTE: we actually disrespect the install prefix here
if(NOT DEFINED CMAKE_INSTALL_LIBDIR)
    get_filename_component(CMAKE_INSTALL_LIBDIR ${PAM_LIBRARY} DIRECTORY)
endif()
install(TARGETS ${PROJECT_NAME}
    LIBRARY DESTINATION "/lib/x86_64-linux-gnu/security/"
)

SET(CPACK_GENERATOR "DEB")
SET(CPACK_PACKAGE_VERSION_MAJOR 1)
SET(CPACK_PACKAGE_VERSION_MINOR 0)
SET(CPACK_PACKAGE_VERSION_PATCH 2)
SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "visa@ill.fr") #required
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Linux PAM module to enable authentication through the verification of a signature against a public key")
INCLUDE(CPack)
