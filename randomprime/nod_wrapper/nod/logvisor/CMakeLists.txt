include (CMakePackageConfigHelpers)

include_directories(include)
add_library(logvisor
            lib/logvisor.cpp
            include/logvisor/logvisor.hpp)

set(LOGVISOR_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include CACHE PATH "logvisor include path" FORCE)

install(DIRECTORY include/logvisor DESTINATION include) 

set(version_config_file "${PROJECT_BINARY_DIR}/logvisorConfigVersion.cmake")
set(config_file "${PROJECT_BINARY_DIR}/logvisorConfig.cmake")
set(config_install_dir "lib/cmake/logvisor")

# Associate target with export
install(
    TARGETS logvisor
    EXPORT logvisorTargets
    ARCHIVE DESTINATION "lib"
    INCLUDES DESTINATION include  # This sets the INTERFACE_INCLUDE_DIRECTORIES property of the target.
)

# Install the target config files
install(
    EXPORT logvisorTargets
    NAMESPACE "logvisor::"
    DESTINATION "${config_install_dir}"
)

# Generate version config file
write_basic_package_version_file(
    "${version_config_file}"
    COMPATIBILITY SameMajorVersion
)

# Generate config file
configure_package_config_file(
    "Config.cmake.in"
    "${config_file}"
    INSTALL_DESTINATION "lib/cmake/logvisor"
)

# Install the config files
install(
    FILES "${config_file}" "${version_config_file}"
    DESTINATION ${config_install_dir}
)
