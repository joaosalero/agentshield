cmake_minimum_required(VERSION 3.20)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
             "${CMAKE_CURRENT_SOURCE_DIR}/VERSION"
             "${CMAKE_CURRENT_SOURCE_DIR}/scripts/read_version.py")
execute_process(COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/scripts/read_version.py"
                        "${CMAKE_CURRENT_SOURCE_DIR}/VERSION"
                OUTPUT_VARIABLE AGENTSHIELD_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE
                RESULT_VARIABLE VERSION_RESULT ERROR_VARIABLE VERSION_ERROR)
if(NOT VERSION_RESULT EQUAL 0)
  message(FATAL_ERROR "Invalid VERSION: ${VERSION_ERROR}")
endif()
project(AgentShield VERSION ${AGENTSHIELD_VERSION} LANGUAGES C CXX)
include(GNUInstallDirs)
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "AgentShield 0.1 native sensor supports Linux only; see docs/PLATFORM_SUPPORT.md")
endif()
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
find_package(Java 17 REQUIRED COMPONENTS Development)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_library(agentshield_sensor STATIC core/src/sensor_linux.c)
target_include_directories(agentshield_sensor PUBLIC core/include)
add_library(agentshield_engine STATIC engine/src/risk_engine.cpp engine/src/audit_log.cpp)
target_include_directories(agentshield_engine PUBLIC engine/include)
target_link_libraries(agentshield_engine PUBLIC agentshield_sensor OpenSSL::Crypto)
add_executable(agentshield cli/src/main.cpp)
target_link_libraries(agentshield PRIVATE agentshield_engine)
target_compile_definitions(agentshield PRIVATE AGENTSHIELD_VERSION="${PROJECT_VERSION}")
foreach(target agentshield_sensor agentshield_engine agentshield)
  target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
endforeach()

set(DESKTOP_CLASSES "${CMAKE_CURRENT_BINARY_DIR}/desktop-classes")
set(DESKTOP_JAR "${CMAKE_CURRENT_BINARY_DIR}/agentshield-desktop.jar")
add_custom_command(OUTPUT "${DESKTOP_JAR}"
  COMMAND "${CMAKE_COMMAND}" -E make_directory "${DESKTOP_CLASSES}"
  COMMAND "${Java_JAVAC_EXECUTABLE}" --release 17 -d "${DESKTOP_CLASSES}"
          "${CMAKE_CURRENT_SOURCE_DIR}/desktop/src/main/java/io/agentshield/DesktopApp.java"
  COMMAND "${Java_JAR_EXECUTABLE}" --create --file "${DESKTOP_JAR}"
          --main-class io.agentshield.DesktopApp -C "${DESKTOP_CLASSES}" .
  DEPENDS desktop/src/main/java/io/agentshield/DesktopApp.java
  VERBATIM)
add_custom_target(agentshield_desktop ALL DEPENDS "${DESKTOP_JAR}")
include(CTest)
if(BUILD_TESTING)
  add_executable(test_risk tests/test_risk.cpp)
  target_link_libraries(test_risk PRIVATE agentshield_engine)
  add_test(NAME risk_engine COMMAND test_risk)
endif()

install(TARGETS agentshield RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(PROGRAMS scripts/agentshield-desktop DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES "${DESKTOP_JAR}" DESTINATION ${CMAKE_INSTALL_LIBDIR}/agentshield)
install(FILES packaging/linux/io.agentshield.AgentShield.desktop
        DESTINATION ${CMAKE_INSTALL_DATADIR}/applications)
install(FILES packaging/linux/io.agentshield.AgentShield.svg
        DESTINATION ${CMAKE_INSTALL_DATADIR}/icons/hicolor/scalable/apps)
install(FILES packaging/linux/io.agentshield.AgentShield.metainfo.xml
        DESTINATION ${CMAKE_INSTALL_DATADIR}/metainfo)
install(FILES policies/baseline.policy policies/observe.policy
        DESTINATION ${CMAKE_INSTALL_DATADIR}/agentshield/policies)
install(FILES README.md SECURITY.md CONTRIBUTING.md docs/AUDIT.md docs/POLICY.md
        docs/PRIVACY.md docs/SECURITY_ARCHITECTURE.md docs/THREAT_MODEL.md
        docs/VALIDATION.md docs/DISTRIBUTION.md docs/PLATFORM_SUPPORT.md
        docs/AI_AND_DATA_SCIENCE.md
        DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(FILES LICENSE VERSION DESTINATION ${CMAKE_INSTALL_DOCDIR})

set(CPACK_PACKAGE_NAME "agentshield")
set(CPACK_PACKAGE_VENDOR "AgentShield")
set(CPACK_PACKAGE_CONTACT "AgentShield maintainers")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Runtime security visibility and policy enforcement for AI agents")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_GENERATOR "TGZ;DEB")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "openjdk-17-jre | default-jre")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_ARCHIVE_FILE_NAME "agentshield-${PROJECT_VERSION}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")
include(CPack)
