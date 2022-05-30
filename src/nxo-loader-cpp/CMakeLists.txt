CollectSourceFiles(
  ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE_SOURCES
  # Exclude
  )

GroupSources(${CMAKE_CURRENT_SOURCE_DIR})

add_ida_plugin(nxo-loader-cpp
  ${PRIVATE_SOURCES}
)

add_dependencies(nxo-loader-cpp
  dreadful-plugin-ida-base
)

target_link_libraries(nxo-loader-cpp
  PRIVATE
    dreadful-plugin-ida-base
)

target_include_directories(nxo-loader-cpp
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR})

if (MSVC)
  target_compile_options(nxo-loader-cpp PUBLIC "/Zc:__cplusplus")
endif()

target_compile_features(nxo-loader-cpp PUBLIC cxx_std_20)

add_custom_command(TARGET nxo-loader-cpp POST_BUILD
  COMMAND
    ${CMAKE_COMMAND} -E copy 
      $<TARGET_FILE:dreadful-plugin-dump> 
      "${IDA_INSTALL_DIR}/loaders"
  COMMENT
    "$(TargetFileName) -> ${IDA_INSTALL_DIR}/loaders ..."
  VERBATIM
)
