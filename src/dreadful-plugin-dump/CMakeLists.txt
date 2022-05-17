CollectSourceFiles(
  ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE_SOURCES
  # Exclude
  )

GroupSources(${CMAKE_CURRENT_SOURCE_DIR})

add_ida_plugin(dreadful-plugin-dump
  ${PRIVATE_SOURCES}
)

add_dependencies(dreadful-plugin-dump
  dreadful-plugin-ida-base
)

target_link_libraries(dreadful-plugin-dump
  PRIVATE
    dreadful-plugin-ida-base
)

target_include_directories(dreadful-plugin-dump
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR})

if (MSVC)
  target_compile_options(dreadful-plugin-dump PUBLIC "/Zc:__cplusplus")
endif()

target_compile_features(dreadful-plugin-dump PUBLIC cxx_std_20)

add_custom_command(TARGET dreadful-plugin-dump POST_BUILD
  COMMAND
    ${CMAKE_COMMAND} -E copy 
      $<TARGET_FILE:dreadful-plugin-dump> 
      "${IDA_INSTALL_DIR}/plugins"
  COMMENT
    "Moved $(TargetFileName) to ${IDA_INSTALL_DIR}/plugins ..."
  VERBATIM
)
