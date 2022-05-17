CollectSourceFiles(
  ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE_SOURCES
  # Exclude
)

CollectIncludeDirectories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  PUBLIC_INCLUDES
)

GroupSources(${CMAKE_CURRENT_SOURCE_DIR})

# Declare both targets
add_ida_plugin(dreadful-plugin
  ${PRIVATE_SOURCES}
)

add_dependencies(dreadful-plugin
  ast-parser
  dreadful-plugin-interface
)

target_include_directories(dreadful-plugin
  PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
)

target_compile_definitions(dreadful-plugin
  PRIVATE
    IDA_INCLUDE_DIR="${IDA_LIB_DIR}"
)

target_link_libraries(dreadful-plugin
  PRIVATE
    ast-parser
    dreadful-plugin-interface
)

target_compile_features(dreadful-plugin
  PUBLIC
    cxx_std_20
)

set_target_properties(dreadful-plugin PROPERTIES 
  OUTPUT_NAME "dreadful_plugin"
)

add_custom_command(TARGET dreadful-plugin POST_BUILD
  COMMAND
    ${CMAKE_COMMAND} -E copy 
      $<TARGET_FILE:dreadful-plugin> 
      "${IDA_INSTALL_DIR}/plugins"
  COMMENT
    "Moved $(TargetFileName) to ${IDA_INSTALL_DIR}/plugins ..."
  VERBATIM
)
