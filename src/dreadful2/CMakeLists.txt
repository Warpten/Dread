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
add_ida_plugin(dreadful2_plugin
  ${PRIVATE_SOURCES}
)

add_dependencies(dreadful2_plugin ast-parser)

target_include_directories(dreadful2_plugin
  PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
)

target_compile_definitions(dreadful2_plugin
  PRIVATE
    IDA_INCLUDE_DIR="${IDA_LIB_DIR}"
)

target_link_libraries(dreadful2_plugin
  ast-parser
)

if (MSVC)
  target_compile_options(dreadful2_plugin
    PRIVATE
      "/Zc:__cplusplus"
  )

  target_compile_options(dreadful2_plugin
    PUBLIC
      /wd4624 # warning C4624: 'identifier': destructor was implicitly defined as deleted
      /wd4291 # warning C4291: 'identifier': no matching operator delete found; memory will not be freed if initialization throws an exception
  )
endif()

target_compile_features(dreadful2_plugin
  PUBLIC
    cxx_std_20
)

add_custom_command(TARGET dreadful2_plugin POST_BUILD
  COMMAND
    ${CMAKE_COMMAND} -E copy 
      $<TARGET_FILE:dreadful2_plugin> 
      "${IDA_INSTALL_DIR}/plugins"
  COMMENT
    "Moved $(TargetFileName) to ${IDA_INSTALL_DIR}/plugins ..."
  VERBATIM
)
