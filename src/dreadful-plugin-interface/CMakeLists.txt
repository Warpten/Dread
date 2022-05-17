CollectSourceFiles(
  ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE_SOURCES
  # Exclude
  )

GroupSources(${CMAKE_CURRENT_SOURCE_DIR})

add_ida_library(dreadful-plugin-interface
  ${PRIVATE_SOURCES}
)

add_dependencies(dreadful-plugin-interface ast-parser)

target_include_directories(dreadful-plugin-interface
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR})

if (MSVC)
  target_compile_options(dreadful-plugin-interface PUBLIC "/Zc:__cplusplus")
endif()

target_compile_features(dreadful-plugin-interface PUBLIC cxx_std_20)
