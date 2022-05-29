CollectSourceFiles(
  ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE_SOURCES
  # Exclude
  )

GroupSources(${CMAKE_CURRENT_SOURCE_DIR})

# Declare target
add_library(dreadful-plugin-shared-base
  STATIC
    ${PRIVATE_SOURCES}
)

CollectIncludeDirectories(${CMAKE_CURRENT_SOURCE_DIR}
  PUBLIC_INCLUDES
)

target_include_directories(dreadful-plugin-shared-base
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
)

target_compile_options(dreadful-plugin-shared-base
  PUBLIC
    "$<$<CXX_COMPILER_ID:MSVC>:/Zc:__cplusplus>"
    "$<$<CXX_COMPILER_ID:MSVC>:/wd4624>" # warning C4624: 'identifier': destructor was implicitly defined as deleted
    "$<$<CXX_COMPILER_ID:MSVC>:/wd4291>" # warning C4291: 'identifier': no matching operator delete found; memory will not be freed if initialization throws an exception
)

set_target_properties(dreadful-plugin-shared-base PROPERTIES LINKER_LANGUAGE CXX)

target_compile_features(dreadful-plugin-shared-base PUBLIC cxx_std_20)
