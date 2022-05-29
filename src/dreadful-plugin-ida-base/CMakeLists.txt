CollectSourceFiles(
  ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE_SOURCES
  # Exclude
  )

GroupSources(${CMAKE_CURRENT_SOURCE_DIR})

add_ida_library(dreadful-plugin-ida-base
  ${PRIVATE_SOURCES}
)

target_compile_definitions(dreadful-plugin-ida-base
  PRIVATE
    IDA_INCLUDE_DIR="${IDA_LIB_DIR}"
)

add_dependencies(dreadful-plugin-clang-base
  dreadful-plugin-shared-base
)

target_link_libraries(dreadful-plugin-ida-base
  PUBLIC
    dreadful-plugin-shared-base
)

target_include_directories(dreadful-plugin-ida-base
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR})

if (MSVC)
  target_compile_options(dreadful-plugin-ida-base PUBLIC "/Zc:__cplusplus")
endif()

target_compile_features(dreadful-plugin-ida-base PUBLIC cxx_std_20)
