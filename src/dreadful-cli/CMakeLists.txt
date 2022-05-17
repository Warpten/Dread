CollectSourceFiles(
  ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE_SOURCES
  # Exclude
  )

GroupSources(${CMAKE_CURRENT_SOURCE_DIR})

add_executable(dreadful-cli ${PRIVATE_SOURCES})

add_dependencies(dreadful-cli ast-parser)

target_link_libraries(dreadful-cli
  PRIVATE
    ast-parser
)

target_include_directories(dreadful-cli 
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR})

if (MSVC)
  target_compile_options(dreadful-cli PUBLIC "/Zc:__cplusplus")
endif()

target_compile_features(dreadful-cli PUBLIC cxx_std_20)
