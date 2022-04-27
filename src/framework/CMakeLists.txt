CollectSourceFiles(
  ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE_SOURCES
  # Exclude
  )

GroupSources(${CMAKE_CURRENT_SOURCE_DIR})

add_library(framework SHARED ${PRIVATE_SOURCES})

CollectIncludeDirectories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  PUBLIC_INCLUDES)

target_include_directories(framework 
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR} # ${PUBLIC_INCLUDES}
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR})

if (MSVC)
    target_compile_options(framework PUBLIC "/Zc:__cplusplus")
endif()

target_compile_features(framework PUBLIC cxx_std_23)
