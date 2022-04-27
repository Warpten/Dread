CollectSourceFiles(
  ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE_SOURCES
  # Exclude
  )

GroupSources(${CMAKE_CURRENT_SOURCE_DIR})

add_ida_plugin(Dreadful ${PRIVATE_SOURCES})

find_package(Clang REQUIRED)
find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Found Clang: ${Clang_DIR}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
message(STATUS "Including LLVM from: ${LLVM_INCLUDE_DIRS}")
message(STATUS "Including Clang from: ${CLANG_INCLUDE_DIRS}")

CollectIncludeDirectories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  PUBLIC_INCLUDES)

target_include_directories(Dreadful
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR} # ${PUBLIC_INCLUDES}
    ${LLVM_INCLUDE_DIRS}
    ${CLANG_INCLUDE_DIRS}
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR})

separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})
add_definitions(${CLANG_DEFINITIONS})

# Find the libraries that correspond to the LLVM components
# that we wish to use
llvm_map_components_to_libnames(llvm_libs support core)

message(STATUS "Linking with LLVM binaries: ${llvm_libs}")
message(STATUS "Linking with Clang binaries: ${clang_libs}")

# Link against LLVM/Clang libraries
target_link_libraries(Dreadful ${llvm_libs} clangAST clangTooling)

if (MSVC)
    target_compile_options(Dreadful PUBLIC "/Zc:__cplusplus")
endif()

target_compile_features(Dreadful PUBLIC cxx_std_23)
