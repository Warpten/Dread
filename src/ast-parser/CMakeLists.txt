CollectSourceFiles(
  ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE_SOURCES
  # Exclude
  )

GroupSources(${CMAKE_CURRENT_SOURCE_DIR})

# Locate LLVM & Clang and link against the appropriate libraries
find_package(Clang REQUIRED clangTooling clangAST)
find_package(LLVM REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Found Clang: ${Clang_DIR}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
message(STATUS "Including LLVM from: ${LLVM_INCLUDE_DIRS}")
message(STATUS "Including Clang from: ${CLANG_INCLUDE_DIRS}")

separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})
add_definitions(${CLANG_DEFINITIONS})

# Find the libraries that correspond to the LLVM components we wish to use
llvm_map_components_to_libnames(llvm_libs support core)

message(STATUS "Linking with LLVM binaries: ${llvm_libs}")
message(STATUS "Linking with Clang binaries: ${CLANG_LIBS}")

# Declare target
add_library(ast-parser
  STATIC
    ${PRIVATE_SOURCES}
)

CollectIncludeDirectories(${CMAKE_CURRENT_SOURCE_DIR}
  PUBLIC_INCLUDES
)

target_include_directories(ast-parser
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LLVM_INCLUDE_DIRS}
    ${CLANG_INCLUDE_DIRS}
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
)

target_link_libraries(ast-parser 
  PRIVATE
    ${llvm_libs} 
    clangAST 
    clangASTMatchers 
    clangBasic 
    clangTooling
)

target_compile_options(ast-parser
  PUBLIC
    "$<$<CXX_COMPILER_ID:MSVC>:/Zc:__cplusplus>"
    "$<$<CXX_COMPILER_ID:MSVC>:/wd4624>" # warning C4624: 'identifier': destructor was implicitly defined as deleted
    "$<$<CXX_COMPILER_ID:MSVC>:/wd4291>" # warning C4291: 'identifier': no matching operator delete found; memory will not be freed if initialization throws an exception
)

target_compile_features(ast-parser PUBLIC cxx_std_20)
