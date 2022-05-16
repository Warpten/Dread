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

# Find the libraries that correspond to the LLVM components
# that we wish to use
llvm_map_components_to_libnames(llvm_libs support core)

message(STATUS "Linking with LLVM binaries: ${llvm_libs}")
message(STATUS "Linking with Clang binaries: ${CLANG_LIBS}")

# Declare both targets
add_ida_plugin(dreadful2_plugin
  ${PRIVATE_SOURCES}
)
# add_executable(dreadful2_exe ${PRIVATE_SOURCES})
# target_compile_definitions(dreadful2_exe
#   PRIVATE
#     DREADFUL_BUILD_AS_EXECUTABLE  
# )

foreach (target IN ITEMS dreadful2_plugin ) #dreadful2_exe)
  target_include_directories(${target}
    PUBLIC 
      ${CMAKE_CURRENT_SOURCE_DIR}
      ${LLVM_INCLUDE_DIRS}
      ${CLANG_INCLUDE_DIRS}
    PRIVATE
      ${CMAKE_CURRENT_BINARY_DIR}
  )

  target_compile_definitions(${target}
    PRIVATE
      IDA_INCLUDE_DIR="${IDA_LIB_DIR}"
  )

  target_link_libraries(${target}
    ${llvm_libs} 
    clangAST 
    clangASTMatchers 
    clangBasic 
    clangTooling
  )

  if (MSVC)
    target_compile_options(${target}
      PRIVATE
        "/Zc:__cplusplus"
    )

    target_compile_options(${target}
      PUBLIC
        /wd4624 # warning C4624: 'identifier': destructor was implicitly defined as deleted
        /wd4291 # warning C4291: 'identifier': no matching operator delete found; memory will not be freed if initialization throws an exception
    )
  endif()

  target_compile_features(${target}
    PUBLIC
      cxx_std_20
  )

  add_custom_command(TARGET ${target} POST_BUILD
    COMMAND
      ${CMAKE_COMMAND} -E copy 
        $<TARGET_FILE:${target}> 
        "${IDA_INSTALL_DIR}/plugins"
    COMMENT
      "Moving $(TargetFileName) to ${IDA_INSTALL_DIR}/plugins ..."
    VERBATIM
  )
endforeach()