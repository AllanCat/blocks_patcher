cmake_minimum_required(VERSION 3.22)

project(
    blocks_loader
    VERSION "0.1.0"
    DESCRIPTION ""
    LANGUAGES C CXX)


set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_DEBUG_POSTFIX "")

add_library(32 SHARED
    main.cpp
)
target_compile_features(32 PUBLIC cxx_std_23)
target_link_options(32 PUBLIC /INCREMENTAL:NO)
target_compile_options(32 PUBLIC /MTd)

