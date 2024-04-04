cmake_minimum_required(VERSION 3.17)
project(projekt_alokator C)

set(CMAKE_C_STANDARD 11)

# Ustaw opcje kompilatora (z raportu Dante)
add_compile_options(
        "-ggdb3"
        "-std=c11"
        "-xc"
        "-pedantic"
        "-Werror"
        "-Wall"
        "-Wextra"
        "-fmax-errors=5"
        "-Werror=vla"
        "-Wno-error=unused-parameter"
        "-Wno-error=unused-function"
        "-Wno-error=unused-variable"
        "-Wno-error=parentheses"
        "-Wno-parentheses"
        "-D_GNU_SOURCE"
        "-D__TEST_BOOTSTRAP"
        "-DINSIDE_DANTE"
        "-D_ANSI_OUTPUT"
)

add_link_options(
        "-ggdb3"
        "-fuse-ld=gold"
        "-Wl,-Map=main.map"
        "-Wl,-cref"
        "-Wl,-wrap,main"
)

add_executable(projekt_alokator
        "main.c"
        "heap.c"
        "unit_helper_v2.c"
        "unit_test_v2.c"
        "rdebug.c"
        "memmanager.c"
)

#[[add_executable(projekt_alokator
        "main.c"
        "heap.c"
        "memmanager.c"
)]]

target_link_libraries(projekt_alokator m pthread)
