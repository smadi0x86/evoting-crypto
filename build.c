// This is your build script. You only need to "bootstrap" it once with `cc -o nob nob.c`
// (you can call the executable whatever actually) or `cl nob.c` on MSVC. After that every
// time you run the `nob` executable if it detects that you modifed nob.c it will rebuild
// itself automatically thanks to NOB_GO_REBUILD_URSELF (see below)

// nob.h is an stb-style library https://github.com/nothings/stb/blob/master/docs/stb_howto.txt
// What that means is that it's a single file that acts both like .c and .h files, but by default
// when you include it, it acts only as .h. To make it include implementations of the functions
// you must define NOB_IMPLEMENTATION macro. This is done to give you full control over where
// the implementations go.

#define NOB_IMPLEMENTATION
#include "nob.h"

#define BUILD_FOLDER "bin"
#define SRC_FOLDER   "src"

int main(int argc, char **argv)
{
    // Enable self-rebuilding
    NOB_GO_REBUILD_URSELF(argc, argv);

    // Create build directory if it doesn't exist
    if (!nob_mkdir_if_not_exists(BUILD_FOLDER)) {
        fprintf(stderr, "ERROR: Could not create build directory\n");
        return 1;
    }

    // Clear command structure
    Nob_Cmd cmd = {0};

    // Compile the e-voting system
    printf("Building e-voting system...\n");

#if !defined(_MSC_VER)
    // POSIX build command
    nob_cmd_append(&cmd, "cc");
    nob_cmd_append(&cmd, "-Wall", "-Wextra");
    nob_cmd_append(&cmd, "-o", BUILD_FOLDER"/evoting-system");
    nob_cmd_append(&cmd,
        SRC_FOLDER"/main.c",
        SRC_FOLDER"/des.c",
        SRC_FOLDER"/desModes.c",
        SRC_FOLDER"/utils.c",
        SRC_FOLDER"/rsa.c",
        SRC_FOLDER"/rsaKeygen.c",
        SRC_FOLDER"/evoting.c",
        SRC_FOLDER"/sha256.c"
    );
    // link with gmp lib
    nob_cmd_append(&cmd, "-lgmp");
#else
    // MSVC build command
    nob_cmd_append(&cmd, "cl");
    nob_cmd_append(&cmd, "-I.");
    nob_cmd_append(&cmd, "-o", BUILD_FOLDER"/evoting-system.exe");
    nob_cmd_append(&cmd,
        SRC_FOLDER"/main.c",
        SRC_FOLDER"/des.c",
        SRC_FOLDER"/desModes.c",
        SRC_FOLDER"/utils.c",
        SRC_FOLDER"/rsa.c",
        SRC_FOLDER"/rsaKeygen.c",
        SRC_FOLDER"/evoting.c",
        SRC_FOLDER"/sha256.c"
    );
    // link with gmp lib
    nob_cmd_append(&cmd, "-lgmp");
#endif

    // Execute the build command
    if (!nob_cmd_run_sync(cmd)) {
        fprintf(stderr, "ERROR: Build failed\n");
        return 1;
    }

    printf("Build successful! Executable is at %s/evoting-system\n", BUILD_FOLDER);
    return 0;
}