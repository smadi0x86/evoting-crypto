E-Voting System
==========================

== Description ==
This project is an implementation of an electronic voting system.
It is written in C and provides functionalities for secure voting.

== How to Build ==
The project uses a custom build script. To build the project, compile and run `build.c`:

    cc -o build build.c
    ./build

This will generate the executables in the `bin/` directory.

== How to Run ==
The main executables are located in the `bin/` directory after building the project.
Run the desired program from the command line.

For example:
    ./bin/evoting-system

== Helpers ==

I used standalone C files to test some logic before actual implementation, this includes:

- cts-test.c which helped me learn more about cipher text stealing
- rsa-keygen.c which was used to generate P and Q values for RSA encryption
- confirm-permute.c which was used to test the initial permutation table
- sqmul.c which was used to implement the square and multiply algorithm

== References ==
This project utilizes the following libraries and technologies:
- GNU Multiple Precision Arithmetic Library (GMP)
- SHA-256 for hashing
- RSA for public-key cryptography
- DES for symmetric-key cryptography
- tsoding nob.h header file for build system

== License ==
This project is licensed under the terms GNU Version 3, check the LICENSE file for more details.