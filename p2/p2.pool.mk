# Build a client and server from the reference solution, but use the student's
# common.pool.cc

# The executables will have the suffix p2.pool.exe
EXESUFFIX = p2.pool.exe

# Names for building the client
CLIENT_MAIN     = client
CLIENT_CXX      = 
CLIENT_COMMON   =
CLIENT_PROVIDED = client crypto err file net requests my_crypto

# Names for building the server
SERVER_MAIN     = server
SERVER_CXX      = 
SERVER_COMMON   = my_pool
SERVER_PROVIDED = server responses my_storage concurrenthashmap_factories \
                  crypto err file net parsing my_crypto

# All warnings should be treated as errors
CXXEXTRA = -Werror

# Pull in the common build rules
include common.mk
