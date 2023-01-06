# Build a client and server using only the student's my_pool.cc

# The executables will have the suffix .exe
EXESUFFIX = exe

# Names for building the client:
CLIENT_MAIN     = client
CLIENT_CXX      = 
CLIENT_COMMON   = 
CLIENT_PROVIDED = crypto err file net client requests my_crypto

# Names for building the server
SERVER_MAIN     = server
SERVER_CXX      = 
SERVER_COMMON   = my_pool
SERVER_PROVIDED = crypto err file net my_crypto server responses parsing \
                  my_storage concurrenthashmap_factories

# Pull in the common build rules
include common.mk
