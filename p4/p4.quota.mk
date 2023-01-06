# Build a client and server from the reference solution, but use the student's
# quota tracker

# The executables will have the suffix p4.quota.exe
EXESUFFIX = p4.quota.exe

# Names for building the client:
CLIENT_MAIN     = client
CLIENT_CXX      = 
CLIENT_COMMON   = 
CLIENT_PROVIDED = client requests crypto err file net my_crypto

# Names for building the server
SERVER_MAIN     = server
SERVER_CXX      = my_storage my_quota_tracker
SERVER_COMMON   = 
SERVER_PROVIDED = server responses parsing persist concurrenthashmap_factories \
                  my_mru crypto err file net my_pool my_crypto helpers

# All warnings should be treated as errors
CXXEXTRA = -Werror

# Pull in the common build rules
include common.mk