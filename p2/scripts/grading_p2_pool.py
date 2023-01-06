#!/usr/bin/python3
import cse303

# Configure constants and users
cse303.indentation = 80
cse303.verbose = cse303.check_args_verbose()
alice = cse303.UserConfig("alice", "alice_is_awesome")
fakealice = cse303.UserConfig("alice", "not_alice_password")
bob = cse303.UserConfig("bob", "bob_is_the_best")
filet1 = "server/responses.h"
filet2 = "client/client.cc"
filet3 = "server/server.cc"
filet4 = "client/requests.cc"
fileb1 = "solutions/file.o"
fileb2 = "solutions/err.o"
fileb3 = "solutions/crypto.o"
fileb4 = "solutions/net.o"
allfile = "allfile"
makefiles = ["Makefile", "p2.pool.mk", "p2.nopool.mk"]
num_iters = 256

# Create objects with server and client configuration
server = cse303.ServerConfig("./obj64/server.exe", "9999", "rsa", "company.dir", "4", "1024", "1", "67108864", "67108864", "8192", "4")
client = cse303.ClientConfig("./obj64/client.exe", "localhost", "9999", "localhost.pub")

# Check if we should use solution server and/or client
cse303.override_exe(server, client)

# Set up a clean slate before getting started
cse303.line()
print("Getting ready to run tests")
cse303.line()
cse303.makeclean() # make clean
cse303.clean_common_files(server, client) # .pub, .pri, .dir files
cse303.killprocs()
cse303.build(makefiles)
cse303.leftmsg("Copying files with student pool into place")
cse303.copyexefile("obj64/server.p2.pool.exe", "obj64/server.exe")
cse303.copyexefile("obj64/client.p2.pool.exe", "obj64/client.exe")
cse303.okmsg()

print()
cse303.line()
print("Test: Thread pool correctness: requests should not hang")
cse303.line()
server.pid = cse303.do_cmd_a("Starting server:", [
    "Listening on port "+server.port+" using (key/data) = (rsa, "+server.dirfile+")",
    "Generating RSA keys as ("+server.keyfile+".pub, "+server.keyfile+".pri)",
    "File not found: " + server.dirfile], server.launchcmd())
cse303.waitfor(2)
cse303.do_cmd("Registering a user", "___OK___", client.reg(alice), server)
cse303.after(server.pid) # need an extra cleanup to handle the KEY that was sent by first REG
for i in range(num_iters):
    key = "k"+str(i)
    file = key + ".dat"
    cse303.build_file(file, 64)
    cse303.do_cmd("Setting key "+key+".", "___OK___", client.kvI(alice, key, file), server)
for i in range(num_iters):
    key = "k"+str(i)
    file = key + ".dat"
    cse303.do_cmd("Getting key "+key+".", "___OK___", client.kvG(alice, key), server)
    cse303.check_file_result(file, key)
    cse303.delfile(file)
for i in range(num_iters):
    key = "k"+str(i)
    file = key + ".dat"
    cse303.do_cmd("Deleting key "+key+".", "___OK___", client.kvD(alice, key), server)

print()
cse303.line()
print("Test: Thread pool correctness: pool should shut down gracefully")
cse303.line()
cse303.do_cmd("Shutting down", "___OK___", client.bye(alice), server)
cse303.await_server("Waiting for server to shut down.", "Server terminated", server)
cse303.clean_common_files(server, client)

print()
