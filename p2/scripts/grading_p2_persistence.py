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
fileb3 = "solutions/my_pool.o"
fileb4 = "solutions/net.o"
allfile = "allfile"
makefiles = ["Makefile", "p2.pool.mk", "p2.nopool.mk"]

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
cse303.leftmsg("Copying files with solution pool into place")
cse303.copyexefile("obj64/server.p2.nopool.exe", "obj64/server.exe")
cse303.copyexefile("obj64/client.p2.nopool.exe", "obj64/client.exe")
cse303.okmsg()

print()
cse303.line()
print("Test: Persistence: Generating data")
cse303.line()
server.pid = cse303.do_cmd_a("Starting server:", [
    "Listening on port "+server.port+" using (key/data) = (rsa, "+server.dirfile+")",
    "Generating RSA keys as ("+server.keyfile+".pub, "+server.keyfile+".pri)",
    "File not found: " + server.dirfile], server.launchcmd())
cse303.waitfor(2)
expectsize = 0
cse303.do_cmd("Registering a user", "___OK___", client.reg(alice), server)
expectsize += (8 + 8 + cse303.next8(len(alice.name) + 8 + 16 + 8 + 32 + 8))
cse303.after(server.pid) # need an extra cleanup to handle the KEY that was sent by first REG
cse303.do_cmd("Setting key b1.", "___OK___", client.kvI(alice, "b1", fileb1), server)
expectsize += cse303.next8(8 + 8 + 8 + len("b1") + cse303.get_len(fileb1))
for i in range(4096):
    key = "k"+str(i)
    file = key + ".dat"
    cse303.build_file(file, 64)
    cse303.do_cmd("Setting key "+key+".", "___OK___", client.kvI(alice, key, file), server)
    expectsize += cse303.next8(8 + 8 + 8 + len(key) + cse303.get_len(file))
cse303.do_cmd("Persisting", "___OK___", client.persist(alice), server)
cse303.do_cmd("Shutting down", "___OK___", client.bye(alice), server)
cse303.await_server("Waiting for server to shut down.", "Server terminated", server)
cse303.check_exist(server.dirfile, True)
cse303.verify_filesize(server.dirfile, expectsize)
server.pid = cse303.do_cmd_a("Starting server:", [
    "Listening on port "+server.port+" using (key/data) = (rsa, "+server.dirfile+")",
    "Loaded: " + server.dirfile], server.launchcmd())
cse303.waitfor(2)
for i in range(4096):
    key = "k"+str(i)
    file = key + ".dat"
    cse303.do_cmd("Getting key "+key+".", "___OK___", client.kvG(alice, key), server)
    cse303.check_file_result(file, key)
    cse303.delfile(file)
cse303.do_cmd("Getting key b1.", "___OK___", client.kvG(alice, "b1"), server)
cse303.check_file_result(fileb1, "b1")

cse303.do_cmd("Shutting down", "___OK___", client.bye(alice), server)
cse303.await_server("Waiting for server to shut down.", "Server terminated", server)
cse303.clean_common_files(server, client)

print()
