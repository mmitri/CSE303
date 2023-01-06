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
print("Test #1: Basic KVI functionality")
cse303.line()
server.pid = cse303.do_cmd_a("Starting server:", [
    "Listening on port "+server.port+" using (key/data) = (rsa, "+server.dirfile+")",
    "Generating RSA keys as ("+server.keyfile+".pub, "+server.keyfile+".pri)",
    "File not found: " + server.dirfile], server.launchcmd())
cse303.waitfor(2)
cse303.do_cmd("Registering a user", "___OK___", client.reg(alice), server)
cse303.after(server.pid) # need an extra cleanup to handle the KEY that was sent by first REG

cse303.do_cmd("Setting key k1 with invalid user.", "ERR_LOGIN", client.kvI(bob, "k1", filet1), server)
cse303.do_cmd("Setting key k1 with invalid password.", "ERR_LOGIN", client.kvI(fakealice, "k1", filet1), server)
cse303.do_cmd("Setting key k1.", "___OK___", client.kvI(alice, "k1", filet1), server)
cse303.do_cmd("Re-setting key k1.", "ERR_KEY", client.kvI(alice, "k1", filet1), server)
cse303.do_cmd("Setting key k2 with binary data.", "___OK___", client.kvI(alice, "k2", fileb1), server)
cse303.build_file("toobig.dat", 1048577)
cse303.build_file("nottoobig.dat", 1048576)
cse303.do_cmd("Setting key k3 with too large file.", "ERR_REQ_FMT", client.kvI(alice, "k3", "toobig.dat"), server)
cse303.do_cmd("Setting key k4 with large file.", "___OK___", client.kvI(alice, "k4", "nottoobig.dat"), server)
cse303.delfile("toobig.dat")

print()
cse303.line()
print("Test #2: KVG functionality")
cse303.line()
cse303.do_cmd("Getting key k1 with invalid user.", "ERR_LOGIN", client.kvG(bob, "k1"), server)
cse303.do_cmd("Getting key k1 with invalid password.", "ERR_LOGIN", client.kvG(fakealice, "k1"), server)
cse303.do_cmd("Getting nonexistent key k11.", "ERR_KEY", client.kvG(alice, "k11"), server)
cse303.do_cmd("Getting nonexistent key k3.", "ERR_KEY", client.kvG(alice, "k3"), server)
cse303.do_cmd("Getting text key k1.", "___OK___", client.kvG(alice, "k1"), server)
cse303.check_file_result(filet1, "k1")
cse303.do_cmd("Getting binary key k2.", "___OK___", client.kvG(alice, "k2"), server)
cse303.check_file_result(fileb1, "k2")
cse303.do_cmd("Getting large key k4.", "___OK___", client.kvG(alice, "k4"), server)
cse303.check_file_result("nottoobig.dat", "k4")
cse303.delfile("nottoobig.dat")

print()
cse303.line()
print("Test #3: KVD functionality")
cse303.line()
cse303.do_cmd("Deleting key k1 with invalid user.", "ERR_LOGIN", client.kvD(bob, "k1"), server)
cse303.do_cmd("Deleting key k1 with invalid password.", "ERR_LOGIN", client.kvD(fakealice, "k1"), server)
cse303.do_cmd("Deleting nonexistent key k11.", "ERR_KEY", client.kvD(alice, "k11"), server)
cse303.do_cmd("Deleting text key k1.", "___OK___", client.kvD(alice, "k1"), server)
cse303.do_cmd("Checking delete.", "ERR_KEY", client.kvG(alice, "k1"), server)
cse303.do_cmd("Deleting binary key k2.", "___OK___", client.kvD(alice, "k2"), server)
cse303.do_cmd("Checking delete.", "ERR_KEY", client.kvG(alice, "k2"), server)

print()
cse303.line()
print("Test #4: KVU functionality")
cse303.line()
cse303.do_cmd("Upserting key k1 with invalid user.", "ERR_LOGIN", client.kvU(bob, "k1", filet1), server)
cse303.do_cmd("Upserting key k1 with invald password.", "ERR_LOGIN", client.kvU(fakealice, "k1", filet1), server)
cse303.do_cmd("Upserting key k1 with text value.", "OK_INSERT", client.kvU(alice, "k1", filet1), server)
cse303.do_cmd("Getting key k1.", "___OK___", client.kvG(alice, "k1"), server)
cse303.check_file_result(filet1, "k1")
cse303.do_cmd("Upserting key k2 with binary value.", "OK_INSERT", client.kvU(alice, "k2", fileb1), server)
cse303.do_cmd("Getting key k2.", "___OK___", client.kvG(alice, "k2"), server)
cse303.check_file_result(fileb1, "k2")
cse303.do_cmd("Upserting key k1 with text value.", "OK_UPDATE", client.kvU(alice, "k1", filet2), server)
cse303.do_cmd("Getting key k1.", "___OK___", client.kvG(alice, "k1"), server)
cse303.check_file_result(filet2, "k1")
cse303.do_cmd("Upserting key k2 with binary value.", "OK_UPDATE", client.kvU(alice, "k2", fileb2), server)
cse303.do_cmd("Getting key k2.", "___OK___", client.kvG(alice, "k2"), server)
cse303.check_file_result(fileb2, "k2")

print()
cse303.line()
print("Test #5: Key/Value ALL")
cse303.line()
cse303.do_cmd("Getting all keys with invalid user.", "ERR_LOGIN", client.kvA(bob, allfile), server)
cse303.do_cmd("Getting all keys with invald password.", "ERR_LOGIN", client.kvA(fakealice, allfile), server)
cse303.do_cmd("Getting all keys to make sure it's k1, k2, and k4.", "___OK___", client.kvA(alice, allfile), server)
cse303.check_file_list(allfile, ["k1", "k2", "k4"])
cse303.do_cmd("Deleting text key k1.", "___OK___", client.kvD(alice, "k1"), server)
cse303.do_cmd("Deleting binary key k2.", "___OK___", client.kvD(alice, "k2"), server)
cse303.do_cmd("Getting all keys to make sure it's just k4.", "___OK___", client.kvA(alice, allfile), server)
cse303.check_file_list(allfile, ["k4"])
cse303.do_cmd("Deleting binary key k4.", "___OK___", client.kvD(alice, "k4"), server)
cse303.do_cmd("Getting all keys from empty table.", "ERR_NO_DATA", client.kvA(alice, allfile), server)

cse303.do_cmd("Shutting down", "___OK___", client.bye(alice), server)
cse303.await_server("Waiting for server to shut down.", "Server terminated", server)
cse303.check_exist(server.dirfile, False)
cse303.clean_common_files(server, client)

print()
