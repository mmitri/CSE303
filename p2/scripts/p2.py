#!/usr/bin/python3
import cse303

# Configure constants and users
cse303.indentation = 80
cse303.verbose = cse303.check_args_verbose()
alice = cse303.UserConfig("alice", "alice_is_awesome")
fakealice = cse303.UserConfig("alice", "not_alice_password")
afile1 = "server/responses.h"
afile2 = "solutions/net.o"
allfile = "allfile"

# Create objects with server and client configuration
server = cse303.ServerConfig("./obj64/server.exe", "9999", "rsa", "company.dir", "4", "1024", "1", "67108864", "67108864", "8192", "4")
client = cse303.ClientConfig("./obj64/client.exe", "localhost", "9999", "localhost.pub")

# Check if we should use solution server or client
cse303.override_exe(server, client)

# Set up a clean slate before getting started
cse303.line()
print("Getting ready to run tests")
cse303.line()
cse303.clean_common_files(server, client) # .pub, .pri, .dir files
cse303.killprocs()

print()
cse303.line()
print("Test #1: Key/Value Get and Set")
cse303.line()
server.pid = cse303.do_cmd_a("Starting server:", [
    "Listening on port "+server.port+" using (key/data) = (rsa, "+server.dirfile+")",
    "Generating RSA keys as ("+server.keyfile+".pub, "+server.keyfile+".pri)",
    "File not found: " + server.dirfile], server.launchcmd())
cse303.waitfor(2)
cse303.do_cmd("Registering new user alice.", "___OK___", client.reg(alice), server)
cse303.after(server.pid) # need an extra cleanup to handle the KEY that was sent by first REG
cse303.do_cmd("Setting key k1.", "___OK___", client.kvI(alice, "k1", afile1), server)
cse303.do_cmd("Getting key k1.", "___OK___", client.kvG(alice, "k1"), server)
cse303.check_file_result(afile1, "k1")
cse303.do_cmd("Setting key k1 again.", "ERR_KEY", client.kvI(alice, "k1", afile1), server)
cse303.do_cmd("Upserting key k1.", "OK_UPDATE", client.kvU(alice, "k1", afile2), server)
cse303.do_cmd("Getting key k1.", "___OK___", client.kvG(alice, "k1"), server)
cse303.check_file_result(afile2, "k1")

print()
cse303.line()
print("Test #2: Key/Value Upsert")
cse303.line()
cse303.do_cmd("Upserting key k2.", "OK_INSERT", client.kvU(alice, "k2", afile1), server)
cse303.do_cmd("Getting key k2.", "___OK___", client.kvG(alice, "k2"), server)
cse303.check_file_result(afile1, "k2")
cse303.do_cmd("Upserting key k2.", "OK_UPDATE", client.kvU(alice, "k2", afile2), server)
cse303.do_cmd("Getting key k2.", "___OK___", client.kvG(alice, "k2"), server)
cse303.check_file_result(afile2, "k2")

print()
cse303.line()
print("Test #3: Key/Value ALL")
cse303.line()
cse303.do_cmd("Getting all keys to make sure it's k1 and k2.", "___OK___", client.kvA(alice, allfile), server)
cse303.check_file_list(allfile, ["k1", "k2"])

print()
cse303.line()
print("Test #4: Key/Value Delete")
cse303.line()
cse303.do_cmd("Deleting key k2.", "___OK___", client.kvD(alice, "k2"), server)
cse303.do_cmd("Getting key k2.", "ERR_KEY", client.kvG(alice, "k2"), server)
cse303.do_cmd("Getting key k7.", "ERR_KEY", client.kvG(alice, "k7"), server)
cse303.do_cmd("Getting key k1.", "___OK___", client.kvG(alice, "k1"), server)
cse303.check_file_result(afile2, "k1")

print()
cse303.line()
print("Test #5: Key/Value Persistence")
cse303.line()
cse303.do_cmd("Inserting key k3.", "___OK___", client.kvI(alice, "k3", afile1), server)
cse303.do_cmd("Instructing server to persist data.", "___OK___", client.persist(alice), server)
cse303.line()
cse303.do_cmd("Stopping server.", "___OK___", client.bye(alice), server)
cse303.await_server("Waiting for server to shut down.", "Server terminated", server)
server.pid = cse303.do_cmd_a("Restarting server:", [
    "Listening on port "+server.port+" using (key/data) = (rsa, "+server.dirfile+")",
    "Loaded: " + server.dirfile], server.launchcmd())
cse303.waitfor(2)
cse303.do_cmd("Getting key k1.", "___OK___", client.kvG(alice, "k1"), server)
cse303.check_file_result(afile2, "k1")
cse303.do_cmd("Getting key k2.", "ERR_KEY", client.kvG(alice, "k2"), server)
cse303.do_cmd("Getting key k3.", "___OK___", client.kvG(alice, "k3"), server)
cse303.check_file_result(afile1, "k3")
cse303.do_cmd("Stopping server.", "___OK___", client.bye(alice), server)
cse303.await_server("Waiting for server to shut down.", "Server terminated", server)

cse303.clean_common_files(server, client)

print()
