#!/usr/bin/python3
import cse303

# Configure constants and users
cse303.indentation = 80
cse303.verbose = cse303.check_args_verbose()
alice = cse303.UserConfig("alice", "alice_is_awesome")
fakealice = cse303.UserConfig("alice", "not_alice_password")
bob = cse303.UserConfig("bob", "bob_is_awesome")
valfile = "valfile"
cse303.build_file(valfile, 8)
topkeys = "topkeys"
makefiles = ["Makefile", "p4.quota.mk", "p4.mru.mk"]

# Create objects with server and client configuration
server = cse303.ServerConfig("./obj64/server.exe", "9999", "rsa", "company.dir", "4", "1024", "6", "65536", "65536", "1024", "8")
client = cse303.ClientConfig("./obj64/client.exe", "localhost", "9999", "localhost.pub")

# Check if we should use solution server or client
cse303.override_exe(server, client)

# Set up a clean slate before getting started
cse303.line()
print("Getting ready to run tests")
cse303.line()
cse303.makeclean() # make clean
cse303.clean_common_files(server, client) # .pub, .pri, .dir files
cse303.killprocs()
cse303.build(makefiles)
cse303.leftmsg("Copying files with student mru into place")
cse303.copyexefile("obj64/server.p4.mru.exe", "obj64/server.exe")
cse303.copyexefile("obj64/client.p4.mru.exe", "obj64/client.exe")
cse303.okmsg()

print()
cse303.line()
print("Test #1: KVT on an empty K/V Store")
cse303.line()
server.pid = cse303.do_cmd_a("Starting server:", [
    "Listening on port "+server.port+" using (key/data) = (rsa, "+server.dirfile+")",
    "Generating RSA keys as ("+server.keyfile+".pub, "+server.keyfile+".pri)",
    "File not found: " + server.dirfile], server.launchcmd())
cse303.waitfor(2)
cse303.do_cmd("Registering new user alice.", "___OK___", client.reg(alice), server)
cse303.after(server.pid) # need an extra cleanup to handle the KEY that was sent by first REG
cse303.do_cmd("Registering new user bob.", "___OK___", client.reg(bob), server)
cse303.do_cmd("Calling KVT on an empty K/V store", "ERR_NO_DATA", client.kvT(alice, topkeys), server)

print()
cse303.line()
print("Test #2: Successful KVI affect KVT")
cse303.line()
cse303.do_cmd("Inserting k1.", "___OK___", client.kvI(alice, "k1", valfile), server)
cse303.do_cmd("Inserting k2.", "___OK___", client.kvI(alice, "k2", valfile), server)
cse303.do_cmd("Inserting k3.", "___OK___", client.kvI(alice, "k3", valfile), server)
cse303.do_cmd("Getting top keys", "___OK___", client.kvT(alice, topkeys), server)
cse303.check_file_list_nosort(topkeys, ["k3", "k2", "k1"])

print()
cse303.line()
print("Test #3: Failed KVI do not affect KVT")
cse303.line()
cse303.do_cmd("Inserting k1.", "ERR_KEY", client.kvI(alice, "k1", valfile), server)
cse303.do_cmd("Getting top keys", "___OK___", client.kvT(alice, topkeys), server)
cse303.check_file_list_nosort(topkeys, ["k3", "k2", "k1"])

print()
cse303.line()
print("Test #4: MRU handles overflow from KVI")
cse303.line()
cse303.do_cmd("Inserting k4.", "___OK___", client.kvI(alice, "k4", valfile), server)
cse303.do_cmd("Inserting k5.", "___OK___", client.kvI(alice, "k5", valfile), server)
cse303.do_cmd("Inserting k6.", "___OK___", client.kvI(alice, "k6", valfile), server)
cse303.do_cmd("Inserting k7.", "___OK___", client.kvI(alice, "k7", valfile), server)
cse303.do_cmd("Inserting k8.", "___OK___", client.kvI(alice, "k8", valfile), server)
cse303.do_cmd("Inserting k9.", "___OK___", client.kvI(alice, "k9", valfile), server)
cse303.do_cmd("Getting top keys", "___OK___", client.kvT(alice, topkeys), server)
cse303.check_file_list_nosort(topkeys, ["k9", "k8", "k7", "k6", "k5", "k4", "k3", "k2"])

print()
cse303.line()
print("Test #5: KVD contracts the MRU")
cse303.line()
cse303.do_cmd("Deleting k4.", "___OK___", client.kvD(alice, "k4"), server)
cse303.do_cmd("Deleting k8.", "___OK___", client.kvD(alice, "k8"), server)
cse303.do_cmd("Getting top keys", "___OK___", client.kvT(alice, topkeys), server)
cse303.check_file_list_nosort(topkeys, ["k9", "k7", "k6", "k5", "k3", "k2"])

print()
cse303.line()
print("Test #6: KVG rearranges the MRU")
cse303.line()
cse303.do_cmd("Getting key k3.", "___OK___", client.kvG(alice, "k3"), server)
cse303.check_file_result(valfile, "k3")
cse303.do_cmd("Getting key k2.", "___OK___", client.kvG(alice, "k2"), server)
cse303.check_file_result(valfile, "k2")
cse303.do_cmd("Getting top keys", "___OK___", client.kvT(alice, topkeys), server)
cse303.check_file_list_nosort(topkeys, ["k2", "k3", "k9", "k7", "k6", "k5" ])

print()
cse303.line()
print("Test #7: KVG enlarges the MRU")
cse303.line()
cse303.do_cmd("Getting key k1.", "___OK___", client.kvG(alice, "k1"), server)
cse303.check_file_result(valfile, "k1")
cse303.do_cmd("Getting top keys", "___OK___", client.kvT(alice, topkeys), server)
cse303.check_file_list_nosort(topkeys, ["k1", "k2", "k3", "k9", "k7", "k6", "k5" ])

print()
cse303.line()
print("Test #8: KVU rearranges the MRU")
cse303.line()
cse303.do_cmd("Upserting k5.", "OK_UPDATE", client.kvU(alice, "k5", valfile), server)
cse303.do_cmd("Getting top keys", "___OK___", client.kvT(alice, topkeys), server)
cse303.check_file_list_nosort(topkeys, ["k5", "k1", "k2", "k3", "k9", "k7", "k6" ])

print()
cse303.line()
print("Test #9: KVU enlarges the MRU and causes eviction")
cse303.line()
cse303.do_cmd("Upserting k10.", "OK_INSERT", client.kvU(alice, "k10", valfile), server)
cse303.do_cmd("Upserting k11.", "OK_INSERT", client.kvU(alice, "k11", valfile), server)
cse303.do_cmd("Getting top keys", "___OK___", client.kvT(alice, topkeys), server)
cse303.check_file_list_nosort(topkeys, ["k11", "k10", "k5", "k1", "k2", "k3", "k9", "k7"])

print()
cse303.line()
print("Test #10: Failed KVG and KVD do not affect MRU")
cse303.line()
cse303.do_cmd("Getting key k100.", "ERR_KEY", client.kvG(alice, "k100"), server)
cse303.do_cmd("Deleting k40.", "ERR_KEY", client.kvD(alice, "k40"), server)
cse303.do_cmd("Getting top keys", "___OK___", client.kvT(alice, topkeys), server)
cse303.check_file_list_nosort(topkeys, ["k11", "k10", "k5", "k1", "k2", "k3", "k9", "k7"])

print()
cse303.line()
print("Test #11: All users affect the same MRU")
cse303.line()
cse303.do_cmd("Getting key k1 with bob.", "___OK___", client.kvG(bob, "k1"), server)
cse303.check_file_result(valfile, "k1")
cse303.do_cmd("Upserting k10 with bob.", "OK_UPDATE", client.kvU(bob, "k10", valfile), server)
cse303.do_cmd("Deleting k5 with bob.", "___OK___", client.kvD(bob, "k5"), server)
cse303.do_cmd("Upserting k12 with bob.", "OK_INSERT", client.kvU(bob, "k12", valfile), server)
cse303.do_cmd("Getting top keys with alice", "___OK___", client.kvT(alice, topkeys), server)
cse303.check_file_list_nosort(topkeys, ["k12", "k10", "k1", "k11", "k2", "k3", "k9", "k7"])
cse303.do_cmd("Getting top keys with bob", "___OK___", client.kvT(bob, topkeys), server)
cse303.check_file_list_nosort(topkeys, ["k12", "k10", "k1", "k11", "k2", "k3", "k9", "k7"])
cse303.do_cmd("Stopping server.", "___OK___", client.bye(alice), server)
cse303.await_server("Waiting for server to shut down.", "Server terminated", server)

cse303.clean_common_files(server, client)
cse303.delfile(valfile)

print()
