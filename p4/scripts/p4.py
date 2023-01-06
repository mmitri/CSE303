#!/usr/bin/python3
import cse303

# Configure constants and users
cse303.indentation = 80
cse303.verbose = cse303.check_args_verbose()
alice = cse303.UserConfig("alice", "alice_is_awesome")
fakealice = cse303.UserConfig("alice", "not_alice_password")
bob = cse303.UserConfig("bob", "bob_is_awesome")
t1kname = "t1k"
cse303.build_file(t1kname, 1024)
allkeys = "allkeys"
topkeys = "topkeys"

# Create objects with server and client configuration
server = cse303.ServerConfig("./obj64/server.exe", "9999", "rsa", "company.dir", "4", "1024", "6", "8192", "8192", "24", "4")
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
print("Test #1: Use KVI and KVU to expend the upload quota")
cse303.line()
server.pid = cse303.do_cmd_a("Starting server:", [
    "Listening on port "+server.port+" using (key/data) = (rsa, "+server.dirfile+")",
    "Generating RSA keys as ("+server.keyfile+".pub, "+server.keyfile+".pri)",
    "File not found: " + server.dirfile], server.launchcmd())
cse303.waitfor(2)
cse303.do_cmd("Registering new user alice.", "___OK___", client.reg(alice), server)
cse303.after(server.pid) # need an extra cleanup to handle the KEY that was sent by first REG
cse303.do_cmd("Registering new user bob.", "___OK___", client.reg(bob), server)
cse303.do_cmd("Setting key k1 to 1K file.", "___OK___", client.kvI(alice, "k1", t1kname), server)
cse303.do_cmd("Setting key k2 to 1K file.", "___OK___", client.kvI(alice, "k2", t1kname), server)
cse303.do_cmd("Updating key k2 to 1K file.", "OK_UPDATE", client.kvU(alice, "k2", t1kname), server)
cse303.do_cmd("Upserting key k3 to 1K file.", "OK_INSERT", client.kvU(alice, "k3", t1kname), server)
cse303.do_cmd("Setting key k4 to 1K file.", "___OK___", client.kvI(alice, "k4", t1kname), server)
cse303.do_cmd("Setting key k5 to 1K file.", "___OK___", client.kvI(alice, "k5", t1kname), server)
cse303.do_cmd("Setting key k6 to 1K file.", "___OK___", client.kvI(alice, "k6", t1kname), server)
cse303.do_cmd("Setting key k7 to 1K file.", "___OK___", client.kvI(alice, "k7", t1kname), server)

cse303.do_cmd("Setting key k8 to 1K file.", "ERR_QUOTA_UP", client.kvI(alice, "k8", t1kname), server)
cse303.do_cmd("Updating key k9 to 1K file.", "ERR_QUOTA_UP", client.kvU(alice, "k9", t1kname), server)
cse303.do_cmd("Upserting key k7 to 1K file.", "ERR_QUOTA_UP", client.kvU(alice, "k7", t1kname), server)

print()
cse303.line()
print("Test #2: Ensure upload quotas are per-user")
cse303.line()
cse303.do_cmd("Upserting key k7 to 1K file.", "OK_UPDATE", client.kvU(bob, "k7", t1kname), server)

print()
cse303.line()
print("Test #3: Test download quotas, with success after violation")
cse303.line()
cse303.do_cmd("Getting key k1.", "___OK___", client.kvG(alice, "k1"), server)
cse303.check_file_result(t1kname, "k1")
cse303.do_cmd("Getting all keys.", "___OK___", client.kvA(alice, allkeys), server)
cse303.check_file_list(allkeys, ["k1", "k2", "k3", "k4", "k5", "k6", "k7"])
cse303.do_cmd("Getting key k2.", "___OK___", client.kvG(alice, "k2"), server)
cse303.check_file_result(t1kname, "k2")
cse303.do_cmd("Getting key k3.", "___OK___", client.kvG(alice, "k3"), server)
cse303.check_file_result(t1kname, "k3")
cse303.do_cmd("Getting key k4.", "___OK___", client.kvG(alice, "k4"), server)
cse303.check_file_result(t1kname, "k4")
cse303.do_cmd("Getting key k5.", "___OK___", client.kvG(alice, "k5"), server)
cse303.check_file_result(t1kname, "k5")
cse303.do_cmd("Getting key k6.", "___OK___", client.kvG(alice, "k6"), server)
cse303.check_file_result(t1kname, "k6")
cse303.do_cmd("Getting key k7.", "___OK___", client.kvG(alice, "k7"), server)
cse303.check_file_result(t1kname, "k7")

cse303.do_cmd("Getting key k1.", "ERR_QUOTA_DOWN", client.kvG(alice, "k1"), server)
cse303.do_cmd("Getting all keys.", "___OK___", client.kvA(alice, allkeys), server)
cse303.check_file_list(allkeys, ["k1", "k2", "k3", "k4", "k5", "k6", "k7"])

print()
cse303.line()
print("Test #4: Ensure download quotas are per-user")
cse303.line()
cse303.do_cmd("Getting key k7.", "___OK___", client.kvG(bob, "k7"), server)
cse303.check_file_result(t1kname, "k7")

print()
cse303.line()
print("Test #5: Use KVD and KVT to test request quotas")
cse303.line()
cse303.do_cmd("Deleting key k6.", "___OK___", client.kvD(alice, "k6"), server)
cse303.do_cmd("Getting all keys.", "___OK___", client.kvA(alice, allkeys), server)
cse303.check_file_list(allkeys, ["k1", "k2", "k3", "k4", "k5", "k7"])

cse303.do_cmd("Getting top keys", "___OK___", client.kvT(alice, topkeys), server)
cse303.check_file_list_nosort(topkeys, ["k7", "k5", "k4"])

cse303.do_cmd("Setting key k10 to 1K file.", "ERR_QUOTA_REQ", client.kvI(alice, "k10", t1kname), server)
cse303.do_cmd("Upserting key k2 to 1K file.", "ERR_QUOTA_REQ", client.kvU(alice, "k2", t1kname), server)
cse303.do_cmd("Updating key k3 to 1K file.", "ERR_QUOTA_REQ", client.kvU(alice, "k3", t1kname), server)
cse303.do_cmd("Getting key k1.", "ERR_QUOTA_REQ", client.kvG(alice, "k1"), server)
cse303.do_cmd("Getting all keys.", "ERR_QUOTA_REQ", client.kvA(alice, allkeys), server)
cse303.do_cmd("Deleting key k2.", "ERR_QUOTA_REQ", client.kvD(alice, "k2"), server)
cse303.do_cmd("Getting top keys", "ERR_QUOTA_REQ", client.kvT(alice, topkeys), server)

print()
cse303.line()
print("Test #6: Quotas reset after a few seconds")
cse303.line()
print("Waiting for " + server.qi + " seconds so that quotas can reset")
cse303.waitfor(int(server.qi) + 1) # one extra, to play it safe...
cse303.do_cmd("Getting key k5.", "___OK___", client.kvG(alice, "k5"), server)
cse303.check_file_result(t1kname, "k5")
cse303.do_cmd("Getting key k7.", "___OK___", client.kvG(alice, "k7"), server)
cse303.check_file_result(t1kname, "k7")
cse303.do_cmd("Setting key k10 to 1K file.", "___OK___", client.kvI(alice, "k10", t1kname), server)
cse303.do_cmd("Getting all keys.", "___OK___", client.kvA(alice, allkeys), server)
cse303.check_file_list(allkeys, ["k1", "k2", "k3", "k4", "k5", "k7", "k10"])
cse303.do_cmd("Deleting key k5.", "___OK___", client.kvD(alice, "k5"), server)
cse303.do_cmd("Getting all keys.", "___OK___", client.kvA(alice, allkeys), server)
cse303.check_file_list(allkeys, ["k1", "k2", "k3", "k4", "k7", "k10"])
cse303.do_cmd("Getting top keys", "___OK___", client.kvT(alice, topkeys), server)
cse303.check_file_list_nosort(topkeys, ["k10", "k7", "k4"])

print()
cse303.line()
print("Test #7: Reset quotas can still be used up")
cse303.line()
print("Waiting for " + server.qi + " seconds so that quotas can reset")
cse303.waitfor(int(server.qi) + 1) # one extra, to play it safe...

cse303.do_cmd("Getting key k1.", "___OK___", client.kvG(alice, "k1"), server)
cse303.check_file_result(t1kname, "k1")
cse303.do_cmd("Getting key k2.", "___OK___", client.kvG(alice, "k2"), server)
cse303.check_file_result(t1kname, "k2")
cse303.do_cmd("Getting key k3.", "___OK___", client.kvG(alice, "k3"), server)
cse303.check_file_result(t1kname, "k3")
cse303.do_cmd("Getting key k4.", "___OK___", client.kvG(alice, "k4"), server)
cse303.check_file_result(t1kname, "k4")
cse303.do_cmd("Getting key k7.", "___OK___", client.kvG(alice, "k7"), server)
cse303.check_file_result(t1kname, "k7")
cse303.do_cmd("Getting key k10.", "___OK___", client.kvG(alice, "k10"), server)
cse303.check_file_result(t1kname, "k10")
cse303.do_cmd("Getting key k7.", "___OK___", client.kvG(alice, "k7"), server)
cse303.check_file_result(t1kname, "k7")
cse303.do_cmd("Getting key k1.", "___OK___", client.kvG(alice, "k1"), server)
cse303.check_file_result(t1kname, "k1")

cse303.do_cmd("Getting all keys.", "ERR_QUOTA_DOWN", client.kvA(alice, allkeys), server)
cse303.do_cmd("Getting top keys", "ERR_QUOTA_DOWN", client.kvT(alice, topkeys), server)

print()
cse303.line()
print("Test #8: KVT produces correct result")
cse303.line()
print("Waiting for " + server.qi + " seconds so that quotas can reset")
cse303.waitfor(int(server.qi) + 1) # one extra, to play it safe...
cse303.do_cmd("Getting top keys", "___OK___", client.kvT(alice, topkeys), server)
cse303.check_file_list_nosort(topkeys, ["k1", "k7", "k10", "k4"])
cse303.do_cmd("Stopping server.", "___OK___", client.bye(alice), server)
cse303.await_server("Waiting for server to shut down.", "Server terminated", server)

cse303.clean_common_files(server, client)
cse303.delfile(t1kname)

print()
