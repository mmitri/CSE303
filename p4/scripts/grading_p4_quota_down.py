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
makefiles = ["Makefile", "p4.quota.mk", "p4.mru.mk"]

# Create objects with server and client configuration
server = cse303.ServerConfig("./obj64/server.exe", "9999", "rsa", "company.dir", "4", "1024", "6", "16384", "8192", "1024", "4")
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
cse303.leftmsg("Copying files with student quotas into place")
cse303.copyexefile("obj64/server.p4.quota.exe", "obj64/server.exe")
cse303.copyexefile("obj64/client.p4.quota.exe", "obj64/client.exe")
cse303.okmsg()

print()
cse303.line()
print("Initializing KV Store")
cse303.line()
server.pid = cse303.do_cmd_a("Starting server:", [
    "Listening on port "+server.port+" using (key/data) = (rsa, "+server.dirfile+")",
    "Generating RSA keys as ("+server.keyfile+".pub, "+server.keyfile+".pri)",
    "File not found: " + server.dirfile], server.launchcmd())
cse303.waitfor(2)
cse303.do_cmd("Registering new user alice.", "___OK___", client.reg(alice), server)
cse303.after(server.pid) # need an extra cleanup to handle the KEY that was sent by first REG
cse303.do_cmd("Registering new user bob.", "___OK___", client.reg(bob), server)
for i in range(1,17):
    cse303.do_cmd("Setting key k"+str(i)+" to 1K file.", "___OK___", client.kvI(alice, "k"+str(i), t1kname), server)

print()
cse303.line()
print("Test #1: Use KVG to expend a user's download quota")
cse303.line()
for i in range(1,9):
    cse303.do_cmd("Getting key k"+str(i)+".", "___OK___", client.kvG(alice, "k"+str(i)), server)
    cse303.check_file_result(t1kname, "k"+str(i))
cse303.do_cmd("Getting key k9.", "ERR_QUOTA_DOWN", client.kvG(alice, "k9"), server)

print()
cse303.line()
print("Test #2: Ensure download quotas are per-user")
cse303.line()
for i in range(1,9):
    cse303.do_cmd("Getting key k"+str(i)+".", "___OK___", client.kvG(bob, "k"+str(i)), server)
    cse303.check_file_result(t1kname, "k"+str(i))
cse303.do_cmd("Getting key k9.", "ERR_QUOTA_DOWN", client.kvG(bob, "k9"), server)

print()
cse303.line()
print("Test #3: Waiting resets quotas, which are affected by KVA")
cse303.line()
print("Waiting for " + server.qi + " seconds so that quotas can reset")
cse303.waitfor(int(server.qi) + 1) # one extra, to play it safe...
for i in range(1,8):
    cse303.do_cmd("Getting key k"+str(i)+".", "___OK___", client.kvG(bob, "k"+str(i)), server)
    cse303.check_file_result(t1kname, "k"+str(i))
cse303.do_cmd("Getting all keys.", "___OK___", client.kvA(bob, allkeys), server)
cse303.check_file_list(allkeys, ["k1", "k2", "k3", "k4", "k5", "k6", "k7", "k8", "k9", "k10", "k11", "k12", "k13", "k14", "k15", "k16"])
cse303.do_cmd("Getting key k8.", "ERR_QUOTA_DOWN", client.kvG(bob, "k8"), server)
cse303.do_cmd("Getting all keys.", "___OK___", client.kvA(bob, allkeys), server)
cse303.check_file_list(allkeys, ["k1", "k2", "k3", "k4", "k5", "k6", "k7", "k8", "k9", "k10", "k11", "k12", "k13", "k14", "k15", "k16"])

print()
cse303.line()
print("Test #4: Quotas are affected by KVT")
cse303.line()
for i in range(1,8):
    cse303.do_cmd("Getting key k"+str(i)+".", "___OK___", client.kvG(alice, "k"+str(i)), server)
    cse303.check_file_result(t1kname, "k"+str(i))
cse303.do_cmd("Getting top keys", "___OK___", client.kvT(alice, topkeys), server)
cse303.check_file_list_nosort(topkeys, ["k7", "k6", "k5", "k4"])
cse303.do_cmd("Getting key k7.", "ERR_QUOTA_DOWN", client.kvG(alice, "k7"), server)
cse303.do_cmd("Getting top keys", "___OK___", client.kvT(alice, topkeys), server)
cse303.check_file_list_nosort(topkeys, ["k7", "k6", "k5", "k4"])
cse303.do_cmd("Stopping server.", "___OK___", client.bye(alice), server)
cse303.await_server("Waiting for server to shut down.", "Server terminated", server)

cse303.clean_common_files(server, client)
cse303.delfile(t1kname)

print()
