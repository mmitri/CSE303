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
server = cse303.ServerConfig("./obj64/server.exe", "9999", "rsa", "company.dir", "4", "1024", "6", "8192", "8192", "4", "4")
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
print("Test #1: Use KVI to expend the request quota")
cse303.line()
server.pid = cse303.do_cmd_a("Starting server:", [
    "Listening on port "+server.port+" using (key/data) = (rsa, "+server.dirfile+")",
    "Generating RSA keys as ("+server.keyfile+".pub, "+server.keyfile+".pri)",
    "File not found: " + server.dirfile], server.launchcmd())
cse303.waitfor(2)
cse303.do_cmd("Registering new user alice.", "___OK___", client.reg(alice), server)
cse303.after(server.pid) # need an extra cleanup to handle the KEY that was sent by first REG
cse303.do_cmd("Registering new user bob.", "___OK___", client.reg(bob), server)

for i in range(1,5):
    cse303.do_cmd("Setting key k"+str(i)+" to 1K file.", "___OK___", client.kvI(alice, "k"+str(i), t1kname), server)
cse303.do_cmd("Setting key k5 to 1K file.", "ERR_QUOTA_REQ", client.kvI(alice, "k5", t1kname), server)

print()
cse303.line()
print("Test #2: Use KVG to expend another user's request quota")
cse303.line()
for i in range(1,5):
    cse303.do_cmd("Getting key k"+str(i)+".", "___OK___", client.kvG(bob, "k"+str(i)), server)
    cse303.check_file_result(t1kname, "k"+str(i))
cse303.do_cmd("Getting key k5.", "ERR_QUOTA_REQ", client.kvG(alice, "k5"), server)

print()
cse303.line()
print("Test #3: Waiting resets quotas, which are then expended with KVU (insert)")
cse303.line()
print("Waiting for " + server.qi + " seconds so that quotas can reset")
cse303.waitfor(int(server.qi) + 1) # one extra, to play it safe...
for i in range(5,9):
    cse303.do_cmd("Upserting key k"+str(i)+".", "OK_INSERT", client.kvU(bob, "k"+str(i), t1kname), server)
cse303.do_cmd("Upserting key k9.", "ERR_QUOTA_REQ", client.kvU(bob, "k9", t1kname), server)

print()
cse303.line()
print("Test #4: KVU (update) also affects quotas")
cse303.line()
for i in range(1,5):
    cse303.do_cmd("Upserting key k"+str(i)+".", "OK_UPDATE", client.kvU(alice, "k"+str(i), t1kname), server)
cse303.do_cmd("Upserting key k5.", "ERR_QUOTA_REQ", client.kvU(alice, "k5", t1kname), server)

print()
cse303.line()
print("Test #5: Waiting resets quotas, which are then expended with KVA")
cse303.line()
print("Waiting for " + server.qi + " seconds so that quotas can reset")
cse303.waitfor(int(server.qi) + 1) # one extra, to play it safe...
for i in range(4):
    cse303.do_cmd("Getting all keys.", "___OK___", client.kvA(bob, allkeys), server)
    cse303.check_file_list(allkeys, ["k1", "k2", "k3", "k4", "k5", "k6", "k7", "k8"])
cse303.do_cmd("Getting all keys.", "ERR_QUOTA_REQ", client.kvA(bob, allkeys), server)

print()
cse303.line()
print("Test #6: KVT also expends quotas")
cse303.line()
for i in range(4):
    cse303.do_cmd("Getting top keys.", "___OK___", client.kvT(alice, topkeys), server)
    cse303.check_file_list_nosort(topkeys, ["k4", "k3", "k2", "k1"])
cse303.do_cmd("Getting top keys.", "ERR_QUOTA_REQ", client.kvT(alice, topkeys), server)

print()
cse303.line()
print("Test #7: Waiting resets quotas, which are then expended with KVD")
cse303.line()
print("Waiting for " + server.qi + " seconds so that quotas can reset")
cse303.waitfor(int(server.qi) + 1) # one extra, to play it safe...
for i in range(1,5):
    cse303.do_cmd("Deleting key k"+str(i)+".", "___OK___", client.kvD(alice, "k"+str(i)), server)
cse303.do_cmd("Deleting key k5.", "ERR_QUOTA_REQ", client.kvD(alice, "k5"), server)

print()
cse303.line()
print("Test #8: Mixed requests expend the quota")
cse303.line()
cse303.do_cmd("Inserting key k4.", "___OK___", client.kvI(bob, "k4", t1kname), server)
cse303.do_cmd("Deleting key k5.", "___OK___", client.kvD(bob, "k5"), server)
cse303.do_cmd("Upserting key k7.", "OK_UPDATE", client.kvU(bob, "k7", t1kname), server)
cse303.do_cmd("Getting key k6.", "___OK___", client.kvG(bob, "k6"), server)
cse303.check_file_result(t1kname, "k6")
cse303.do_cmd("Getting key k6.", "ERR_QUOTA_REQ", client.kvG(bob, "k6"), server)

print()
cse303.line()
print("Test #9: Waiting resets quotas, which are then expended with invalid requests")
cse303.line()
print("Waiting for " + server.qi + " seconds so that quotas can reset")
cse303.waitfor(int(server.qi) + 1) # one extra, to play it safe...
cse303.do_cmd("Deleting key k5.", "ERR_KEY", client.kvD(alice, "k5"), server)
cse303.do_cmd("Getting key k6000.", "ERR_KEY", client.kvG(alice, "k6000"), server)
cse303.do_cmd("Inserting key k6.", "ERR_KEY", client.kvI(alice, "k6", t1kname), server)
cse303.do_cmd("Getting key k6000.", "ERR_KEY", client.kvG(alice, "k6000"), server)
cse303.do_cmd("Getting key k6000.", "ERR_QUOTA_REQ", client.kvG(alice, "k6000"), server)
cse303.do_cmd("Stopping server.", "___OK___", client.bye(alice), server)
cse303.await_server("Waiting for server to shut down.", "Server terminated", server)

cse303.clean_common_files(server, client)
cse303.delfile(t1kname)

print()
