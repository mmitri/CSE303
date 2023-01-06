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
server = cse303.ServerConfig("./obj64/server.exe", "9999", "rsa", "company.dir", "4", "1024", "6", "8192", "8192", "24", "4")
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
print("Test #1: Use KVI to expend the upload quota")
cse303.line()
server.pid = cse303.do_cmd_a("Starting server:", [
    "Listening on port "+server.port+" using (key/data) = (rsa, "+server.dirfile+")",
    "Generating RSA keys as ("+server.keyfile+".pub, "+server.keyfile+".pri)",
    "File not found: " + server.dirfile], server.launchcmd())
cse303.waitfor(2)
cse303.do_cmd("Registering new user alice.", "___OK___", client.reg(alice), server)
cse303.after(server.pid) # need an extra cleanup to handle the KEY that was sent by first REG
cse303.do_cmd("Registering new user bob.", "___OK___", client.reg(bob), server)
for i in range(1,9):
    cse303.do_cmd("Setting key k"+str(i)+" to 1K file.", "___OK___", client.kvI(alice, "k"+str(i), t1kname), server)
cse303.do_cmd("Setting key k9 to 1K file.", "ERR_QUOTA_UP", client.kvI(alice, "k9", t1kname), server)

print()
cse303.line()
print("Test #2: Use KVU (insert) to expend another user's upload quota")
cse303.line()
for i in range(1,9):
    cse303.do_cmd("Upserting key b"+str(i)+" to 1K file.", "OK_INSERT", client.kvU(bob, "b"+str(i), t1kname), server)
cse303.do_cmd("Upserting key b9 to 1K file.", "ERR_QUOTA_UP", client.kvU(bob, "b9", t1kname), server)

print()
cse303.line()
print("Test #3: Waiting resets quotas, which are then expended with KVU (update)")
cse303.line()
print("Waiting for " + server.qi + " seconds so that quotas can reset")
cse303.waitfor(int(server.qi) + 1) # one extra, to play it safe...
for i in range(1,9):
    cse303.do_cmd("Upserting key b"+str(i)+" to 1K file.", "OK_UPDATE", client.kvU(bob, "b"+str(i), t1kname), server)
cse303.do_cmd("Upserting key b9 to 1K file.", "ERR_QUOTA_UP", client.kvU(bob, "b9", t1kname), server)

print()
cse303.line()
print("Test #4: Waiting resets quotas, which are then expended with a mix of operations")
cse303.line()
print("Waiting for " + server.qi + " seconds so that quotas can reset")
cse303.waitfor(int(server.qi) + 1) # one extra, to play it safe...
cse303.do_cmd("Inserting key c1 to 1K file.", "___OK___", client.kvI(bob, "c1", t1kname), server)
cse303.do_cmd("Inserting key c2 to 1K file.", "___OK___", client.kvI(bob, "c2", t1kname), server)
cse303.do_cmd("Inserting key c3 to 1K file.", "___OK___", client.kvI(bob, "c3", t1kname), server)
cse303.do_cmd("Upserting key c4 to 1K file.", "OK_INSERT", client.kvU(bob, "c4", t1kname), server)
cse303.do_cmd("Upserting key c5 to 1K file.", "OK_INSERT", client.kvU(bob, "c5", t1kname), server)
cse303.do_cmd("Upserting key c6 to 1K file.", "OK_INSERT", client.kvU(bob, "c6", t1kname), server)
cse303.do_cmd("Upserting key b7 to 1K file.", "OK_UPDATE", client.kvU(bob, "b7", t1kname), server)
cse303.do_cmd("Upserting key b8 to 1K file.", "OK_UPDATE", client.kvU(bob, "b8", t1kname), server)
cse303.do_cmd("Upserting key b9 to 1K file.", "ERR_QUOTA_UP", client.kvU(bob, "c9", t1kname), server)

print()
cse303.line()
print("Test #5: Invalid inserts count against quota")
cse303.line()
print("Waiting for " + server.qi + " seconds so that quotas can reset")
cse303.waitfor(int(server.qi) + 1) # one extra, to play it safe...
for i in range(1,9):
    cse303.do_cmd("Inserting key b"+str(i)+" to 1K file.", "ERR_KEY", client.kvI(bob, "b"+str(i), t1kname), server)
cse303.do_cmd("Inserting key b1 to 1K file.", "ERR_QUOTA_UP", client.kvI(bob, "b1", t1kname), server)

cse303.do_cmd("Stopping server.", "___OK___", client.bye(alice), server)
cse303.await_server("Waiting for server to shut down.", "Server terminated", server)

cse303.clean_common_files(server, client)
cse303.delfile(t1kname)

print()
