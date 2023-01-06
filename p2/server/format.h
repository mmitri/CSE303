#pragma once

#include <string>

/// format.h defines the file format used by the server.  Note that the format
/// changes between phase 1 and phase 2 of the assignment, and again between
/// phase 2 and phase 3.

/// In phase 1, there is only one table that needs to be persisted to file: the
/// authentication table.  Furthermore, this authentication table is only
/// persisted in response to an explicit SAV command.  To persist the table to a
/// file, each entry needs to be written to the file.  The format of each entry
/// is as follows:
///
/// Authentication entry format:
/// - 8-byte constant AUTHAUTH
/// - 8-byte binary write of the length of the username
/// - Binary write of the bytes of the username
/// - 8-byte binary write of the length of the salt
/// - Binary write of the bytes of the salt
/// - 8-byte binary write of the length of the hashed password
/// - Binary write of the bytes of the hashed password
/// - 8-byte binary write of the length of the profile file
/// - If the profile file isn't empty, binary write of the bytes of the profile
///   file
/// - Binary write of some bytes of padding, to ensure that the next entry will
///   be aligned on an 8-byte boundary.
///
/// Note that there are no newline or other delimiters required by the format.
/// The 8-byte constant, coupled with the *binary* writes of the lengths of the
/// fields, suffice to unambiguously represent the file contents.  Note that the
/// username, salt, and hashed password must each be at least one byte.

/// A unique 8-byte code to use as a prefix each time an AuthTable Entry is
/// written to disk.
const std::string AUTHENTRY = "AUTHAUTH";

/// In phase 2, the authentication table does not change, but a key/value store
/// is added to the server.  This key/value store needs to be persisted.  It is
/// only persisted in response to an explicit SAV command, and it must be
/// persisted in the same consistent, indivisible operation that persists the
/// authentication table.  To persist the table to a file, each entry needs to
/// be written to the file. The format of each entry is as follows:
///
/// K/V entry format:
/// - 8-byte constant KVKVKVKV
/// - 8-byte binary write of the length of the key
/// - Binary write of the bytes of the key
/// - 8-byte binary write of the length of the value
/// - Binary write of the bytes of the value
/// - Binary write of some bytes of padding, to ensure that the next entry will
///   be aligned on an 8-byte boundary.
///
/// Note that the constants are always 8 bytes.  This makes it much easier to
/// parse the file.  This design decision is analogous to the one that resulted
/// in all commands being 8 bytes.  Note, too, that keys and values never have a
/// length of zero.
///
/// The server should assume that it is possible for authentication table
/// entries and key/value table entries to be interspersed in any arbitrary
/// order.  However, each entry itself should appear in the file without being
/// interleaved with other entries.

/// A unique 8-byte code to use as a prefix each time a KV pair is written to
/// disk.
const std::string KVENTRY = "KVKVKVKV";
