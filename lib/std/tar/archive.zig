const std = @import("std");

pub const Header = @import("Header.zig").Header;

pub const Options = struct {
    /// Number of directory levels to skip when extracting files.
    strip_components: u32 = 0,
    /// How to handle the "mode" property of files from within the tar file.
    mode_mode: ModeMode = .executable_bit_only,

    const ModeMode = enum {
        /// The mode from the tar file is completely ignored. Files are created
        /// with the default mode when creating files.
        ignore,
        /// The mode from the tar file is inspected for the owner executable bit
        /// only. This bit is copied to the group and other executable bits.
        /// Other bits of the mode are left as the default when creating files.
        executable_bit_only,
    };
};

pub fn Archive(comptime Reader: type) type {
    return struct {
        const Self = @This();
        reader: std.io.CountingReader(Reader),
        options: Options,
        next_header: u64 = 0,

        pub fn raw_next(self: *Self) !?RawEntry {
            const reader = self.reader.reader();

            var header: Header = undefined;

            while (true) {
                const offset = self.next_header - self.reader.bytes_read;
                try reader.skipBytes(offset, .{});

                header = reader.readStruct(Header) catch return null;
                self.next_header += @sizeOf(Header);

                if (std.mem.allEqual(u8, std.mem.asBytes(&header), 0))
                    return null;

                break;
            }

            if (header.checksum()) |expected| {
                const calculated = header.calculateChecksum();
                if (calculated != expected) {
                    std.log.debug("invalid checksum expected: {o} got: {o}", .{ expected, calculated });
                    return error.InvalidChecksum;
                }
            } else {
                return error.FailedToParseChecksum;
            }

            const size = header.size() orelse return error.FailedToParseSize;

            // align to the block size
            self.next_header += (size + 511) & ~@as(usize, 511);

            return RawEntry{
                .archive = self,
                .header = header,
                .end_offset = self.reader.bytes_read + size,
            };
        }

        pub fn next(self: *Self) !?Entry {
            var result = std.mem.zeroes(Entry);
            while (true) {
                result.raw_entry = (try self.raw_next()) orelse return null;
                switch (result.raw_entry.header.fileType()) {
                    .gnu_long_name => {
                        if (result.long_name.len != 0)
                            return error.LongNameAlreadyPresent;

                        const reader = result.reader();
                        try reader.streamUntilDelimiter(result.long_name.writer(), 0, std.fs.MAX_PATH_BYTES);
                        continue;
                    },
                    .gnu_long_link => {
                        if (result.long_link.len != 0)
                            return error.LongLinkAlreadyPresent;

                        const reader = result.reader();
                        try reader.streamUntilDelimiter(result.long_link.writer(), 0, std.fs.MAX_PATH_BYTES);
                        continue;
                    },
                    .extended_header => {
                        return error.TODO;
                    },
                    .normal,
                    .hard_link,
                    .symbolic_link,
                    .character_special,
                    .block_special,
                    .directory,
                    .fifo,
                    .contiguous,
                    .global_extended_header,
                    => {
                        switch (result.raw_entry.header.extended()) {
                            .ustar => |ustar| {
                                const prefix = ustar.prefix();
                                if (prefix.len > 0) {
                                    if (result.long_name.len != 0)
                                        return error.LongNameAlreadyPresent;

                                    try result.long_name.appendSlice(prefix);
                                    try result.long_name.append('/');
                                    try result.long_name.appendSlice(result.raw_entry.header.name());
                                }
                            },
                            .gnu => {}, //TODO
                            .none => {},
                        }
                        return result;
                    },
                    _ => return error.UnsupportedFileType,
                }
            }
        }

        pub const PaxIterator = struct {
            // data:
        };

        pub const Entry = struct {
            raw_entry: RawEntry,
            long_name: std.BoundedArray(u8, std.fs.MAX_PATH_BYTES),
            long_link: std.BoundedArray(u8, std.fs.MAX_PATH_BYTES),

            pub fn name(self: *const Entry) []const u8 {
                if (self.long_link.len != 0) return self.long_name.constSlice();
                return self.raw_entry.header.name();
            }

            pub fn fileType(self: *const Entry) Header.FileType {
                return self.raw_entry.header.fileType();
            }

            pub fn linkName(self: *const Entry) []const u8 {
                switch (self.fileType()) {
                    .symbolic_link => {
                        if (self.long_link.len != 0) return self.long_link.constSlice();
                        return self.raw_entry.header.linkName();
                    },
                    else => |file_type| std.debug.panic("linkName called on {}", .{file_type}),
                }
            }

            const EntryReaderError = error{} || Reader.Error || std.fmt.ParseIntError;
            const EntryReader = std.io.Reader(*const Entry, EntryReaderError, read);

            pub fn reader(self: *const Entry) EntryReader {
                return EntryReader{ .context = self };
            }

            pub fn read(self: *const Entry, buffer: []u8) EntryReaderError!usize {
                return self.raw_entry.read(buffer);
            }
        };

        pub const RawEntry = struct {
            archive: ?*Self,
            header: Header,
            end_offset: usize = 0,

            const EntryReaderError = error{} || Reader.Error || std.fmt.ParseIntError;
            const EntryReader = std.io.Reader(*const RawEntry, EntryReaderError, read);

            pub fn reader(self: *const RawEntry) EntryReader {
                return EntryReader{ .context = self };
            }

            pub fn read(self: *const RawEntry, buffer: []u8) EntryReaderError!usize {
                const max = @min(self.end_offset - self.archive.?.reader.bytes_read, buffer.len);
                if (max == 0) return 0;
                return try self.archive.?.reader.read(buffer[0..max]);
            }
        };
    };
}

pub fn archive(reader: anytype, options: Options) Archive(@TypeOf(reader)) {
    return .{ .reader = std.io.countingReader(reader), .options = options };
}

pub fn str(data: []const u8) []const u8 {
    const end = std.mem.indexOfScalar(u8, data, 0) orelse data.len;
    return data[0..end];
}

test str {
    const expectEqualStrings = std.testing.expectEqualStrings;
    try expectEqualStrings("foo", str("foo"));
    try expectEqualStrings("foo", str("foo\x00bar"));
}

pub fn stripComponents(path: []const u8, count: u32) ![]const u8 {
    var i: usize = 0;
    var c = count;
    while (c > 0) : (c -= 1) {
        if (std.mem.indexOfScalarPos(u8, path, i, '/')) |pos| {
            i = pos + 1;
        } else {
            return error.TarComponentsOutsideStrippedPrefix;
        }
    }
    return path[i..];
}

test stripComponents {
    const expectEqualStrings = std.testing.expectEqualStrings;
    try expectEqualStrings("a/b/c", try stripComponents("a/b/c", 0));
    try expectEqualStrings("b/c", try stripComponents("a/b/c", 1));
    try expectEqualStrings("c", try stripComponents("a/b/c", 2));
}

const two_files_simple = @embedFile("archives/two_files_simple.tar");

test "tar - iterating over files ignoring content" {
    var fba = std.io.fixedBufferStream(two_files_simple);
    var a = archive(fba.reader(), .{});

    const file_a = (try a.next_raw_entry(null)).?;
    try std.testing.expectEqualSlices(u8, "a", file_a.header.name());

    const file_b = (try a.next_raw_entry(null)).?;
    try std.testing.expectEqualSlices(u8, "b", file_b.header.name());

    std.debug.assert(try a.next_entry() == null);
}

test "tar - iterating over files and read the content" {
    var fba = std.io.fixedBufferStream(two_files_simple);
    var a = archive(fba.reader(), .{});

    const file_a = (try a.next_raw_entry(null)).?;
    try std.testing.expectEqualSlices(u8, "a", file_a.header.name());

    const file_a_content = try file_a.reader().readAllAlloc(std.testing.allocator, 256);
    defer std.testing.allocator.free(file_a_content);
    try std.testing.expectEqualSlices(u8, "first file\n", file_a_content);

    const file_b = (try a.next_raw_entry(null)).?;
    try std.testing.expectEqualSlices(u8, "b", file_b.header.name());

    const file_b_content = try file_b.reader().readAllAlloc(std.testing.allocator, 256);
    defer std.testing.allocator.free(file_b_content);
    try std.testing.expectEqualSlices(u8, "second file\n", file_b_content);

    std.debug.assert(try a.next_entry() == null);
}
