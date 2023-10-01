const archive_zig = @import("tar/archive.zig");

pub const Options = archive_zig.Options;
pub const Archive = archive_zig.Archive;
pub const archive = archive_zig.archive;

pub fn pipeToFileSystem(dir: std.fs.Dir, reader: anytype, options: Options) !void {
    var a = archive(reader, options);

    while (try a.next()) |entry| {
        switch (entry.fileType()) {
            .directory => {
                const name = try archive_zig.stripComponents(entry.name(), options.strip_components);
                if (name.len != 0) {
                    std.log.debug("mkdir: {s}", .{name});
                    try dir.makePath(name);
                }
            },
            .normal => {
                const name = try archive_zig.stripComponents(entry.name(), options.strip_components);
                std.log.debug("extracting: {s}", .{name});

                if (std.fs.path.dirname(name)) |dir_name| {
                    try dir.makePath(dir_name);
                }

                var file = try dir.createFile(name, .{});
                defer file.close();

                while (true) {
                    var buf: [512]u8 = undefined;
                    const temp = buf[0..try entry.read(&buf)];
                    if (temp.len == 0) break;
                    try file.writeAll(temp);
                }
            },
            .symbolic_link => {
                const name = try archive_zig.stripComponents(entry.name(), options.strip_components);
                std.log.debug("symlink: {s} -> {s}", .{ name, entry.linkName() });

                try dir.symLink(entry.linkName(), name, .{});
            },
            .global_extended_header => {},
            else => return error.TarUnsupportedFileType,
        }
    }
}

comptime {
    _ = archive_zig;
}

const std = @import("std");
const assert = std.debug.assert;
