const std = @import("std");
const str = @import("archive.zig").str;

pub const Header = extern struct {
    name_: [100]u8,
    mode_: [8]u8,
    owner_: [8]u8,
    group_: [8]u8,
    size_: [12]u8,
    mktime_: [12]u8,
    checksum_: [8]u8,
    type_: u8,
    linkname_: [100]u8,

    // extended
    magic_: [6]u8,
    version_: [2]u8,
    extended_: extern union {
        ustar_: Ustar,
        gnu_: Gnu,
    },

    pub const Ustar = extern struct {
        const Magic = "ustar\x00".*;
        const Version = "00".*;
        uname_: [32]u8,
        gname_: [32]u8,
        dev_major_: [8]u8,
        dev_minor_: [8]u8,
        prefix_: [155]u8,
        pad_: [12]u8,

        pub fn uname(self: *const Ustar) []const u8 {
            return str(&self.uname_);
        }

        pub fn gname(self: *const Ustar) []const u8 {
            return str(&self.gname_);
        }

        pub fn devMajor(self: *const Ustar) !u32 {
            return std.fmt.parseInt(u32, str(&self.dev_major_), 8);
        }

        pub fn devMinor(self: *const Ustar) !u32 {
            return std.fmt.parseInt(u32, str(&self.dev_minor_), 8);
        }

        pub fn prefix(self: *const Ustar) []const u8 {
            return str(&self.prefix_);
        }

        pub fn format(self: *const Ustar, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = options;
            _ = fmt;
            try writer.print("Ustar{{ .uname = \"{s}\", .gname = \"{s}\", .dev_major = {}, .dev_minor = {}, .prefix = \"{s}\" }}", .{
                self.uname(),
                self.gname(),
                self.devMajor() catch return error.Unexpected,
                self.devMinor() catch return error.Unexpected,
                self.prefix(),
            });
        }
    };

    pub const Gnu = extern struct {
        const Magic = "ustar ".*;
        const Version = " \x00".*;
        uname_: [32]u8,
        gname_: [32]u8,
        dev_major_: [8]u8,
        dev_minor_: [8]u8,
        atime_: [12]u8,
        ctime_: [12]u8,
        offset_: [12]u8,
        longnames_: [4]u8,
        unused_: u8,
        sparse_: [4]Sparse,
        is_extended_: u8,
        realsize_: [12]u8,
        pad_: [17]u8,

        pub fn uname(self: *const Gnu) []const u8 {
            return str(&self.uname_);
        }

        pub fn gname(self: *const Gnu) []const u8 {
            return str(&self.gname_);
        }

        pub fn devMajor(self: *const Gnu) ?u32 {
            return std.fmt.parseInt(u32, str(&self.dev_major_), 8) catch null;
        }

        pub fn devMinor(self: *const Gnu) ?u32 {
            return std.fmt.parseInt(u32, str(&self.dev_minor_), 8) catch null;
        }

        pub fn atime(self: *const Gnu) ?u32 {
            return std.fmt.parseInt(u32, str(&self.atime_), 8) catch null;
        }

        pub fn ctime(self: *const Gnu) ?u32 {
            return std.fmt.parseInt(u32, str(&self.ctime_), 8) catch null;
        }

        pub fn offset(self: *const Gnu) ?u32 {
            return std.fmt.parseInt(u32, str(&self.offset_), 8) catch null;
        }

        // TODO: longnames

        pub fn sparse(self: *const Gnu) *const [4]Sparse {
            return &self.sparse_;
        }

        pub fn isExtended(self: *const Gnu) u8 {
            return self.is_extended_;
        }

        pub fn realSize(self: *const Gnu) ?u32 {
            return std.fmt.parseInt(u32, str(&self.realsize_), 8) catch null;
        }

        const Sparse = extern struct {
            offset_: [12]u8,
            numbytes_: [12]u8,

            pub fn offset(self: *const Sparse) ?u32 {
                return std.fmt.parseInt(u32, str(&self.offset_), 8) catch null;
            }

            pub fn numbytes(self: *const Sparse) ?u32 {
                return std.fmt.parseInt(u32, str(&self.numbytes_), 8) catch null;
            }

            pub fn format(self: *const Sparse, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
                _ = options;
                _ = fmt;
                try writer.print("Sparse{{ .offset = {?}, .numbytes = {?} }}", .{
                    self.offset(),
                    self.numbytes(),
                });
            }
        };

        pub fn format(self: *const Gnu, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = options;
            _ = fmt;
            try writer.print("Gnu{{ .uname = \"{s}\", .gname = \"{s}\", .dev_major = {?}, .dev_minor = {?}, .atime = {?}, .ctime = {?}, .longnames = TODO, .sparse = {any}, isextended = {}, realsize = {?} }}", .{
                self.uname(),
                self.gname(),
                self.devMajor(),
                self.devMinor(),
                self.atime(),
                self.ctime(),
                // TODO: longnames
                self.sparse().*,
                self.isExtended(),
                self.realSize(),
            });
        }
    };

    pub fn name(self: *const Header) []const u8 {
        return str(&self.name_);
    }

    pub fn mode(self: *const Header) ?u32 {
        return std.fmt.parseInt(u32, str(&self.mode_), 8) catch null;
    }

    pub fn owner(self: *const Header) ?u32 {
        return std.fmt.parseInt(u32, str(&self.owner_), 8) catch null;
    }

    pub fn group(self: *const Header) ?u32 {
        return std.fmt.parseInt(u32, str(&self.group_), 8) catch null;
    }

    pub fn size(self: *const Header) ?u32 {
        return std.fmt.parseInt(u32, str(&self.size_), 8) catch null;
    }

    pub fn mktime(self: *const Header) ?u32 {
        return std.fmt.parseInt(u32, str(&self.mktime_), 8) catch null;
    }

    pub fn checksum(self: *const Header) ?u32 {
        return std.fmt.parseInt(u32, str(&self.checksum_), 8) catch null;
    }

    pub fn linkName(self: *const Header) []const u8 {
        return str(&self.linkname_);
    }

    pub fn fileType(self: *const Header) FileType {
        return @enumFromInt(self.type_);
    }

    pub const Extended = union(enum) {
        none: void,
        ustar: Ustar,
        gnu: Gnu,
    };
    pub fn extended(self: *const Header) Extended {
        if (std.mem.eql(u8, &self.magic_, &Ustar.Magic) and std.mem.eql(u8, &self.version_, &Ustar.Version))
            return .{ .ustar = self.extended_.ustar_ };

        if (std.mem.eql(u8, &self.magic_, &Gnu.Magic) and std.mem.eql(u8, &self.version_, &Gnu.Version))
            return .{ .gnu = self.extended_.gnu_ };

        return .{ .none = {} };
    }

    pub fn calculateChecksum(self: *const Header) u32 {
        const len = @offsetOf(Header, "checksum_");
        var result: u32 = 256;
        for (std.mem.asBytes(self)[0..len]) |b| {
            result += b;
        }
        for (std.mem.asBytes(self)[len + 8 ..]) |b| {
            result += b;
        }
        return result;
    }

    pub const FileType = enum(u8) {
        normal = '0',
        hard_link = '1',
        symbolic_link = '2',
        character_special = '3',
        block_special = '4',
        directory = '5',
        fifo = '6',
        contiguous = '7',
        global_extended_header = 'g',
        gnu_long_name = 'L',
        gnu_long_link = 'K',
        extended_header = 'x',
        _,

        pub fn format(self: FileType, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = options;
            _ = fmt;
            try writer.print(".{s}", .{@tagName(self)});
        }
    };
    pub fn format(self: Header, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = options;
        _ = fmt;
        try writer.print("Header{{ .name = \"{s}\", .mode = {?}, .owner = {?}, .group = {?}, .size = {?}, .checksum = {?}, .type = {?}, .linkname = \"{s}\", .extended = .{{ ", .{
            self.name(),
            self.mode(),
            self.owner(),
            self.group(),
            self.size(),
            self.checksum(),
            self.fileType(),
            self.linkName(),
        });

        switch (self.extended()) {
            .ustar => |u| {
                try writer.print(".ustar = {} ", .{u});
            },
            .gnu => |g| {
                try writer.print(".gnu = {} ", .{g});
            },
            .none => {
                try writer.print(".none ", .{});
            },
        }
        try writer.print("}} }}", .{});
    }
};

comptime {
    std.debug.assert(@sizeOf(Header) == 512);
}
