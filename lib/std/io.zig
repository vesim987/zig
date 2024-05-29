const std = @import("std.zig");
const builtin = @import("builtin");
const root = @import("root");
const c = std.c;
const is_windows = builtin.os.tag == .windows;
const windows = std.os.windows;
const posix = std.posix;
const native_endian = builtin.target.cpu.arch.endian();

const math = std.math;
const assert = std.debug.assert;
const fs = std.fs;
const mem = std.mem;
const meta = std.meta;
const File = std.fs.File;
const Allocator = std.mem.Allocator;

fn getStdOutHandle() posix.fd_t {
    if (is_windows) {
        if (builtin.zig_backend == .stage2_aarch64) {
            // TODO: this is just a temporary workaround until we advance aarch64 backend further along.
            return windows.GetStdHandle(windows.STD_OUTPUT_HANDLE) catch windows.INVALID_HANDLE_VALUE;
        }
        return windows.peb().ProcessParameters.hStdOutput;
    }

    if (@hasDecl(root, "os") and @hasDecl(root.os, "io") and @hasDecl(root.os.io, "getStdOutHandle")) {
        return root.os.io.getStdOutHandle();
    }

    return posix.STDOUT_FILENO;
}

pub fn getStdOut() File {
    return .{ .handle = getStdOutHandle() };
}

fn getStdErrHandle() posix.fd_t {
    if (is_windows) {
        if (builtin.zig_backend == .stage2_aarch64) {
            // TODO: this is just a temporary workaround until we advance aarch64 backend further along.
            return windows.GetStdHandle(windows.STD_ERROR_HANDLE) catch windows.INVALID_HANDLE_VALUE;
        }
        return windows.peb().ProcessParameters.hStdError;
    }

    if (@hasDecl(root, "os") and @hasDecl(root.os, "io") and @hasDecl(root.os.io, "getStdErrHandle")) {
        return root.os.io.getStdErrHandle();
    }

    return posix.STDERR_FILENO;
}

pub fn getStdErr() File {
    return .{ .handle = getStdErrHandle() };
}

fn getStdInHandle() posix.fd_t {
    if (is_windows) {
        if (builtin.zig_backend == .stage2_aarch64) {
            // TODO: this is just a temporary workaround until we advance aarch64 backend further along.
            return windows.GetStdHandle(windows.STD_INPUT_HANDLE) catch windows.INVALID_HANDLE_VALUE;
        }
        return windows.peb().ProcessParameters.hStdInput;
    }

    if (@hasDecl(root, "os") and @hasDecl(root.os, "io") and @hasDecl(root.os.io, "getStdInHandle")) {
        return root.os.io.getStdInHandle();
    }

    return posix.STDIN_FILENO;
}

pub fn getStdIn() File {
    return .{ .handle = getStdInHandle() };
}

pub fn GenericReader(
    comptime Context: type,
    comptime ReadError: type,
    /// Returns the number of bytes read. It may be less than buffer.len.
    /// If the number of bytes read is 0, it means end of stream.
    /// End of stream is not an error condition.
    comptime readFn: fn (context: Context, buffer: []u8) ReadError!usize,
) type {
    return struct {
        context: Context,

        pub const Error = ReadError;
        pub const NoEofError = ReadError || error{
            EndOfStream,
        };
        /// Returns the number of bytes read. It may be less than buffer.len.
        /// If the number of bytes read is 0, it means end of stream.
        /// End of stream is not an error condition.
        pub fn read(self: Self, buffer: []u8) Error!usize {
            return readFn(self.context, buffer);
        }

        /// Returns the number of bytes read. If the number read is smaller than `buffer.len`, it
        /// means the stream reached the end. Reaching the end of a stream is not an error
        /// condition.
        pub fn readAll(self: Self, buffer: []u8) Error!usize {
            return readAtLeast(self, buffer, buffer.len);
        }

        /// Returns the number of bytes read, calling the underlying read
        /// function the minimal number of times until the buffer has at least
        /// `len` bytes filled. If the number read is less than `len` it means
        /// the stream reached the end. Reaching the end of the stream is not
        /// an error condition.
        pub fn readAtLeast(self: Self, buffer: []u8, len: usize) Error!usize {
            assert(len <= buffer.len);
            var index: usize = 0;
            while (index < len) {
                const amt = try self.read(buffer[index..]);
                if (amt == 0) break;
                index += amt;
            }
            return index;
        }

        /// If the number read would be smaller than `buf.len`, `error.EndOfStream` is returned instead.
        pub fn readNoEof(self: Self, buf: []u8) NoEofError!void {
            const amt_read = try self.readAll(buf);
            if (amt_read < buf.len) return error.EndOfStream;
        }

        /// Appends to the `std.ArrayList` contents by reading from the stream
        /// until end of stream is found.
        /// If the number of bytes appended would exceed `max_append_size`,
        /// `error.StreamTooLong` is returned
        /// and the `std.ArrayList` has exactly `max_append_size` bytes appended.
        pub fn readAllArrayList(
            self: Self,
            array_list: *std.ArrayList(u8),
            max_append_size: usize,
        ) Error!void {
            return self.readAllArrayListAligned(null, array_list, max_append_size);
        }

        pub fn readAllArrayListAligned(
            self: Self,
            comptime alignment: ?u29,
            array_list: *std.ArrayListAligned(u8, alignment),
            max_append_size: usize,
        ) Error!void {
            try array_list.ensureTotalCapacity(@min(max_append_size, 4096));
            const original_len = array_list.items.len;
            var start_index: usize = original_len;
            while (true) {
                array_list.expandToCapacity();
                const dest_slice = array_list.items[start_index..];
                const bytes_read = try self.readAll(dest_slice);
                start_index += bytes_read;

                if (start_index - original_len > max_append_size) {
                    array_list.shrinkAndFree(original_len + max_append_size);
                    return error.StreamTooLong;
                }

                if (bytes_read != dest_slice.len) {
                    array_list.shrinkAndFree(start_index);
                    return;
                }

                // This will trigger ArrayList to expand superlinearly at whatever its growth rate is.
                try array_list.ensureTotalCapacity(start_index + 1);
            }
        }

        /// Allocates enough memory to hold all the contents of the stream. If the allocated
        /// memory would be greater than `max_size`, returns `error.StreamTooLong`.
        /// Caller owns returned memory.
        /// If this function returns an error, the contents from the stream read so far are lost.
        pub fn readAllAlloc(self: Self, allocator: mem.Allocator, max_size: usize) Error![]u8 {
            var array_list = std.ArrayList(u8).init(allocator);
            defer array_list.deinit();
            try self.readAllArrayList(&array_list, max_size);
            return try array_list.toOwnedSlice();
        }

        /// Deprecated: use `streamUntilDelimiter` with ArrayList's writer instead.
        /// Replaces the `std.ArrayList` contents by reading from the stream until `delimiter` is found.
        /// Does not include the delimiter in the result.
        /// If the `std.ArrayList` length would exceed `max_size`, `error.StreamTooLong` is returned and the
        /// `std.ArrayList` is populated with `max_size` bytes from the stream.
        pub fn readUntilDelimiterArrayList(
            self: Self,
            array_list: *std.ArrayList(u8),
            delimiter: u8,
            max_size: usize,
        ) Error!void {
            array_list.shrinkRetainingCapacity(0);
            try self.streamUntilDelimiter(array_list.writer(), delimiter, max_size);
        }

        /// Deprecated: use `streamUntilDelimiter` with ArrayList's writer instead.
        /// Allocates enough memory to read until `delimiter`. If the allocated
        /// memory would be greater than `max_size`, returns `error.StreamTooLong`.
        /// Caller owns returned memory.
        /// If this function returns an error, the contents from the stream read so far are lost.
        pub fn readUntilDelimiterAlloc(
            self: Self,
            allocator: mem.Allocator,
            delimiter: u8,
            max_size: usize,
        ) Error![]u8 {
            var array_list = std.ArrayList(u8).init(allocator);
            defer array_list.deinit();
            try self.streamUntilDelimiter(array_list.writer(), delimiter, max_size);
            return try array_list.toOwnedSlice();
        }

        /// Deprecated: use `streamUntilDelimiter` with FixedBufferStream's writer instead.
        /// Reads from the stream until specified byte is found. If the buffer is not
        /// large enough to hold the entire contents, `error.StreamTooLong` is returned.
        /// If end-of-stream is found, `error.EndOfStream` is returned.
        /// Returns a slice of the stream data, with ptr equal to `buf.ptr`. The
        /// delimiter byte is written to the output buffer but is not included
        /// in the returned slice.
        pub fn readUntilDelimiter(self: Self, buf: []u8, delimiter: u8) Error![]u8 {
            var fbs = std.io.fixedBufferStream(buf);
            try self.streamUntilDelimiter(fbs.writer(), delimiter, fbs.buffer.len);
            const output = fbs.getWritten();
            buf[output.len] = delimiter; // emulating old behaviour
            return output;
        }

        /// Deprecated: use `streamUntilDelimiter` with ArrayList's (or any other's) writer instead.
        /// Allocates enough memory to read until `delimiter` or end-of-stream.
        /// If the allocated memory would be greater than `max_size`, returns
        /// `error.StreamTooLong`. If end-of-stream is found, returns the rest
        /// of the stream. If this function is called again after that, returns
        /// null.
        /// Caller owns returned memory.
        /// If this function returns an error, the contents from the stream read so far are lost.
        pub fn readUntilDelimiterOrEofAlloc(
            self: Self,
            allocator: mem.Allocator,
            delimiter: u8,
            max_size: usize,
        ) Error!?[]u8 {
            var array_list = std.ArrayList(u8).init(allocator);
            defer array_list.deinit();
            self.streamUntilDelimiter(array_list.writer(), delimiter, max_size) catch |err| switch (err) {
                error.EndOfStream => if (array_list.items.len == 0) {
                    return null;
                },
                else => |e| return e,
            };
            return try array_list.toOwnedSlice();
        }

        /// Deprecated: use `streamUntilDelimiter` with FixedBufferStream's writer instead.
        /// Reads from the stream until specified byte is found. If the buffer is not
        /// large enough to hold the entire contents, `error.StreamTooLong` is returned.
        /// If end-of-stream is found, returns the rest of the stream. If this
        /// function is called again after that, returns null.
        /// Returns a slice of the stream data, with ptr equal to `buf.ptr`. The
        /// delimiter byte is written to the output buffer but is not included
        /// in the returned slice.
        pub fn readUntilDelimiterOrEof(self: Self, buf: []u8, delimiter: u8) Error!?[]u8 {
            var fbs = std.io.fixedBufferStream(buf);
            self.streamUntilDelimiter(fbs.writer(), delimiter, fbs.buffer.len) catch |err| switch (err) {
                error.EndOfStream => if (fbs.getWritten().len == 0) {
                    return null;
                },

                else => |e| return e,
            };
            const output = fbs.getWritten();
            buf[output.len] = delimiter; // emulating old behaviour
            return output;
        }

        /// Appends to the `writer` contents by reading from the stream until `delimiter` is found.
        /// Does not write the delimiter itself.
        /// If `optional_max_size` is not null and amount of written bytes exceeds `optional_max_size`,
        /// returns `error.StreamTooLong` and finishes appending.
        /// If `optional_max_size` is null, appending is unbounded.
        pub fn streamUntilDelimiter(
            self: Self,
            writer: anytype,
            delimiter: u8,
            optional_max_size: ?usize,
        ) Error!void {
            if (optional_max_size) |max_size| {
                for (0..max_size) |_| {
                    const byte: u8 = try self.readByte();
                    if (byte == delimiter) return;
                    try writer.writeByte(byte);
                }
                return error.StreamTooLong;
            } else {
                while (true) {
                    const byte: u8 = try self.readByte();
                    if (byte == delimiter) return;
                    try writer.writeByte(byte);
                }
                // Can not throw `error.StreamTooLong` since there are no boundary.
            }
        }

        /// Reads from the stream until specified byte is found, discarding all data,
        /// including the delimiter.
        /// If end-of-stream is found, this function succeeds.
        pub fn skipUntilDelimiterOrEof(self: Self, delimiter: u8) Error!void {
            while (true) {
                const byte = self.readByte() catch |err| switch (err) {
                    error.EndOfStream => return,
                    else => |e| return e,
                };
                if (byte == delimiter) return;
            }
        }

        /// Reads 1 byte from the stream or returns `error.EndOfStream`.
        pub fn readByte(self: Self) NoEofError!u8 {
            var result: [1]u8 = undefined;
            const amt_read = try self.read(result[0..]);
            if (amt_read < 1) return error.EndOfStream;
            return result[0];
        }

        /// Same as `readByte` except the returned byte is signed.
        pub fn readByteSigned(self: Self) NoEofError!i8 {
            return @as(i8, @bitCast(try self.readByte()));
        }

        /// Reads exactly `num_bytes` bytes and returns as an array.
        /// `num_bytes` must be comptime-known
        pub fn readBytesNoEof(self: Self, comptime num_bytes: usize) NoEofError![num_bytes]u8 {
            var bytes: [num_bytes]u8 = undefined;
            try self.readNoEof(&bytes);
            return bytes;
        }

        /// Reads bytes until `bounded.len` is equal to `num_bytes`,
        /// or the stream ends.
        ///
        /// * it is assumed that `num_bytes` will not exceed `bounded.capacity()`
        pub fn readIntoBoundedBytes(
            self: Self,
            comptime num_bytes: usize,
            bounded: *std.BoundedArray(u8, num_bytes),
        ) Error!void {
            while (bounded.len < num_bytes) {
                // get at most the number of bytes free in the bounded array
                const bytes_read = try self.read(bounded.unusedCapacitySlice());
                if (bytes_read == 0) return;

                // bytes_read will never be larger than @TypeOf(bounded.len)
                // due to `self.read` being bounded by `bounded.unusedCapacitySlice()`
                bounded.len += @as(@TypeOf(bounded.len), @intCast(bytes_read));
            }
        }

        /// Reads at most `num_bytes` and returns as a bounded array.
        pub fn readBoundedBytes(self: Self, comptime num_bytes: usize) Error!std.BoundedArray(u8, num_bytes) {
            var result = std.BoundedArray(u8, num_bytes){};
            try self.readIntoBoundedBytes(num_bytes, &result);
            return result;
        }

        pub inline fn readInt(self: Self, comptime T: type, endian: std.builtin.Endian) NoEofError!T {
            const bytes = try self.readBytesNoEof(@divExact(@typeInfo(T).Int.bits, 8));
            return mem.readInt(T, &bytes, endian);
        }

        pub fn readVarInt(
            self: Self,
            comptime ReturnType: type,
            endian: std.builtin.Endian,
            size: usize,
        ) Error!ReturnType {
            assert(size <= @sizeOf(ReturnType));
            var bytes_buf: [@sizeOf(ReturnType)]u8 = undefined;
            const bytes = bytes_buf[0..size];
            try self.readNoEof(bytes);
            return mem.readVarInt(ReturnType, bytes, endian);
        }

        /// Optional parameters for `skipBytes`
        pub const SkipBytesOptions = struct {
            buf_size: usize = 512,
        };

        // `num_bytes` is a `u64` to match `off_t`
        /// Reads `num_bytes` bytes from the stream and discards them
        pub fn skipBytes(self: Self, num_bytes: u64, comptime options: SkipBytesOptions) Error!void {
            var buf: [options.buf_size]u8 = undefined;
            var remaining = num_bytes;

            while (remaining > 0) {
                const amt = @min(remaining, options.buf_size);
                try self.readNoEof(buf[0..amt]);
                remaining -= amt;
            }
        }

        /// Reads `slice.len` bytes from the stream and returns if they are the same as the passed slice
        pub fn isBytes(self: Self, slice: []const u8) Error!bool {
            var i: usize = 0;
            var matches = true;
            while (i < slice.len) : (i += 1) {
                if (slice[i] != try self.readByte()) {
                    matches = false;
                }
            }
            return matches;
        }

        pub fn readStruct(self: Self, comptime T: type) NoEofError!T {
            // Only extern and packed structs have defined in-memory layout.
            comptime assert(@typeInfo(T).Struct.layout != .auto);
            var res: [1]T = undefined;
            try self.readNoEof(mem.sliceAsBytes(res[0..]));
            return res[0];
        }

        pub fn readStructEndian(self: Self, comptime T: type, endian: std.builtin.Endian) Error!T {
            var res = try self.readStruct(T);
            if (native_endian != endian) {
                mem.byteSwapAllFields(T, &res);
            }
            return res;
        }

        /// Reads an integer with the same size as the given enum's tag type. If the integer matches
        /// an enum tag, casts the integer to the enum tag and returns it. Otherwise, returns an `error.InvalidValue`.
        /// TODO optimization taking advantage of most fields being in order
        pub fn readEnum(self: Self, comptime Enum: type, endian: std.builtin.Endian) Error!Enum {
            const E = error{
                /// An integer was read, but it did not match any of the tags in the supplied enum.
                InvalidValue,
            };
            const type_info = @typeInfo(Enum).Enum;
            const tag = try self.readInt(type_info.tag_type, endian);

            inline for (std.meta.fields(Enum)) |field| {
                if (tag == field.value) {
                    return @field(Enum, field.name);
                }
            }

            return E.InvalidValue;
        }

        /// Reads the stream until the end, ignoring all the data.
        /// Returns the number of bytes discarded.
        pub fn discard(self: Self) Error!u64 {
            var trash: [4096]u8 = undefined;
            var index: u64 = 0;
            while (true) {
                const n = try self.read(&trash);
                if (n == 0) return index;
                index += n;
            }
        }

        // pub inline fn any(self: *const Self) AnyReader {
        //     return .{
        //         .context = .{
        //             .context = @ptrCast(&self.context),
        //             .readFn = typeErasedReadFn,
        //         },
        //     };
        // }

        const Self = @This();

        fn typeErasedReadFn(context: *const anyopaque, buffer: []u8) anyerror!usize {
            const ptr: *const Context = @alignCast(@ptrCast(context));
            return readFn(ptr.*, buffer);
        }
    };
}

pub fn GenericWriter(
    comptime Context: type,
    comptime WriteError: type,
    comptime writeFn: fn (context: Context, bytes: []const u8) WriteError!usize,
) type {
    return struct {
        context: Context,

        const Self = @This();
        pub const Error = WriteError;

        pub inline fn write(self: Self, bytes: []const u8) Error!usize {
            return writeFn(self.context, bytes);
        }

        pub inline fn writeAll(self: Self, bytes: []const u8) Error!void {
            return @errorCast(self.any().writeAll(bytes));
        }

        pub inline fn print(self: Self, comptime format: []const u8, args: anytype) Error!void {
            return @errorCast(self.any().print(format, args));
        }

        pub inline fn writeByte(self: Self, byte: u8) Error!void {
            return @errorCast(self.any().writeByte(byte));
        }

        pub inline fn writeByteNTimes(self: Self, byte: u8, n: usize) Error!void {
            return @errorCast(self.any().writeByteNTimes(byte, n));
        }

        pub inline fn writeBytesNTimes(self: Self, bytes: []const u8, n: usize) Error!void {
            return @errorCast(self.any().writeBytesNTimes(bytes, n));
        }

        pub inline fn writeInt(self: Self, comptime T: type, value: T, endian: std.builtin.Endian) Error!void {
            return @errorCast(self.any().writeInt(T, value, endian));
        }

        pub inline fn writeStruct(self: Self, value: anytype) Error!void {
            return @errorCast(self.any().writeStruct(value));
        }

        pub inline fn writeStructEndian(self: Self, value: anytype, endian: std.builtin.Endian) Error!void {
            return @errorCast(self.any().writeStructEndian(value, endian));
        }

        pub inline fn any(self: *const Self) AnyWriter {
            return .{
                .context = @ptrCast(&self.context),
                .writeFn = typeErasedWriteFn,
            };
        }

        fn typeErasedWriteFn(context: *const anyopaque, bytes: []const u8) anyerror!usize {
            const ptr: *const Context = @alignCast(@ptrCast(context));
            return writeFn(ptr.*, bytes);
        }
    };
}

/// Deprecated; consider switching to `AnyReader` or use `GenericReader`
/// to use previous API.
pub const Reader = GenericReader;
/// Deprecated; consider switching to `AnyWriter` or use `GenericWriter`
/// to use previous API.
pub const Writer = GenericWriter;

const AnyReaderContext = struct {
    context: *anyopaque,
    readFn: *const fn (*anyopaque, []u8) anyerror!usize,

    fn read(context: AnyReaderContext, buffer: []u8) anyerror!usize {
        return context.readFn(context.context, buffer);
    }
};
pub const AnyReader = std.io.GenericReader(AnyReaderContext, anyerror, AnyReaderContext.read);
pub const AnyWriter = @import("io/Writer.zig");

pub const SeekableStream = @import("io/seekable_stream.zig").SeekableStream;

pub const BufferedWriter = @import("io/buffered_writer.zig").BufferedWriter;
pub const bufferedWriter = @import("io/buffered_writer.zig").bufferedWriter;

pub const BufferedReader = @import("io/buffered_reader.zig").BufferedReader;
pub const bufferedReader = @import("io/buffered_reader.zig").bufferedReader;
pub const bufferedReaderSize = @import("io/buffered_reader.zig").bufferedReaderSize;

pub const FixedBufferStream = @import("io/fixed_buffer_stream.zig").FixedBufferStream;
pub const fixedBufferStream = @import("io/fixed_buffer_stream.zig").fixedBufferStream;

pub const CWriter = @import("io/c_writer.zig").CWriter;
pub const cWriter = @import("io/c_writer.zig").cWriter;

pub const LimitedReader = @import("io/limited_reader.zig").LimitedReader;
pub const limitedReader = @import("io/limited_reader.zig").limitedReader;

pub const CountingWriter = @import("io/counting_writer.zig").CountingWriter;
pub const countingWriter = @import("io/counting_writer.zig").countingWriter;
pub const CountingReader = @import("io/counting_reader.zig").CountingReader;
pub const countingReader = @import("io/counting_reader.zig").countingReader;

pub const MultiWriter = @import("io/multi_writer.zig").MultiWriter;
pub const multiWriter = @import("io/multi_writer.zig").multiWriter;

pub const BitReader = @import("io/bit_reader.zig").BitReader;
pub const bitReader = @import("io/bit_reader.zig").bitReader;

pub const BitWriter = @import("io/bit_writer.zig").BitWriter;
pub const bitWriter = @import("io/bit_writer.zig").bitWriter;

pub const ChangeDetectionStream = @import("io/change_detection_stream.zig").ChangeDetectionStream;
pub const changeDetectionStream = @import("io/change_detection_stream.zig").changeDetectionStream;

pub const FindByteWriter = @import("io/find_byte_writer.zig").FindByteWriter;
pub const findByteWriter = @import("io/find_byte_writer.zig").findByteWriter;

pub const BufferedAtomicFile = @import("io/buffered_atomic_file.zig").BufferedAtomicFile;

pub const StreamSource = @import("io/stream_source.zig").StreamSource;

pub const tty = @import("io/tty.zig");

/// A Writer that doesn't write to anything.
pub const null_writer: NullWriter = .{ .context = {} };

const NullWriter = Writer(void, error{}, dummyWrite);
fn dummyWrite(context: void, data: []const u8) error{}!usize {
    _ = context;
    return data.len;
}

test null_writer {
    null_writer.writeAll("yay" ** 10) catch |err| switch (err) {};
}

pub fn poll(
    allocator: Allocator,
    comptime StreamEnum: type,
    files: PollFiles(StreamEnum),
) Poller(StreamEnum) {
    const enum_fields = @typeInfo(StreamEnum).Enum.fields;
    var result: Poller(StreamEnum) = undefined;

    if (is_windows) result.windows = .{
        .first_read_done = false,
        .overlapped = [1]windows.OVERLAPPED{
            mem.zeroes(windows.OVERLAPPED),
        } ** enum_fields.len,
        .active = .{
            .count = 0,
            .handles_buf = undefined,
            .stream_map = undefined,
        },
    };

    inline for (0..enum_fields.len) |i| {
        result.fifos[i] = .{
            .allocator = allocator,
            .buf = &.{},
            .head = 0,
            .count = 0,
        };
        if (is_windows) {
            result.windows.active.handles_buf[i] = @field(files, enum_fields[i].name).handle;
        } else {
            result.poll_fds[i] = .{
                .fd = @field(files, enum_fields[i].name).handle,
                .events = posix.POLL.IN,
                .revents = undefined,
            };
        }
    }
    return result;
}

pub const PollFifo = std.fifo.LinearFifo(u8, .Dynamic);

pub fn Poller(comptime StreamEnum: type) type {
    return struct {
        const enum_fields = @typeInfo(StreamEnum).Enum.fields;
        const PollFd = if (is_windows) void else posix.pollfd;

        fifos: [enum_fields.len]PollFifo,
        poll_fds: [enum_fields.len]PollFd,
        windows: if (is_windows) struct {
            first_read_done: bool,
            overlapped: [enum_fields.len]windows.OVERLAPPED,
            active: struct {
                count: math.IntFittingRange(0, enum_fields.len),
                handles_buf: [enum_fields.len]windows.HANDLE,
                stream_map: [enum_fields.len]StreamEnum,

                pub fn removeAt(self: *@This(), index: u32) void {
                    std.debug.assert(index < self.count);
                    for (index + 1..self.count) |i| {
                        self.handles_buf[i - 1] = self.handles_buf[i];
                        self.stream_map[i - 1] = self.stream_map[i];
                    }
                    self.count -= 1;
                }
            },
        } else void,

        const Self = @This();

        pub fn deinit(self: *Self) void {
            if (is_windows) {
                // cancel any pending IO to prevent clobbering OVERLAPPED value
                for (self.windows.active.handles_buf[0..self.windows.active.count]) |h| {
                    _ = windows.kernel32.CancelIo(h);
                }
            }
            inline for (&self.fifos) |*q| q.deinit();
            self.* = undefined;
        }

        pub fn poll(self: *Self) !bool {
            if (is_windows) {
                return pollWindows(self, null);
            } else {
                return pollPosix(self, null);
            }
        }

        pub fn pollTimeout(self: *Self, nanoseconds: u64) !bool {
            if (is_windows) {
                return pollWindows(self, nanoseconds);
            } else {
                return pollPosix(self, nanoseconds);
            }
        }

        pub inline fn fifo(self: *Self, comptime which: StreamEnum) *PollFifo {
            return &self.fifos[@intFromEnum(which)];
        }

        fn pollWindows(self: *Self, nanoseconds: ?u64) !bool {
            const bump_amt = 512;

            if (!self.windows.first_read_done) {
                // Windows Async IO requires an initial call to ReadFile before waiting on the handle
                for (0..enum_fields.len) |i| {
                    const handle = self.windows.active.handles_buf[i];
                    switch (try windowsAsyncRead(
                        handle,
                        &self.windows.overlapped[i],
                        &self.fifos[i],
                        bump_amt,
                    )) {
                        .pending => {
                            self.windows.active.handles_buf[self.windows.active.count] = handle;
                            self.windows.active.stream_map[self.windows.active.count] = @as(StreamEnum, @enumFromInt(i));
                            self.windows.active.count += 1;
                        },
                        .closed => {}, // don't add to the wait_objects list
                    }
                }
                self.windows.first_read_done = true;
            }

            while (true) {
                if (self.windows.active.count == 0) return false;

                const status = windows.kernel32.WaitForMultipleObjects(
                    self.windows.active.count,
                    &self.windows.active.handles_buf,
                    0,
                    if (nanoseconds) |ns|
                        @min(std.math.cast(u32, ns / std.time.ns_per_ms) orelse (windows.INFINITE - 1), windows.INFINITE - 1)
                    else
                        windows.INFINITE,
                );
                if (status == windows.WAIT_FAILED)
                    return windows.unexpectedError(windows.kernel32.GetLastError());
                if (status == windows.WAIT_TIMEOUT)
                    return true;

                if (status < windows.WAIT_OBJECT_0 or status > windows.WAIT_OBJECT_0 + enum_fields.len - 1)
                    unreachable;

                const active_idx = status - windows.WAIT_OBJECT_0;

                const handle = self.windows.active.handles_buf[active_idx];
                const stream_idx = @intFromEnum(self.windows.active.stream_map[active_idx]);
                var read_bytes: u32 = undefined;
                if (0 == windows.kernel32.GetOverlappedResult(
                    handle,
                    &self.windows.overlapped[stream_idx],
                    &read_bytes,
                    0,
                )) switch (windows.kernel32.GetLastError()) {
                    .BROKEN_PIPE => {
                        self.windows.active.removeAt(active_idx);
                        continue;
                    },
                    else => |err| return windows.unexpectedError(err),
                };

                self.fifos[stream_idx].update(read_bytes);

                switch (try windowsAsyncRead(
                    handle,
                    &self.windows.overlapped[stream_idx],
                    &self.fifos[stream_idx],
                    bump_amt,
                )) {
                    .pending => {},
                    .closed => self.windows.active.removeAt(active_idx),
                }
                return true;
            }
        }

        fn pollPosix(self: *Self, nanoseconds: ?u64) !bool {
            // We ask for ensureUnusedCapacity with this much extra space. This
            // has more of an effect on small reads because once the reads
            // start to get larger the amount of space an ArrayList will
            // allocate grows exponentially.
            const bump_amt = 512;

            const err_mask = posix.POLL.ERR | posix.POLL.NVAL | posix.POLL.HUP;

            const events_len = try posix.poll(&self.poll_fds, if (nanoseconds) |ns|
                std.math.cast(i32, ns / std.time.ns_per_ms) orelse std.math.maxInt(i32)
            else
                -1);
            if (events_len == 0) {
                for (self.poll_fds) |poll_fd| {
                    if (poll_fd.fd != -1) return true;
                } else return false;
            }

            var keep_polling = false;
            inline for (&self.poll_fds, &self.fifos) |*poll_fd, *q| {
                // Try reading whatever is available before checking the error
                // conditions.
                // It's still possible to read after a POLL.HUP is received,
                // always check if there's some data waiting to be read first.
                if (poll_fd.revents & posix.POLL.IN != 0) {
                    const buf = try q.writableWithSize(bump_amt);
                    const amt = try posix.read(poll_fd.fd, buf);
                    q.update(amt);
                    if (amt == 0) {
                        // Remove the fd when the EOF condition is met.
                        poll_fd.fd = -1;
                    } else {
                        keep_polling = true;
                    }
                } else if (poll_fd.revents & err_mask != 0) {
                    // Exclude the fds that signaled an error.
                    poll_fd.fd = -1;
                } else if (poll_fd.fd != -1) {
                    keep_polling = true;
                }
            }
            return keep_polling;
        }
    };
}

fn windowsAsyncRead(
    handle: windows.HANDLE,
    overlapped: *windows.OVERLAPPED,
    fifo: *PollFifo,
    bump_amt: usize,
) !enum { pending, closed } {
    while (true) {
        const buf = try fifo.writableWithSize(bump_amt);
        var read_bytes: u32 = undefined;
        const read_result = windows.kernel32.ReadFile(handle, buf.ptr, math.cast(u32, buf.len) orelse math.maxInt(u32), &read_bytes, overlapped);
        if (read_result == 0) return switch (windows.kernel32.GetLastError()) {
            .IO_PENDING => .pending,
            .BROKEN_PIPE => .closed,
            else => |err| windows.unexpectedError(err),
        };
        fifo.update(read_bytes);
    }
}

/// Given an enum, returns a struct with fields of that enum, each field
/// representing an I/O stream for polling.
pub fn PollFiles(comptime StreamEnum: type) type {
    const enum_fields = @typeInfo(StreamEnum).Enum.fields;
    var struct_fields: [enum_fields.len]std.builtin.Type.StructField = undefined;
    for (&struct_fields, enum_fields) |*struct_field, enum_field| {
        struct_field.* = .{
            .name = enum_field.name ++ "",
            .type = fs.File,
            .default_value = null,
            .is_comptime = false,
            .alignment = @alignOf(fs.File),
        };
    }
    return @Type(.{ .Struct = .{
        .layout = .auto,
        .fields = &struct_fields,
        .decls = &.{},
        .is_tuple = false,
    } });
}

test {
    _ = AnyReader;
    // _ = AnyWriter;
    // _ = @import("io/bit_reader.zig");
    // _ = @import("io/bit_writer.zig");
    // _ = @import("io/buffered_atomic_file.zig");
    // _ = @import("io/buffered_reader.zig");
    // _ = @import("io/buffered_writer.zig");
    // _ = @import("io/c_writer.zig");
    // _ = @import("io/counting_writer.zig");
    // _ = @import("io/counting_reader.zig");
    // _ = @import("io/fixed_buffer_stream.zig");
    // _ = @import("io/seekable_stream.zig");
    // _ = @import("io/stream_source.zig");
    // _ = @import("io/test.zig");
}
