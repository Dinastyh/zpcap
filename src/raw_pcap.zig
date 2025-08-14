const std = @import("std");
const mem = std.mem;
const ArenaAllocator = std.heap.ArenaAllocator;
const Allocator = mem.Allocator;
const ArrayList = std.ArrayListUnmanaged;

const Self = @This();

pub const Magic = enum(u32) {
    MicroSeconds = 0xa1b2c3d4,
    NanoSeconds = 0xa1b23c4d,
    MicroSecondsBE = 0xd4c3d2d1,
    NanoSecondsBE = 0x4d3cb1a1,
};

const PcapHeader = extern struct {
    magic: u32,
    major: u16,
    minor: u16,
    reserved1: u32,
    reserved2: u32,
    snap_len: u32,
    network: u32,
};

const PcapRecordHeader = extern struct {
    ts_sec: u32,
    ts_usec: u32,
    captured_len: u32,
    original_len: u32,
};

const PcapRecord = struct {
    hdr: PcapRecordHeader,
    pkt: []u8,
};

arena: ArenaAllocator,
hdr: PcapHeader,
records: []PcapRecord,

pub fn init(allocator: Allocator, path: []const u8) !Self {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const ar_allocator = arena.allocator();

    var records: ArrayList(PcapRecord) = .empty;

    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const reader = file.reader();

    var file_hdr_buf = [_]u8{0} ** @sizeOf(PcapHeader);
    const size = try reader.read(&file_hdr_buf);
    if (size != @sizeOf(PcapHeader))
        return error.InvalidFile;

    const magic = mem.readInt(u32, file_hdr_buf[0..4], .little);
    const endian: std.builtin.Endian = switch (@as(Magic, @enumFromInt(magic))) {
        .MicroSeconds, .NanoSeconds => .little,
        .MicroSecondsBE, .NanoSecondsBE => .big,
    };

    const hdr = PcapHeader{
        .magic = magic,
        .major = mem.readInt(u16, file_hdr_buf[4..6], endian),
        .minor = mem.readInt(u16, file_hdr_buf[6..8], endian),
        .reserved1 = 0,
        .reserved2 = 0,
        .snap_len = mem.readInt(u32, file_hdr_buf[16..20], endian),
        .network = mem.readInt(u32, file_hdr_buf[20..24], endian),
    };

    if (hdr.major != 2 or hdr.minor != 4)
        return error.UnsupportedVersion;

    var hdr_buf = [_]u8{0} ** @sizeOf(PcapRecordHeader);
    while (true) {
        const size_readed = try reader.read(&hdr_buf);
        if (size_readed == 0) break;
        if (size_readed != @sizeOf(PcapRecordHeader))
            return error.InvalidFile;

        const record_hdr = PcapRecordHeader{
            .ts_sec = mem.readInt(u32, hdr_buf[0..4], endian),
            .ts_usec = mem.readInt(u32, hdr_buf[4..8], endian),
            .captured_len = mem.readInt(u32, hdr_buf[8..12], endian),
            .original_len = mem.readInt(u32, hdr_buf[12..16], endian),
        };

        const pkt = try ar_allocator.alloc(u8, record_hdr.captured_len);
        const record_read_size = reader.read(pkt) catch return error.InvalidRecord;
        if (record_read_size != record_hdr.captured_len) return error.InvalidRecord;

        try records.append(ar_allocator, .{ .hdr = record_hdr, .pkt = pkt });
    }

    return .{ .arena = arena, .hdr = hdr, .records = try records.toOwnedSlice(ar_allocator) };
}

pub fn deinit(self: *const Self) void {
    self.arena.deinit();
}

test "Load pcap" {
    const pcap = try Self.init(std.testing.allocator, "pcaps/http.cap");
    defer pcap.deinit();
}
