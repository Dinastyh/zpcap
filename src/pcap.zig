const std = @import("std");
pub const RawPcap = @import("raw_pcap.zig");
const ArenaAllocator = std.heap.ArenaAllocator;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayListUnmanaged;
const Map = std.AutoArrayHashMapUnmanaged;
const c = @cImport({
    @cInclude("net/ethernet.h");
    @cInclude("netinet/ip.h");
    @cInclude("netinet/ip6.h");
    @cInclude("netinet/tcp.h");
    @cInclude("netinet/udp.h");
});
const native_endian = @import("builtin").target.cpu.arch.endian();

const Self = @This();

const Flow = struct { id: usize, protocol: usize, owned_pkt: []usize };

const FlowIdentifier = struct {
    ip_src: [16]u8 = [_]u8{0} ** 16,
    ip_dst: [16]u8 = [_]u8{0} ** 16,
    protocol: u8 = 0,
    port_src: u16 = 0,
    port_dst: u16 = 0,

    const IpHdr = extern struct {
        ihl_and_version: u8 align(1),
        tos: u8 align(1),
        tot_len: u16 align(1),
        id: u16 align(1),
        frag_off: u16 align(1),
        ttl: u8 align(1),
        protocol: u8 align(1),
        check: u16 align(1),
        saddr: [4]u8 align(1),
        daddr: [4]u8 align(1),
    };

    const UdpHdr = extern struct {
        source: u16 align(1),
        dest: u16 align(1),
        len: u16 align(1),
        check: u16 align(1),
    };

    pub fn parse(pkt: []u8) !@This() {
        const eth_header = @as(*c.ether_header, @ptrCast(pkt.ptr));
        const ip_type = eth_header.ether_type;
        var identifier = FlowIdentifier{};
        const iphdr_len = try switch (@byteSwap(ip_type)) {
            c.ETHERTYPE_IP => blk: {
                const iphdr = @as(*IpHdr, @ptrCast(pkt.ptr + @sizeOf(c.ether_header)));
                @memcpy(identifier.ip_src[0..4], &iphdr.saddr);
                @memcpy(identifier.ip_dst[0..4], &iphdr.daddr);
                identifier.protocol = iphdr.protocol;
                break :blk if (native_endian == .big) (iphdr.ihl_and_version >> 4) * 4 else (iphdr.ihl_and_version & 0x0F) * 4;
            },
            c.ETHERTYPE_IPV6 => blk: {
                const iphdr = @as(*c.ip6_hdr, @alignCast(@ptrCast(pkt.ptr + @sizeOf(c.ether_header))));
                @memcpy(&identifier.ip_src, &iphdr.ip6_src.__in6_u.__u6_addr8);
                @memcpy(&identifier.ip_dst, &iphdr.ip6_dst.__in6_u.__u6_addr8);
                identifier.protocol = iphdr.ip6_ctlun.ip6_un1.ip6_un1_nxt;
                break :blk 40;
            },

            else => error.UnsupportedEtherType,
        };

        if (identifier.protocol == 6 or identifier.protocol == 17) {
            // Udp header is used for tcp and udp
            const udphdr = @as(*UdpHdr, @ptrCast(pkt.ptr + @sizeOf(c.ether_header) + iphdr_len));
            identifier.port_src = udphdr.source;
            identifier.port_dst = udphdr.dest;
        }

        return identifier;
    }

    pub fn reverse(src: *const @This()) @This() {
        var identifier = @This(){};
        @memcpy(&identifier.ip_src, &src.ip_dst);
        @memcpy(&identifier.ip_dst, &src.ip_src);
        identifier.port_src = src.port_dst;
        identifier.port_dst = src.port_src;
        identifier.protocol = src.protocol;

        return identifier;
    }
};

const FlowBuilder = struct {
    id: usize,
    protocol: usize,
    owned_pkt: ArrayList(usize),
};

allocator: ArenaAllocator,
flows: []Flow,
raw: RawPcap,

pub fn init(allocator: Allocator, pcap: RawPcap) !Self {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();

    var local_arena = std.heap.ArenaAllocator.init(allocator);
    defer local_arena.deinit();

    var flow_builders: Map(FlowIdentifier, FlowBuilder) = .empty;
    defer flow_builders.deinit(local_arena.allocator());

    var flow_number: usize = 0;
    for (0.., pcap.records) |i, record| {
        const key = try FlowIdentifier.parse(record.pkt);

        const flow_builder = blk: {
            const classic = flow_builders.getPtr(key);
            if (classic) |r| break :blk r;
            const reversed = flow_builders.getPtr(key.reverse());
            if (reversed) |r| break :blk r;

            try flow_builders.put(local_arena.allocator(), key, FlowBuilder{ .id = flow_number, .protocol = key.protocol, .owned_pkt = .empty });
            const new_builder = flow_builders.getPtr(key) orelse unreachable;
            flow_number += 1;
            break :blk new_builder;
        };

        try flow_builder.owned_pkt.append(local_arena.allocator(), i);
    }

    const flows = try arena.allocator().alloc(Flow, flow_builders.count());
    for (0.., flow_builders.values()) |i, builder| {
        const pkts = try arena.allocator().alloc(usize, builder.owned_pkt.items.len);
        @memcpy(pkts, builder.owned_pkt.items);
        flows[i] = .{ .id = builder.id, .protocol = builder.protocol, .owned_pkt = pkts };
    }

    return .{ .allocator = arena, .flows = flows, .raw = pcap };
}

pub fn deinit(self: *const Self) void {
    self.allocator.deinit();
    self.raw.deinit();
}

test "Load pcap" {
    const rpcap = try RawPcap.init(std.testing.allocator, "pcaps/http.cap");
    errdefer rpcap.deinit();
    const pcap = try Self.init(std.testing.allocator, rpcap);
    defer pcap.deinit();
}
