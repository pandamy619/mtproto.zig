const std = @import("std");
pub fn main() !void {
    var list: std.ArrayList(u8) = .empty;
    try list.append(std.heap.page_allocator, 1);
}
