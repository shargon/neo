namespace Neo.Network
{
    public enum MessageCommand : byte
    {
        notfound = 0x00,

        addr = 0x01,
        alert = 0x02,
        block = 0x03,
        consensus = 0x04,
        filteradd = 0x05,
        filterclear = 0x06,
        filterload = 0x07,
        getaddr = 0x08,
        getblocks = 0x09,
        getdata = 0x0A,
        getheaders = 0x0B,
        headers = 0x0C,
        inv = 0x0D,
        invpool = 0x0E,
        mempool = 0x0F,
        merkleblock = 0x10,
        ping = 0x11,
        pong = 0x12,
        reject = 0x13,
        tx = 0x14,
        verack = 0x15,
        version = 0x16,
    }
}