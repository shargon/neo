using Neo.IO;
using System;
using System.IO;

namespace Neo.Network.P2P.Payloads
{
    public class GetBlocksPayload : ISerializable
    {
        public uint StartHeight;
        public short Count;

        public int Size => sizeof(short) + sizeof(uint);

        public static GetBlocksPayload Create(uint startHeight, short count = -1)
        {
            return new GetBlocksPayload
            {
                StartHeight= startHeight,
                Count = count
            };
        }

        void ISerializable.Deserialize(BinaryReader reader)
        {
            StartHeight = reader.ReadUInt32();
            Count = reader.ReadInt16();
            if (Count < -1 || Count == 0) throw new FormatException();
        }

        void ISerializable.Serialize(BinaryWriter writer)
        {
            writer.Write(StartHeight);
            writer.Write(Count);
        }
    }
}
