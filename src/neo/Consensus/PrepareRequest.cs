using Neo.IO;
using Neo.Network.P2P.Payloads;
using System.IO;

namespace Neo.Consensus
{
    public class PrepareRequest : ConsensusMessage
    {
        public ulong Timestamp;
        public ulong Nonce;
        public UInt256[] TransactionHashes;

        public override int Size => base.Size
            + sizeof(ulong)                     //Timestamp
            + sizeof(ulong)                     //Nonce
            + TransactionHashes.GetVarSize();   //TransactionHashes

        public PrepareRequest()
            : base(ConsensusMessageType.PrepareRequest)
        {
        }

        public override void Deserialize(BinaryReader reader)
        {
            base.Deserialize(reader);
            Timestamp = reader.ReadUInt64();
            Nonce = reader.ReadUInt64();
            int hashesCount = (int)reader.ReadVarInt(Block.MaxTransactionsPerBlock);
            TransactionHashes = reader.ReadSerializableFixedAndUniqueArray<UInt256>(hashesCount, (a, b) => a.Equals(b));
        }

        public override void Serialize(BinaryWriter writer)
        {
            base.Serialize(writer);
            writer.Write(Timestamp);
            writer.Write(Nonce);
            writer.Write(TransactionHashes);
        }
    }
}
