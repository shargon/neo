using System;
using System.IO;

namespace Neo.Consensus
{
    public class ChangeView : ConsensusMessage
    {
        public byte NewViewNumber;
        public uint BlockIndex;

        public ChangeView()
            : base(ConsensusMessageType.ChangeView)
        {
        }

        public override void Deserialize(BinaryReader reader)
        {
            base.Deserialize(reader);
            NewViewNumber = reader.ReadByte();
            if (NewViewNumber == 0) throw new FormatException();
            BlockIndex = reader.ReadUInt32();
        }

        public override void Serialize(BinaryWriter writer)
        {
            base.Serialize(writer);
            writer.Write(NewViewNumber);
            writer.Write(BlockIndex);
        }
    }
}
