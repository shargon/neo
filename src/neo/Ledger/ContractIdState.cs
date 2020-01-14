using Neo.IO;
using System.IO;

namespace Neo.Ledger
{
    public class ContractIdState : ICloneable<ContractIdState>, ISerializable
    {
        public uint Id;

        int ISerializable.Size => sizeof(uint);

        ContractIdState ICloneable<ContractIdState>.Clone()
        {
            return new ContractIdState
            {
                Id = Id
            };
        }

        void ISerializable.Deserialize(BinaryReader reader)
        {
            Id = reader.ReadUInt32();
        }

        void ICloneable<ContractIdState>.FromReplica(ContractIdState replica)
        {
            Id = replica.Id;
        }

        void ISerializable.Serialize(BinaryWriter writer)
        {
            writer.Write(Id);
        }

        internal void Set(uint value)
        {
            Id = value;
        }
    }
}