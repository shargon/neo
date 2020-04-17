#pragma warning disable IDE0051

using Neo.Cryptography.ECC;
using Neo.Ledger;
using Neo.Network.P2P.Payloads;
using System.Linq;
using System.Numerics;

namespace Neo.SmartContract.Native.Tokens
{
    public sealed class GasToken : Nep5Token<Nep5AccountState>
    {
        public override string ServiceName => "Neo.Native.Tokens.GAS";
        public override int Id => -2;
        public override string Name => "GAS";
        public override string Symbol => "gas";
        public override byte Decimals => 8;

        internal GasToken()
        {
        }

        internal override bool Initialize(ApplicationEngine engine)
        {
            if (!base.Initialize(engine)) return false;
            if (TotalSupply(engine.Snapshot) != BigInteger.Zero) return false;
            UInt160 account = Blockchain.GetConsensusAddress(Blockchain.StandbyValidators);
            Mint(engine, account, 30_000_000 * Factor);
            return true;
        }

        protected override bool OnPersist(ApplicationEngine engine)
        {
            if (!base.OnPersist(engine)) return false;

            long oracleFee = 0;
            long networkFee = 0;

            foreach (Transaction tx in engine.Snapshot.PersistingBlock.Transactions)
            {
                networkFee += tx.NetworkFee;

                switch (tx.Version)
                {
                    case TransactionVersion.OracleRequest:
                    case TransactionVersion.OracleResponse:
                        {
                            oracleFee += tx.SystemFee;
                            Burn(engine, tx.Sender, tx.NetworkFee);
                            break;
                        }
                    default:
                        {
                            Burn(engine, tx.Sender, tx.SystemFee + tx.NetworkFee);
                            break;
                        }
                }
            }

            ECPoint[] validators = NEO.GetNextBlockValidators(engine.Snapshot);
            UInt160 primary = Contract.CreateSignatureRedeemScript(validators[engine.Snapshot.PersistingBlock.ConsensusData.PrimaryIndex]).ToScriptHash();
            Mint(engine, primary, networkFee);

            if (oracleFee > 0)
            {
                primary = Oracle.GetOracleMultiSigAddress(engine.Snapshot);
                Mint(engine, primary, oracleFee);
            }
            return true;
        }
    }
}
