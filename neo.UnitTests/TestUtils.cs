﻿using Moq;
using Neo.IO;
using Neo.Network.P2P.Payloads;
using Neo.Persistence;
using Neo.VM;
using System;
using System.Collections.Generic;
using System.IO;

namespace Neo.UnitTests
{
    public static class TestUtils
    {
        public static readonly Random TestRandom = new Random(1337); // use fixed seed for guaranteed determinism

        public static byte[] GetByteArray(int length, byte firstByte)
        {
            byte[] array = new byte[length];
            array[0] = firstByte;
            for (int i = 1; i < length; i++)
            {
                array[i] = 0x20;
            }
            return array;
        }

        public static Transaction GetTransaction()
        {
            return new InvocationTransaction
            {
                Version = 1,
                Gas = Fixed8.Zero,
                Script = new byte[1],
                Attributes = new TransactionAttribute[0],
                Inputs = new CoinReference[0],
                Outputs = new TransactionOutput[0],
                Witnesses = new Witness[0]
            };
        }

        public static void SetupHeaderWithValues(Header header, UInt256 val256, out UInt256 merkRootVal, out UInt160 val160, out uint timestampVal, out uint indexVal, out ulong consensusDataVal, out Witness scriptVal)
        {
            setupBlockBaseWithValues(header, val256, out merkRootVal, out val160, out timestampVal, out indexVal, out consensusDataVal, out scriptVal);
        }

        public static void SetupBlockWithValues(Block block, UInt256 val256, out UInt256 merkRootVal, out UInt160 val160, out uint timestampVal, out uint indexVal, out ulong consensusDataVal, out Witness scriptVal, out Transaction[] transactionsVal, int numberOfTransactions)
        {
            setupBlockBaseWithValues(block, val256, out merkRootVal, out val160, out timestampVal, out indexVal, out consensusDataVal, out scriptVal);

            transactionsVal = new Transaction[numberOfTransactions];
            if (numberOfTransactions > 0)
            {
                for (int i = 0; i < numberOfTransactions; i++)
                {
                    transactionsVal[i] = TestUtils.GetTransaction();
                }
            }

            block.Transactions = transactionsVal;
        }

        private static void setupBlockBaseWithValues(BlockBase bb, UInt256 val256, out UInt256 merkRootVal, out UInt160 val160, out uint timestampVal, out uint indexVal, out ulong consensusDataVal, out Witness scriptVal)
        {
            bb.PrevHash = val256;
            merkRootVal = new UInt256(new byte[] { 75, 117, 92, 47, 164, 55, 126, 125, 63, 48, 186, 222, 86, 67, 102, 213, 167, 79, 15, 219, 124, 200, 3, 131, 221, 130, 22, 211, 180, 184, 13, 47 });
            bb.MerkleRoot = merkRootVal;
            timestampVal = new DateTime(1968, 06, 01, 0, 0, 0, DateTimeKind.Utc).ToTimestamp();
            bb.Timestamp = timestampVal;
            indexVal = 0;
            bb.Index = indexVal;
            consensusDataVal = 30;
            bb.ConsensusData = consensusDataVal;
            val160 = UInt160.Zero;
            bb.NextConsensus = val160;
            scriptVal = new Witness
            {
                InvocationScript = new byte[0],
                VerificationScript = new[] { (byte)OpCode.PUSHT }
            };
            bb.Witness = scriptVal;
        }

        public static Mock<InvocationTransaction> CreateRandomHashInvocationMockTransaction()
        {
            var mockTx = new Mock<InvocationTransaction>
            {
                CallBase = true
            };
            mockTx.Setup(p => p.Verify(It.IsAny<Snapshot>(), It.IsAny<IEnumerable<Transaction>>())).Returns(true);
            var tx = mockTx.Object;
            var randomBytes = new byte[16];
            TestRandom.NextBytes(randomBytes);
            tx.Script = randomBytes;
            tx.Attributes = new TransactionAttribute[0];
            tx.Inputs = new CoinReference[0];
            tx.Outputs = new TransactionOutput[0];
            tx.Witnesses = new Witness[0];

            return mockTx;
        }

        public static T CopyMsgBySerialization<T>(T serializableObj, T newObj) where T : ISerializable
        {
            using (MemoryStream ms = new MemoryStream(serializableObj.ToArray(), false))
            using (BinaryReader reader = new BinaryReader(ms))
            {
                newObj.Deserialize(reader);
            }

            return newObj;
        }
    }
}
