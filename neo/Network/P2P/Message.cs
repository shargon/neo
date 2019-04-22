﻿using System;
using System.IO;
using Akka.IO;
using Neo.Cryptography;
using Neo.IO;
using Neo.Network.P2P.Payloads;

namespace Neo.Network.P2P
{
    public class Message : ISerializable
    {
        public const int PayloadMaxSize = 0x02000000;
        public const int CompressionMinSize = 180;
        public const int CompressionThreshold = 100;

        public MessageFlags Flags;
        public MessageCommand Command;
        public byte[] Payload;

        private ISerializable _payload_deserialized = null;

        public int Size => 2 + IO.Helper.GetVarSize(Payload.Length) + Payload.Length;

        public static Message Create(MessageCommand command, ISerializable payload = null)
        {
            var ret = Create(command, payload == null ? new byte[0] : payload.ToArray());
            ret._payload_deserialized = payload;

            return ret;
        }

        public static Message Create(MessageCommand command, byte[] payload)
        {
            var flags = MessageFlags.None;

            // Try compression

            if (payload.Length > CompressionMinSize)
            {
                var compressed = payload.CompressGzip();

                if (compressed.Length < payload.Length - CompressionThreshold)
                {
                    payload = compressed;
                    flags |= MessageFlags.CompressedGzip;
                }
            }

            return new Message
            {
                Flags = flags,
                Command = command,
                Payload = payload
            };
        }

        void ISerializable.Serialize(BinaryWriter writer)
        {
            writer.Write((byte)Flags);
            writer.Write((byte)Command);
            writer.WriteVarBytes(Payload);
        }

        void ISerializable.Deserialize(BinaryReader reader)
        {
            this.Flags = (MessageFlags)reader.ReadByte();
            this.Command = (MessageCommand)reader.ReadByte();
            var length = (int)reader.ReadVarInt(int.MaxValue);

            if (length > PayloadMaxSize) throw new FormatException();
            this.Payload = reader.ReadBytes(length);
        }

        public static int TryDeserialize(ByteString data, out Message msg)
        {
            msg = null;
            if (data.Count < 3) return 0;

            var header = data.Slice(0, 3).ToArray();
            ulong length = header[2];
            int payloadIndex = 3;

            if (length == 0xFD)
            {
                if (data.Count < 5) return 0;
                length = data.Slice(payloadIndex, 2).ToArray().ToUInt16(0);
                payloadIndex += 2;
            }
            else if (length == 0xFE)
            {
                if (data.Count < 7) return 0;
                length = data.Slice(payloadIndex, 4).ToArray().ToUInt32(0);
                payloadIndex += 4;
            }
            else if (length == 0xFF)
            {
                if (data.Count < 11) return 0;
                length = data.Slice(payloadIndex, 8).ToArray().ToUInt64(0);
                payloadIndex += 8;
            }

            if (length > PayloadMaxSize) throw new FormatException();
            if (data.Count < (int)length) return 0;

            msg = new Message()
            {
                Flags = (MessageFlags)header[0],
                Command = (MessageCommand)header[1],
                Payload = data.Slice(payloadIndex, (int)length).ToArray()
            };

            return payloadIndex + (int)length;
        }

        public byte[] GetPayload()
        {
            if (this.Flags.HasFlag(MessageFlags.CompressedGzip))
            {
                return this.Payload.UncompressGzip();
            }

            return this.Payload;
        }

        public T GetPayload<T>() where T : ISerializable, new()
        {
            if (_payload_deserialized is null)
                _payload_deserialized = GetPayload().AsSerializable<T>();
            return (T)_payload_deserialized;
        }

        public Transaction GetTransaction()
        {
            if (_payload_deserialized is null)
                _payload_deserialized = Transaction.DeserializeFrom(GetPayload());
            return (Transaction)_payload_deserialized;
        }
    }
}