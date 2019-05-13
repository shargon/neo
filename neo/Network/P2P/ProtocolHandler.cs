﻿using Akka.Actor;
using Akka.Configuration;
using Akka.IO;
using Neo.Cryptography;
using Neo.IO;
using Neo.IO.Actors;
using Neo.IO.Caching;
using Neo.Ledger;
using Neo.Network.P2P.Payloads;
using Neo.Persistence;
using Neo.Plugins;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace Neo.Network.P2P
{
    internal class ProtocolHandler : UntypedActor
    {
        public class SetFilter { public BloomFilter Filter; }

        private readonly NeoSystem system;
        private readonly FIFOSet<UInt256> knownHashes;
        private readonly FIFOSet<UInt256> sentHashes;
        private VersionPayload version;
        private bool verack = false;
        private BloomFilter bloom_filter;

        public ProtocolHandler(NeoSystem system)
        {
            this.system = system;
            this.knownHashes = new FIFOSet<UInt256>(Blockchain.Singleton.MemPool.Capacity * 2);
            this.sentHashes = new FIFOSet<UInt256>(Blockchain.Singleton.MemPool.Capacity * 2);
        }

        protected override void OnReceive(object message)
        {
            switch (message)
            {
                case Message msg:
                    {
                        foreach (IP2PPlugin plugin in Plugin.P2PPlugins)
                            if (!plugin.OnP2PMessage(msg))
                                return;

                        if (version == null)
                        {
                            if (msg.Command != MessageCommand.Version)
                                throw new ProtocolViolationException();
                            OnVersionMessageReceived((VersionPayload)msg.Payload);
                            return;
                        }
                        if (!verack)
                        {
                            if (msg.Command != MessageCommand.Verack)
                                throw new ProtocolViolationException();
                            OnVerackMessageReceived();
                            return;
                        }
                        switch (msg.Command)
                        {
                            case MessageCommand.Addr:
                                OnAddrMessageReceived((AddrPayload)msg.Payload);
                                break;
                            case MessageCommand.Block:
                                OnInventoryReceived((Block)msg.Payload);
                                break;
                            case MessageCommand.Consensus:
                                OnInventoryReceived((ConsensusPayload)msg.Payload);
                                break;
                            case MessageCommand.FilterAdd:
                                OnFilterAddMessageReceived((FilterAddPayload)msg.Payload);
                                break;
                            case MessageCommand.FilterClear:
                                OnFilterClearMessageReceived();
                                break;
                            case MessageCommand.FilterLoad:
                                OnFilterLoadMessageReceived((FilterLoadPayload)msg.Payload);
                                break;
                            case MessageCommand.GetAddr:
                                OnGetAddrMessageReceived();
                                break;
                            case MessageCommand.GetBlockHashes:
                                OnGetBlockHashesMessageReceived((GetBlocksPayload)msg.Payload);
                                break;
                            case MessageCommand.GetData:
                                OnGetDataMessageReceived((InvPayload)msg.Payload);
                                break;
                            case MessageCommand.GetHeaders:
                                OnGetHeadersMessageReceived((GetBlocksPayload)msg.Payload);
                                break;
                            case MessageCommand.Headers:
                                OnHeadersMessageReceived((HeadersPayload)msg.Payload);
                                break;
                            case MessageCommand.Inv:
                                OnInvMessageReceived((InvPayload)msg.Payload);
                                break;
                            case MessageCommand.Mempool:
                                OnMemPoolMessageReceived();
                                break;
                            case MessageCommand.Ping:
                                OnPingMessageReceived((PingPayload)msg.Payload);
                                break;
                            case MessageCommand.Pong:
                                OnPongMessageReceived((PingPayload)msg.Payload);
                                break;
                            case MessageCommand.Transaction:
                                if (msg.Payload.Size <= Transaction.MaxTransactionSize)
                                    OnInventoryReceived((Transaction)msg.Payload);
                                break;
                            case MessageCommand.Verack:
                            case MessageCommand.Version:
                                throw new ProtocolViolationException();
                            case MessageCommand.Alert:
                            case MessageCommand.MerkleBlock:
                            case MessageCommand.NotFound:
                            case MessageCommand.Reject:
                            default: break;
                        }

                        break;
                    }
                case Udp.Received udp:
                    {
                        if (Message.TryDeserialize(udp.Data, out var msg) != udp.Data.Count) return;

                        switch (msg.Command)
                        {
                            case MessageCommand.Transaction:
                                {
                                    if (msg.Payload.Size <= Transaction.MaxTransactionSize)
                                        system.LocalNode.Tell(new LocalNode.Relay { Inventory = (Transaction)msg.Payload });
                                    break;
                                }
                            case MessageCommand.Ping:
                                {
                                    var payload = (PingPayload)msg.Payload;
                                    msg = Message.Create(MessageCommand.Pong, PingPayload.Create(Blockchain.Singleton.Height, payload.Nonce));

                                    system.LocalNode.Tell(new UdpResponse((IPEndPoint)udp.Sender, ByteString.FromBytes(msg.ToArray())));
                                    break;
                                }
                            case MessageCommand.GetAddr:
                                {
                                    var networkAddresses = LocalNode.Singleton.GetPeers();
                                    if (networkAddresses.Length == 0) return;
                                    msg = Message.Create(MessageCommand.Addr, AddrPayload.Create(networkAddresses));

                                    system.LocalNode.Tell(new UdpResponse((IPEndPoint)udp.Sender, ByteString.FromBytes(msg.ToArray())));
                                    break;
                                }
                        }
                        break;
                    }
            }
        }

        private void OnAddrMessageReceived(AddrPayload payload)
        {
            system.LocalNode.Tell(new Peer.Peers
            {
                EndPoints = payload.AddressList.Select(p => p.EndPoint)
            });
        }

        private void OnFilterAddMessageReceived(FilterAddPayload payload)
        {
            if (bloom_filter != null)
                bloom_filter.Add(payload.Data);
        }

        private void OnFilterClearMessageReceived()
        {
            bloom_filter = null;
            Context.Parent.Tell(new SetFilter { Filter = null });
        }

        private void OnFilterLoadMessageReceived(FilterLoadPayload payload)
        {
            bloom_filter = new BloomFilter(payload.Filter.Length * 8, payload.K, payload.Tweak, payload.Filter);
            Context.Parent.Tell(new SetFilter { Filter = bloom_filter });
        }

        private void OnGetAddrMessageReceived()
        {
            NetworkAddressWithTime[] networkAddresses = LocalNode.Singleton.GetPeers();
            if (networkAddresses.Length == 0) return;
            Context.Parent.Tell(Message.Create(MessageCommand.Addr, AddrPayload.Create(networkAddresses)));
        }

        private void OnGetBlockHashesMessageReceived(GetBlocksPayload payload)
        {
            int count = payload.Count < 0 ? InvPayload.MaxHashesCount : payload.Count;
            var block = Blockchain.Singleton.Store.GetBlock(payload.StartHeight);
            if (block == null) return;
            var hashes = new List<UInt256>();
            for (uint i = 1; i <= count; i++)
            {
                uint index = block.Index + i;
                block = Blockchain.Singleton.Store.GetBlock(index);
                if (block == null) break;
                hashes.Add(block.Hash);
            }
            if (hashes.Count == 0) return;
            Context.Parent.Tell(Message.Create(MessageCommand.Inv, InvPayload.Create(InventoryType.Block, hashes.ToArray())));
        }

        private void OnGetHeadersMessageReceived(GetBlocksPayload payload)
        {
            int count = payload.Count < 0 ? HeadersPayload.MaxHeadersCount : payload.Count;
            var header = Blockchain.Singleton.Store.GetHeader(payload.StartHeight);
            if (header == null) return;
            var headers = new List<Header>();
            for (uint i = 1; i <= count; i++)
            {
                uint index = header.Index + i;
                header = Blockchain.Singleton.Store.GetHeader(index);
                if (header == null) break;
                headers.Add(header);
            }
            if (headers.Count == 0) return;
            Context.Parent.Tell(Message.Create(MessageCommand.Headers, HeadersPayload.Create(headers)));
        }

        private void OnGetDataMessageReceived(InvPayload payload)
        {
            UInt256[] hashes = payload.Hashes.Where(p => sentHashes.Add(p)).ToArray();
            foreach (UInt256 hash in hashes)
            {
                Blockchain.Singleton.RelayCache.TryGet(hash, out IInventory inventory);
                switch (payload.Type)
                {
                    case InventoryType.TX:
                        if (inventory == null)
                            inventory = Blockchain.Singleton.GetTransaction(hash);
                        if (inventory is Transaction)
                            Context.Parent.Tell(Message.Create(MessageCommand.Transaction, inventory));
                        break;
                    case InventoryType.Block:
                        if (inventory == null)
                            inventory = Blockchain.Singleton.GetBlock(hash);
                        if (inventory is Block block)
                        {
                            if (bloom_filter == null)
                            {
                                Context.Parent.Tell(Message.Create(MessageCommand.Block, inventory));
                            }
                            else
                            {
                                BitArray flags = new BitArray(block.Transactions.Select(p => bloom_filter.Test(p)).ToArray());
                                Context.Parent.Tell(Message.Create(MessageCommand.MerkleBlock, MerkleBlockPayload.Create(block, flags)));
                            }
                        }
                        break;
                    case InventoryType.Consensus:
                        if (inventory != null)
                            Context.Parent.Tell(Message.Create(MessageCommand.Consensus, inventory));
                        break;
                }
            }
        }

        private void OnHeadersMessageReceived(HeadersPayload payload)
        {
            if (payload.Headers.Length == 0) return;
            system.Blockchain.Tell(payload.Headers, Context.Parent);
        }

        private void OnInventoryReceived(IInventory inventory)
        {
            system.TaskManager.Tell(new TaskManager.TaskCompleted { Hash = inventory.Hash }, Context.Parent);
            system.LocalNode.Tell(new LocalNode.Relay { Inventory = inventory });
        }

        private void OnInvMessageReceived(InvPayload payload)
        {
            UInt256[] hashes = payload.Hashes.Where(p => knownHashes.Add(p)).ToArray();
            if (hashes.Length == 0) return;
            switch (payload.Type)
            {
                case InventoryType.Block:
                    using (Snapshot snapshot = Blockchain.Singleton.GetSnapshot())
                        hashes = hashes.Where(p => !snapshot.ContainsBlock(p)).ToArray();
                    break;
                case InventoryType.TX:
                    using (Snapshot snapshot = Blockchain.Singleton.GetSnapshot())
                        hashes = hashes.Where(p => !snapshot.ContainsTransaction(p)).ToArray();
                    break;
            }
            if (hashes.Length == 0) return;
            system.TaskManager.Tell(new TaskManager.NewTasks { Payload = InvPayload.Create(payload.Type, hashes) }, Context.Parent);
        }

        private void OnMemPoolMessageReceived()
        {
            foreach (InvPayload payload in InvPayload.CreateGroup(InventoryType.TX, Blockchain.Singleton.MemPool.GetVerifiedTransactions().Select(p => p.Hash).ToArray()))
                Context.Parent.Tell(Message.Create(MessageCommand.Inv, payload));
        }

        private void OnPingMessageReceived(PingPayload payload)
        {
            Context.Parent.Tell(payload);
            Context.Parent.Tell(Message.Create(MessageCommand.Pong, PingPayload.Create(Blockchain.Singleton.Height, payload.Nonce)));
        }

        private void OnPongMessageReceived(PingPayload payload)
        {
            Context.Parent.Tell(payload);
        }

        private void OnVerackMessageReceived()
        {
            verack = true;
            Context.Parent.Tell(MessageCommand.Verack);
        }

        private void OnVersionMessageReceived(VersionPayload payload)
        {
            version = payload;
            Context.Parent.Tell(payload);
        }

        public static Props Props(NeoSystem system)
        {
            return Akka.Actor.Props.Create(() => new ProtocolHandler(system)).WithMailbox("protocol-handler-mailbox");
        }
    }

    internal class ProtocolHandlerMailbox : PriorityMailbox
    {
        public ProtocolHandlerMailbox(Settings settings, Config config)
            : base(settings, config)
        {
        }

        protected override bool IsHighPriority(object message)
        {
            if (!(message is Message msg)) return true;
            switch (msg.Command)
            {
                case MessageCommand.Consensus:
                case MessageCommand.FilterAdd:
                case MessageCommand.FilterClear:
                case MessageCommand.FilterLoad:
                case MessageCommand.Verack:
                case MessageCommand.Version:
                case MessageCommand.Alert:
                    return true;
                default:
                    return false;
            }
        }

        protected override bool ShallDrop(object message, IEnumerable queue)
        {
            if (!(message is Message msg)) return false;
            switch (msg.Command)
            {
                case MessageCommand.GetAddr:
                case MessageCommand.GetBlockHashes:
                case MessageCommand.GetData:
                case MessageCommand.GetHeaders:
                case MessageCommand.Mempool:
                    return queue.OfType<Message>().Any(p => p.Command == msg.Command);
                default:
                    return false;
            }
        }
    }
}
