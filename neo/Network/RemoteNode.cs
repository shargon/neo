﻿using Neo.Core;
using Neo.Cryptography;
using Neo.IO;
using Neo.Network.Payloads;
using Neo.Network.Queues;
using Neo.Plugins;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Neo.Network
{
    public abstract class RemoteNode : IDisposable
    {
        public event EventHandler<bool> Disconnected;
        internal event EventHandler<IInventory> InventoryReceived;
        internal event EventHandler<IPEndPoint[]> PeersReceived;

        private static readonly TimeSpan HalfMinute = TimeSpan.FromSeconds(30);
        private static readonly TimeSpan OneMinute = TimeSpan.FromMinutes(1);
        private static readonly TimeSpan HalfHour = TimeSpan.FromMinutes(30);

        private SendMessageQueue message_queue_send = new SendMessageQueue();
        private ReceiveMessageQueue message_queue_recv = new ReceiveMessageQueue();

        private static HashSet<UInt256> missions_global = new HashSet<UInt256>();
        private HashSet<UInt256> missions = new HashSet<UInt256>();
        private DateTime mission_start = DateTime.Now.AddYears(100);

        private LocalNode localNode;
        private int disposed = 0;
        private BloomFilter bloom_filter;

        public VersionPayload Version { get; private set; }
        public IPEndPoint RemoteEndpoint { get; protected set; }
        public IPEndPoint ListenerEndpoint { get; protected set; }

        protected RemoteNode(LocalNode localNode)
        {
            this.localNode = localNode;
        }

        public virtual void Disconnect(bool error)
        {
            if (Interlocked.Exchange(ref disposed, 1) == 0)
            {
                Disconnected?.Invoke(this, error);
                bool needSync = false;
                lock (missions_global)
                    lock (missions)
                        if (missions.Count > 0)
                        {
                            missions_global.ExceptWith(missions);
                            needSync = true;
                        }

                if (needSync)
                    localNode.RequestGetBlocks();
            }
        }

        public void Dispose()
        {
            Disconnect(false);
        }

        public void EnqueueMessage(MessageCommand command, ISerializable payload = null)
        {
            message_queue_send.Enqueue(command, payload);
        }

        private void OnAddrMessageReceived(AddrPayload payload)
        {
            IPEndPoint[] peers = payload.AddressList.Select(p => p.EndPoint).Where(p => p.Port != localNode.Port || !LocalNode.LocalAddresses.Contains(p.Address)).ToArray();
            if (peers.Length > 0) PeersReceived?.Invoke(this, peers);
        }

        private void OnFilterAddMessageReceived(FilterAddPayload payload)
        {
            if (bloom_filter != null)
                bloom_filter.Add(payload.Data);
        }

        private void OnFilterClearMessageReceived()
        {
            bloom_filter = null;
        }

        private void OnFilterLoadMessageReceived(FilterLoadPayload payload)
        {
            bloom_filter = new BloomFilter(payload.Filter.Length * 8, payload.K, payload.Tweak, payload.Filter);
        }

        private void OnGetAddrMessageReceived()
        {
            if (!localNode.ServiceEnabled) return;
            AddrPayload payload;
            lock (localNode.connectedPeers)
            {
                const int MaxCountToSend = 200;
                IEnumerable<RemoteNode> peers = localNode.connectedPeers.Where(p => p.ListenerEndpoint != null && p.Version != null);
                if (localNode.connectedPeers.Count > MaxCountToSend)
                {
                    Random rand = new Random();
                    peers = peers.OrderBy(p => rand.Next());
                }
                peers = peers.Take(MaxCountToSend);
                payload = AddrPayload.Create(peers.Select(p => NetworkAddressWithTime.Create(p.ListenerEndpoint, p.Version.Services, p.Version.Timestamp)).ToArray());
            }
            EnqueueMessage(MessageCommand.addr, payload);
        }

        private void OnGetBlocksMessageReceived(GetBlocksPayload payload)
        {
            if (!localNode.ServiceEnabled) return;
            if (Blockchain.Default == null) return;
            UInt256 hash = payload.HashStart.Select(p => Blockchain.Default.GetHeader(p)).Where(p => p != null).OrderBy(p => p.Index).Select(p => p.Hash).FirstOrDefault();
            if (hash == null || hash == payload.HashStop) return;
            List<UInt256> hashes = new List<UInt256>();
            do
            {
                hash = Blockchain.Default.GetNextBlockHash(hash);
                if (hash == null) break;
                hashes.Add(hash);
            } while (hash != payload.HashStop && hashes.Count < 500);
            EnqueueMessage(MessageCommand.inv, InvPayload.Create(InventoryType.Block, hashes.ToArray()));
        }

        private void OnGetDataMessageReceived(InvPayload payload)
        {
            foreach (UInt256 hash in payload.Hashes.Distinct())
            {
                IInventory inventory;
                if (!localNode.RelayCache.TryGet(hash, out inventory) && !localNode.ServiceEnabled)
                    continue;
                switch (payload.Type)
                {
                    case InventoryType.TX:
                        if (inventory == null)
                            inventory = LocalNode.GetTransaction(hash);
                        if (inventory == null && Blockchain.Default != null)
                            inventory = Blockchain.Default.GetTransaction(hash);
                        if (inventory != null)
                            EnqueueMessage(MessageCommand.tx, inventory);
                        break;
                    case InventoryType.Block:
                        if (inventory == null && Blockchain.Default != null)
                            inventory = Blockchain.Default.GetBlock(hash);
                        if (inventory != null)
                        {
                            BloomFilter filter = bloom_filter;
                            if (filter == null)
                            {
                                EnqueueMessage(MessageCommand.block, inventory);
                            }
                            else
                            {
                                Block block = (Block)inventory;
                                BitArray flags = new BitArray(block.Transactions.Select(p => TestFilter(filter, p)).ToArray());
                                EnqueueMessage(MessageCommand.merkleblock, MerkleBlockPayload.Create(block, flags));
                            }
                        }
                        break;
                    case InventoryType.Consensus:
                        if (inventory != null)
                            EnqueueMessage(MessageCommand.consensus, inventory);
                        break;
                }
            }
        }

        private void OnGetHeadersMessageReceived(GetBlocksPayload payload)
        {
            if (!localNode.ServiceEnabled) return;
            if (Blockchain.Default == null) return;
            UInt256 hash = payload.HashStart.Select(p => Blockchain.Default.GetHeader(p)).Where(p => p != null).OrderBy(p => p.Index).Select(p => p.Hash).FirstOrDefault();
            if (hash == null || hash == payload.HashStop) return;
            List<Header> headers = new List<Header>();
            do
            {
                hash = Blockchain.Default.GetNextBlockHash(hash);
                if (hash == null) break;
                headers.Add(Blockchain.Default.GetHeader(hash));
            } while (hash != payload.HashStop && headers.Count < 2000);
            EnqueueMessage(MessageCommand.headers, HeadersPayload.Create(headers));
        }

        private void OnHeadersMessageReceived(HeadersPayload payload)
        {
            if (Blockchain.Default == null) return;
            Blockchain.Default.AddHeaders(payload.Headers);
            if (Blockchain.Default.HeaderHeight < Version.StartHeight)
            {
                EnqueueMessage(MessageCommand.getheaders, GetBlocksPayload.Create(Blockchain.Default.CurrentHeaderHash));
            }
        }

        private void OnInventoryReceived(IInventory inventory)
        {
            lock (missions_global)
            {
                lock (missions)
                {
                    missions_global.Remove(inventory.Hash);
                    missions.Remove(inventory.Hash);
                    if (missions.Count == 0)
                        mission_start = DateTime.Now.AddYears(100);
                    else
                        mission_start = DateTime.Now;
                }
            }
            if (inventory is MinerTransaction) return;
            InventoryReceived?.Invoke(this, inventory);
        }

        private void OnInvMessageReceived(InvPayload payload)
        {
            if (payload.Type != InventoryType.TX && payload.Type != InventoryType.Block && payload.Type != InventoryType.Consensus)
                return;
            UInt256[] hashes = payload.Hashes.Distinct().ToArray();
            lock (LocalNode.KnownHashes)
            {
                hashes = hashes.Where(p => !LocalNode.KnownHashes.Contains(p)).ToArray();
            }
            if (hashes.Length == 0) return;
            lock (missions_global)
            {
                lock (missions)
                {
                    if (localNode.GlobalMissionsEnabled)
                        hashes = hashes.Where(p => !missions_global.Contains(p)).ToArray();
                    if (hashes.Length > 0)
                    {
                        if (missions.Count == 0) mission_start = DateTime.Now;
                        missions_global.UnionWith(hashes);
                        missions.UnionWith(hashes);
                    }
                }
            }
            if (hashes.Length == 0) return;
            EnqueueMessage(MessageCommand.getdata, InvPayload.Create(payload.Type, hashes));
        }

        private void OnMemPoolMessageReceived()
        {
            EnqueueMessage(MessageCommand.invpool, InvPayload.Create(InventoryType.TX, LocalNode.GetMemoryPool().Select(p => p.Hash).ToArray()));
        }

        private bool ParseMessage(Message message, out ISerializable payload)
        {
            switch (message.Command)
            {
                case MessageCommand.addr: payload = message.Payload.AsSerializable<AddrPayload>(); return true;
                case MessageCommand.block: payload = message.Payload.AsSerializable<Block>(); return true;
                case MessageCommand.consensus: payload = message.Payload.AsSerializable<ConsensusPayload>(); return true;
                case MessageCommand.filteradd: payload = message.Payload.AsSerializable<FilterAddPayload>(); return true;
                case MessageCommand.getaddr:
                case MessageCommand.mempool:
                case MessageCommand.filterclear: payload = null; return true;
                case MessageCommand.filterload: payload = message.Payload.AsSerializable<FilterLoadPayload>(); return true;
                case MessageCommand.getblocks: payload = message.Payload.AsSerializable<GetBlocksPayload>(); return true;
                case MessageCommand.getdata: payload = message.Payload.AsSerializable<InvPayload>(); return true;
                case MessageCommand.getheaders: payload = message.Payload.AsSerializable<GetBlocksPayload>(); return true;
                case MessageCommand.headers: payload = message.Payload.AsSerializable<HeadersPayload>(); return true;
                case MessageCommand.invpool:
                case MessageCommand.inv: payload = message.Payload.AsSerializable<InvPayload>(); return true;
                case MessageCommand.tx:
                    {
                        if (message.Payload.Length <= 1024 * 1024)
                        {
                            payload = Transaction.DeserializeFrom(message.Payload);
                            return true;
                        }

                        payload = null;
                        return false;
                    }
                case MessageCommand.verack:
                case MessageCommand.version:
                    {
                        Disconnect(true);
                        payload = null;
                        return false;
                    }
                // Ignore
                default:
                    {
                        payload = null;
                        return false;
                    }
            }
        }

        private void OnMessageReceived(MessageCommand command, ISerializable obj)
        {
            switch (command)
            {
                case MessageCommand.addr:
                    {
                        if (obj is AddrPayload payload)
                            OnAddrMessageReceived(payload);
                        break;
                    }
                case MessageCommand.block:
                    {
                        if (obj is Block payload)
                            OnInventoryReceived(payload);
                        break;
                    }
                case MessageCommand.consensus:
                    {
                        if (obj is ConsensusPayload payload)
                            OnInventoryReceived(payload);
                        break;
                    }
                case MessageCommand.filteradd:
                    {
                        if (obj is FilterAddPayload payload)
                            OnFilterAddMessageReceived(payload);
                        break;
                    }
                case MessageCommand.filterclear:
                    {
                        OnFilterClearMessageReceived();
                        break;
                    }
                case MessageCommand.filterload:
                    {
                        if (obj is FilterLoadPayload payload)
                            OnFilterLoadMessageReceived(payload);
                        break;
                    }
                case MessageCommand.getaddr:
                    {
                        OnGetAddrMessageReceived();
                        break;
                    }
                case MessageCommand.getblocks:
                    {
                        if (obj is GetBlocksPayload payload)
                            OnGetBlocksMessageReceived(payload);
                        break;
                    }
                case MessageCommand.getdata:
                    {
                        if (obj is InvPayload payload)
                            OnGetDataMessageReceived(payload);
                        break;
                    }
                case MessageCommand.getheaders:
                    {
                        if (obj is GetBlocksPayload payload)
                            OnGetHeadersMessageReceived(payload);
                        break;
                    }
                case MessageCommand.headers:
                    {
                        if (obj is HeadersPayload payload)
                            OnHeadersMessageReceived(payload);
                        break;
                    }
                case MessageCommand.inv:
                case MessageCommand.invpool:
                    {
                        if (obj is InvPayload payload)
                            OnInvMessageReceived(payload);
                        break;
                    }
                case MessageCommand.mempool:
                    {
                        OnMemPoolMessageReceived();
                        break;
                    }
                case MessageCommand.tx:
                    {
                        if (obj is Transaction payload)
                            OnInventoryReceived(payload);
                        break;
                    }
                case MessageCommand.verack:
                case MessageCommand.version:
                    {
                        Disconnect(true);
                        break;
                    }
                // Ignore
                default: break;
            }
        }

        protected abstract Task<Message> ReceiveMessageAsync(TimeSpan timeout);

        internal bool Relay(IInventory data)
        {
            if (Version?.Relay != true) return false;
            if (data.InventoryType == InventoryType.TX)
            {
                BloomFilter filter = bloom_filter;
                if (filter != null && !TestFilter(filter, (Transaction)data))
                    return false;
            }
            EnqueueMessage(MessageCommand.inv, InvPayload.Create(data.InventoryType, data.Hash));
            return true;
        }

        internal void Relay(IEnumerable<Transaction> transactions)
        {
            if (Version?.Relay != true) return;
            BloomFilter filter = bloom_filter;
            if (filter != null)
                transactions = transactions.Where(p => TestFilter(filter, p));
            UInt256[] hashes = transactions.Select(p => p.Hash).ToArray();
            if (hashes.Length == 0) return;
            EnqueueMessage(MessageCommand.inv, InvPayload.Create(InventoryType.TX, hashes));
        }

        internal void RequestMemoryPool()
        {
            EnqueueMessage(MessageCommand.mempool, null);
        }

        internal void RequestPeers()
        {
            EnqueueMessage(MessageCommand.getaddr, null);
        }

        protected abstract Task<bool> SendMessageAsync(Message message);

        internal async void StartProtocol()
        {
#if !NET47
            //There is a bug in .NET Core 2.0 that blocks async method which returns void.
            await Task.Yield();
#endif
            if (!await SendMessageAsync(Message.Create(MessageCommand.version, VersionPayload.Create(localNode.Port, localNode.Nonce, localNode.UserAgent))))
                return;
            Message message = await ReceiveMessageAsync(HalfMinute);
            if (message == null) return;
            if (message.Command != MessageCommand.version)
            {
                Disconnect(true);
                return;
            }
            try
            {
                Version = message.Payload.AsSerializable<VersionPayload>();
            }
            catch (EndOfStreamException e)
            {
                NeoPlugin.BroadcastLog(e);
                Disconnect(false);
                return;
            }
            catch (FormatException e)
            {
                NeoPlugin.BroadcastLog(e);
                Disconnect(true);
                return;
            }
            if (Version.Nonce == localNode.Nonce)
            {
                Disconnect(true);
                return;
            }
            bool isSelf;
            lock (localNode.connectedPeers)
            {
                isSelf = localNode.connectedPeers.Where(p => p != this).Any(p => p.RemoteEndpoint.Address.Equals(RemoteEndpoint.Address) && p.Version?.Nonce == Version.Nonce);
            }
            if (isSelf)
            {
                Disconnect(false);
                return;
            }
            if (ListenerEndpoint != null)
            {
                if (ListenerEndpoint.Port != Version.Port)
                {
                    Disconnect(true);
                    return;
                }
            }
            else if (Version.Port > 0)
            {
                ListenerEndpoint = new IPEndPoint(RemoteEndpoint.Address, Version.Port);
            }
            if (!await SendMessageAsync(Message.Create(MessageCommand.verack))) return;
            message = await ReceiveMessageAsync(HalfMinute);
            if (message == null) return;
            if (message.Command != MessageCommand.verack)
            {
                Disconnect(true);
                return;
            }
            if (Blockchain.Default?.HeaderHeight < Version.StartHeight)
            {
                EnqueueMessage(MessageCommand.getheaders, GetBlocksPayload.Create(Blockchain.Default.CurrentHeaderHash));
            }
            StartSendLoop();

            Thread recTh = new Thread(new ThreadStart(AsyncReceive))
            {
                IsBackground = true
            };
            recTh.Start();

            while (disposed == 0)
            {
                if (Blockchain.Default != null)
                {
                    if (missions.Count == 0 && Blockchain.Default.Height < Version.StartHeight)
                    {
                        EnqueueMessage(MessageCommand.getblocks, GetBlocksPayload.Create(Blockchain.Default.CurrentBlockHash));
                    }
                }
                TimeSpan timeout = missions.Count == 0 ? HalfHour : OneMinute;

                message = await ReceiveMessageAsync(timeout);
                if (message == null) break;

                if (DateTime.Now - mission_start > OneMinute
                    && message.Command != MessageCommand.block && message.Command != MessageCommand.consensus && message.Command != MessageCommand.tx)
                {
                    Disconnect(false);
                    break;
                }

                try
                {
                    // Parse message and enqueue
                    if (ParseMessage(message, out ISerializable payload))
                        message_queue_recv.Enqueue(message.Command, payload);
                }
                catch (EndOfStreamException e)
                {
                    NeoPlugin.BroadcastLog(e);
                    Disconnect(false);
                    break;
                }
                catch (FormatException e)
                {
                    NeoPlugin.BroadcastLog(e);
                    Disconnect(true);
                    break;
                }
            }
        }

        private void AsyncReceive()
        {
            while (disposed == 0)
            {
                ParsedMessage msg = message_queue_recv.Dequeue();
                if (msg != null)
                {
                    OnMessageReceived(msg.Command, msg.Payload);
                }
                else
                {
                    Thread.Sleep(1);
                }
            }
        }

        private async void StartSendLoop()
        {
#if !NET47
            //There is a bug in .NET Core 2.0 that blocks async method which returns void.
            await Task.Yield();
#endif
            while (disposed == 0)
            {
                Message message = message_queue_send.Dequeue();

                if (message == null)
                {
                    for (int i = 0; i < 10 && disposed == 0; i++)
                    {
                        Thread.Sleep(10);
                    }
                }
                else
                {
                    await SendMessageAsync(message);
                }
            }
        }

        private bool TestFilter(BloomFilter filter, Transaction tx)
        {
            if (filter.Check(tx.Hash.ToArray())) return true;
            if (tx.Outputs.Any(p => filter.Check(p.ScriptHash.ToArray()))) return true;
            if (tx.Inputs.Any(p => filter.Check(p.ToArray()))) return true;
            if (tx.Scripts.Any(p => filter.Check(p.ScriptHash.ToArray())))
                return true;
            if (tx.Type == TransactionType.RegisterTransaction)
            {
#pragma warning disable CS0612
                RegisterTransaction asset = (RegisterTransaction)tx;
                if (filter.Check(asset.Admin.ToArray())) return true;
#pragma warning restore CS0612
            }
            return false;
        }
    }
}
