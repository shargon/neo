using Neo.Core;
using Neo.Cryptography;
using Neo.IO;
using Neo.Network;
using Neo.Network.Payloads;
using Neo.Plugins;
using Neo.SmartContract;
using Neo.Wallets;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;

namespace Neo.Consensus
{
    public class ConsensusService : IDisposable
    {
        private static Random rand = new Random();
        private ConsensusContext context = new ConsensusContext();
        private LocalNode localNode;
        private Wallet wallet;
        private Timer timer;
        private uint timer_height;
        private byte timer_view;
        private DateTime block_received_time;
        private bool started = false;

        protected virtual bool RequireCheckPolicy { get { return false; } }

        public ConsensusService(LocalNode localNode, Wallet wallet)
        {
            this.localNode = localNode;
            this.wallet = wallet;
            this.timer = new Timer(OnTimeout, null, Timeout.Infinite, Timeout.Infinite);
        }

        private bool AddTransaction(Transaction tx, bool verify)
        {
            Stopwatch sw = Stopwatch.StartNew();
            Log($"{nameof(AddTransaction)}");

            if (Blockchain.Default.ContainsTransaction(tx.Hash) ||
                (verify && !tx.Verify(context.Transactions.Values)) ||
                !CheckPolicy(tx))
            {
                Log($"reject tx: {tx.Hash}{Environment.NewLine}{tx.ToArray().ToHexString()}");
                RequestChangeView();
                Log($"end{nameof(AddTransaction)}: elapsed={sw.Elapsed.ToString()} false");
                sw.Stop();
                return false;
            }
            context.Transactions[tx.Hash] = tx;
            if (context.TransactionHashes.Length == context.Transactions.Count)
            {
                if (Blockchain.GetConsensusAddress(Blockchain.Default.GetValidators(context.Transactions.Values).ToArray()).Equals(context.NextConsensus))
                {
                    Log($"send perpare response");
                    context.State |= ConsensusState.SignatureSent;
                    context.Signatures[context.MyIndex] = context.MakeHeader().Sign(context.KeyPair);
                    SignAndRelay(context.MakePrepareResponse(context.Signatures[context.MyIndex]));
                    CheckSignatures();
                }
                else
                {
                    RequestChangeView();

                    Log($"end{nameof(AddTransaction)}: elapsed={sw.Elapsed.ToString()} false");
                    sw.Stop();
                    return false;
                }
            }

            Log($"end{nameof(AddTransaction)}: elapsed={sw.Elapsed.ToString()} true");
            sw.Stop();
            return true;
        }

        private void Blockchain_PersistCompleted(object sender, Block block)
        {
            Stopwatch sw = Stopwatch.StartNew();

            Log($"{nameof(Blockchain_PersistCompleted)}: {block.Hash}");
            block_received_time = DateTime.Now;
            InitializeConsensus(0);

            Log($"end{nameof(Blockchain_PersistCompleted)}: elapsed={sw.Elapsed.ToString()}");
            sw.Stop();
        }

        private void CheckExpectedView(byte view_number)
        {
            Stopwatch sw = Stopwatch.StartNew();
            Log($"{nameof(CheckExpectedView)}");

            if (context.ViewNumber == view_number)
            {
                Log($"end{nameof(CheckExpectedView)}: ==View elapsed={sw.Elapsed.ToString()}");
                sw.Stop();
                return;
            }
            if (context.ExpectedView.Count(p => p == view_number) >= context.M)
            {
                InitializeConsensus(view_number);
            }

            Log($"end{nameof(CheckExpectedView)}: elapsed={sw.Elapsed.ToString()}");
            sw.Stop();
        }

        protected virtual bool CheckPolicy(Transaction tx) { return true; }

        private void CheckSignatures()
        {
            Stopwatch sw = Stopwatch.StartNew();
            Log($"{nameof(CheckSignatures)}");

            if (context.Signatures.Count(p => p != null) >= context.M && context.TransactionHashes.All(p => context.Transactions.ContainsKey(p)))
            {
                Contract contract = Contract.CreateMultiSigContract(context.M, context.Validators);
                Block block = context.MakeHeader();
                ContractParametersContext sc = new ContractParametersContext(block);
                for (int i = 0, j = 0; i < context.Validators.Length && j < context.M; i++)
                    if (context.Signatures[i] != null)
                    {
                        sc.AddSignature(contract, context.Validators[i], context.Signatures[i]);
                        j++;
                    }
                sc.Verifiable.Scripts = sc.GetScripts();
                block.Transactions = context.TransactionHashes.Select(p => context.Transactions[p]).ToArray();
                Log($"relay block: {block.Hash}");
                if (!localNode.Relay(block))
                    Log($"reject block: {block.Hash}");
                context.State |= ConsensusState.BlockSent;
            }

            Log($"end{nameof(CheckSignatures)}: elapsed={sw.Elapsed.ToString()}");
            sw.Stop();
        }

        private MinerTransaction CreateMinerTransaction(IEnumerable<Transaction> transactions, uint height, ulong nonce)
        {
            Stopwatch sw = Stopwatch.StartNew();
            Log($"{nameof(CreateMinerTransaction)}");

            Fixed8 amount_netfee = Block.CalculateNetFee(transactions);
            TransactionOutput[] outputs = amount_netfee == Fixed8.Zero ? new TransactionOutput[0] : new[] { new TransactionOutput
            {
                AssetId = Blockchain.UtilityToken.Hash,
                Value = amount_netfee,
                ScriptHash = wallet.GetChangeAddress()
            } };

            MinerTransaction ret = new MinerTransaction
            {
                Nonce = (uint)(nonce % (uint.MaxValue + 1ul)),
                Attributes = new TransactionAttribute[0],
                Inputs = new CoinReference[0],
                Outputs = outputs,
                Scripts = new Witness[0]
            };

            Log($"end{nameof(CreateMinerTransaction)}: elapsed={sw.Elapsed.ToString()}");
            sw.Stop();

            return ret;
        }

        public void Dispose()
        {
            Log("OnStop");
            if (timer != null) timer.Dispose();
            if (started)
            {
                Blockchain.PersistCompleted -= Blockchain_PersistCompleted;
                LocalNode.InventoryReceiving -= LocalNode_InventoryReceiving;
                LocalNode.InventoryReceived -= LocalNode_InventoryReceived;
            }
        }

        private static ulong GetNonce()
        {
            byte[] nonce = new byte[sizeof(ulong)];
            rand.NextBytes(nonce);
            return nonce.ToUInt64(0);
        }

        private void InitializeConsensus(byte view_number)
        {
            Stopwatch sw = Stopwatch.StartNew();
            Log($"{nameof(InitializeConsensus)}");

            lock (context)
            {
                if (view_number == 0)
                    context.Reset(wallet);
                else
                    context.ChangeView(view_number);
                if (context.MyIndex < 0)
                {
                    Log($"end{nameof(InitializeConsensus)}: elapsed={sw.Elapsed.ToString()} Invalid MyIndex");
                    sw.Stop();
                    return;
                }
                Log($"initialize: height={context.BlockIndex} view={view_number} index={context.MyIndex} role={(context.MyIndex == context.PrimaryIndex ? ConsensusState.Primary : ConsensusState.Backup)}");
                if (context.MyIndex == context.PrimaryIndex)
                {
                    context.State |= ConsensusState.Primary;
                    timer_height = context.BlockIndex;
                    timer_view = view_number;
                    TimeSpan span = DateTime.Now - block_received_time;
                    if (span >= Blockchain.TimePerBlock)
                        timer.Change(0, Timeout.Infinite);
                    else
                        timer.Change(Blockchain.TimePerBlock - span, Timeout.InfiniteTimeSpan);
                }
                else
                {
                    context.State = ConsensusState.Backup;
                    timer_height = context.BlockIndex;
                    timer_view = view_number;
                    timer.Change(TimeSpan.FromSeconds(Blockchain.SecondsPerBlock << (view_number + 1)), Timeout.InfiniteTimeSpan);
                }
            }

            Log($"end{nameof(InitializeConsensus)}: elapsed={sw.Elapsed.ToString()}");
            sw.Stop();
        }

        private void LocalNode_InventoryReceived(object sender, IInventory inventory)
        {
            ConsensusPayload payload = inventory as ConsensusPayload;
            if (payload == null) return;

            Stopwatch sw = Stopwatch.StartNew();
            Log($"{nameof(LocalNode_InventoryReceived)}");

            lock (context)
            {
                if (payload.ValidatorIndex == context.MyIndex)
                {
                    Log($"end{nameof(LocalNode_InventoryReceived)}: elapsed={sw.Elapsed.ToString()} != Not my ValidatorIndex");
                    sw.Stop();

                    return;
                }
                if (payload.Version != ConsensusContext.Version || payload.PrevHash != context.PrevHash || payload.BlockIndex != context.BlockIndex)
                {
                    Log($"end{nameof(LocalNode_InventoryReceived)}: elapsed={sw.Elapsed.ToString()} != Version or Hash");
                    sw.Stop();

                    return;
                }
                if (payload.ValidatorIndex >= context.Validators.Length)
                {
                    Log($"end{nameof(LocalNode_InventoryReceived)}: elapsed={sw.Elapsed.ToString()} >= ValidatorIndex");
                    sw.Stop();

                    return;
                }
                ConsensusMessage message;
                try
                {
                    message = ConsensusMessage.DeserializeFrom(payload.Data);
                }
                catch (Exception e)
                {
                    NeoPlugin.BroadcastLog(e);
                    return;
                }
                if (message.ViewNumber != context.ViewNumber && message.Type != ConsensusMessageType.ChangeView)
                {
                    Log($"end{nameof(LocalNode_InventoryReceived)}: elapsed={sw.Elapsed.ToString()} != ChangeView");
                    sw.Stop();
                    return;
                }
                switch (message.Type)
                {
                    case ConsensusMessageType.ChangeView:
                        OnChangeViewReceived(payload, (ChangeView)message);
                        break;
                    case ConsensusMessageType.PrepareRequest:
                        OnPrepareRequestReceived(payload, (PrepareRequest)message);
                        break;
                    case ConsensusMessageType.PrepareResponse:
                        OnPrepareResponseReceived(payload, (PrepareResponse)message);
                        break;
                }
            }

            Log($"end{nameof(LocalNode_InventoryReceived)}: elapsed={sw.Elapsed.ToString()}");
            sw.Stop();
        }

        private void LocalNode_InventoryReceiving(object sender, InventoryReceivingEventArgs e)
        {
            Transaction tx = e.Inventory as Transaction;
            if (tx != null)
            {
                Stopwatch sw = Stopwatch.StartNew();
                Log($"{nameof(LocalNode_InventoryReceiving)} threads: {Process.GetCurrentProcess().Threads.Count}");

                lock (context)
                {
                    if (!context.State.HasFlag(ConsensusState.Backup) || !context.State.HasFlag(ConsensusState.RequestReceived) || context.State.HasFlag(ConsensusState.SignatureSent) || context.State.HasFlag(ConsensusState.ViewChanging))
                    {
                        Log($"end{nameof(LocalNode_InventoryReceiving)}: WrongState elapsed={sw.Elapsed.ToString()}");
                        sw.Stop();
                        return;
                    }
                    if (context.Transactions.ContainsKey(tx.Hash))
                    {
                        Log($"end{nameof(LocalNode_InventoryReceiving)}: !Transactions.Contains elapsed={sw.Elapsed.ToString()}");
                        sw.Stop();
                        return;
                    }
                    if (!context.TransactionHashes.Contains(tx.Hash))
                    {
                        Log($"end{nameof(LocalNode_InventoryReceiving)}: !TransactionHashes.Contains elapsed={sw.Elapsed.ToString()}");
                        sw.Stop();
                        return;
                    }

                    AddTransaction(tx, true);
                    e.Cancel = true;
                }

                Log($"end{nameof(LocalNode_InventoryReceiving)}: elapsed={sw.Elapsed.ToString()}");
                sw.Stop();
            }
        }

        protected virtual void Log(string message) { }

        private void OnChangeViewReceived(ConsensusPayload payload, ChangeView message)
        {
            Stopwatch sw = Stopwatch.StartNew();

            Log($"{nameof(OnChangeViewReceived)}: height={payload.BlockIndex} view={message.ViewNumber} index={payload.ValidatorIndex} nv={message.NewViewNumber}");
            if (message.NewViewNumber <= context.ExpectedView[payload.ValidatorIndex])
            {
                Log($"end{nameof(OnChangeViewReceived)}: <=NewViewNumber elapsed={sw.Elapsed.ToString()}");
                sw.Stop();
                return;
            }
            context.ExpectedView[payload.ValidatorIndex] = message.NewViewNumber;
            CheckExpectedView(message.NewViewNumber);

            Log($"end{nameof(OnChangeViewReceived)}: elapsed={sw.Elapsed.ToString()}");
            sw.Stop();
        }

        private void OnPrepareRequestReceived(ConsensusPayload payload, PrepareRequest message)
        {
            Stopwatch sw = Stopwatch.StartNew();
            Log($"{nameof(OnPrepareRequestReceived)}: height={payload.BlockIndex} view={message.ViewNumber} index={payload.ValidatorIndex} tx={message.TransactionHashes.Length}");

            if (!context.State.HasFlag(ConsensusState.Backup) || context.State.HasFlag(ConsensusState.RequestReceived))
            {
                Log($"end{nameof(OnPrepareRequestReceived)} InvalidState elapsed={sw.Elapsed.ToString()}");
                sw.Stop();
                return;
            }
            if (payload.ValidatorIndex != context.PrimaryIndex)
            {
                Log($"end{nameof(OnPrepareRequestReceived)} != ValidatorIndex elapsed={sw.Elapsed.ToString()}");
                sw.Stop();
                return;
            }
            if (payload.Timestamp <= Blockchain.Default.GetHeader(context.PrevHash).Timestamp || payload.Timestamp > DateTime.Now.AddMinutes(10).ToTimestamp())
            {
                Log($"end{nameof(OnPrepareRequestReceived)} Timestamp incorrect: {payload.Timestamp} elapsed={sw.Elapsed.ToString()}");
                sw.Stop();
                return;
            }
            context.State |= ConsensusState.RequestReceived;
            context.Timestamp = payload.Timestamp;
            context.Nonce = message.Nonce;
            context.NextConsensus = message.NextConsensus;
            context.TransactionHashes = message.TransactionHashes;
            context.Transactions = new Dictionary<UInt256, Transaction>();
            if (!Crypto.Default.VerifySignature(context.MakeHeader().GetHashData(), message.Signature, context.Validators[payload.ValidatorIndex].EncodePoint(false)))
            {
                Log($"end{nameof(OnPrepareRequestReceived)}: BadSignature elapsed={sw.Elapsed.ToString()}");
                sw.Stop();
                return;
            }
            context.Signatures = new byte[context.Validators.Length][];
            context.Signatures[payload.ValidatorIndex] = message.Signature;
            Dictionary<UInt256, Transaction> mempool = LocalNode.GetMemoryPoolArray().AsQueryable().ToDictionary(p => p.Hash);
            foreach (UInt256 hash in context.TransactionHashes.Skip(1))
            {
                if (mempool.TryGetValue(hash, out Transaction tx))
                    if (!AddTransaction(tx, false))
                    {
                        Log($"end{nameof(OnPrepareRequestReceived)}: !AddTransaction elapsed={sw.Elapsed.ToString()}");
                        sw.Stop();

                        return;
                    }
            }
            if (!AddTransaction(message.MinerTransaction, true))
            {
                Log($"end{nameof(OnPrepareRequestReceived)}: !AddMinnerTransaction elapsed={sw.Elapsed.ToString()}");
                sw.Stop();
                return;
            }
            LocalNode.AllowHashes(context.TransactionHashes.Except(context.Transactions.Keys));
            if (context.Transactions.Count < context.TransactionHashes.Length)
                localNode.SynchronizeMemoryPool();

            Log($"end{nameof(OnPrepareRequestReceived)}: elapsed={sw.Elapsed.ToString()}");
            sw.Stop();
        }

        private void OnPrepareResponseReceived(ConsensusPayload payload, PrepareResponse message)
        {
            Stopwatch sw = Stopwatch.StartNew();

            Log($"{nameof(OnPrepareResponseReceived)}: height={payload.BlockIndex} view={message.ViewNumber} index={payload.ValidatorIndex}");
            if (context.State.HasFlag(ConsensusState.BlockSent))
            {
                Log($"end{nameof(OnPrepareResponseReceived)}: BadState elapsed={sw.Elapsed.ToString()}");
                sw.Stop();
                return;
            }
            if (context.Signatures[payload.ValidatorIndex] != null)
            {
                Log($"end{nameof(OnPrepareResponseReceived)}: AlreadySigned elapsed={sw.Elapsed.ToString()}");
                sw.Stop();
                return;
            }
            Block header = context.MakeHeader();
            if (header == null || !Crypto.Default.VerifySignature(header.GetHashData(), message.Signature, context.Validators[payload.ValidatorIndex].EncodePoint(false)))
            {
                Log($"end{nameof(OnPrepareResponseReceived)}: BadSignature elapsed={sw.Elapsed.ToString()}");
                sw.Stop();
                return;
            }
            context.Signatures[payload.ValidatorIndex] = message.Signature;
            CheckSignatures();

            Log($"end{nameof(OnPrepareResponseReceived)}: elapsed={sw.Elapsed.ToString()}");
            sw.Stop();
        }

        private void OnTimeout(object state)
        {
            lock (context)
            {
                if (timer_height != context.BlockIndex || timer_view != context.ViewNumber) return;

                Stopwatch sw = Stopwatch.StartNew();

                Log($"{nameof(OnTimeout)}: height={timer_height} view={timer_view} state={context.State}");
                if (context.State.HasFlag(ConsensusState.Primary) && !context.State.HasFlag(ConsensusState.RequestSent))
                {
                    Log($"send perpare request: height={timer_height} view={timer_view}");
                    context.State |= ConsensusState.RequestSent;
                    if (!context.State.HasFlag(ConsensusState.SignatureSent))
                    {
                        context.Timestamp = Math.Max(DateTime.Now.ToTimestamp(), Blockchain.Default.GetHeader(context.PrevHash).Timestamp + 1);
                        context.Nonce = GetNonce();

                        List<Transaction> transactions = new List<Transaction>(LocalNode.GetMemoryPoolArray());

                        // Check without mempool lock
                        if (RequireCheckPolicy)
                        {
                            for (int x = transactions.Count - 1; x >= 0; x--)
                                if (!CheckPolicy(transactions[x])) transactions.RemoveAt(x);
                        }

                        if (transactions.Count >= Settings.Default.MaxTransactionsPerBlock)
                            transactions = transactions.OrderByDescending(p => p.NetworkFee / p.Size).Take(Settings.Default.MaxTransactionsPerBlock - 1).ToList();
                        transactions.Insert(0, CreateMinerTransaction(transactions, context.BlockIndex, context.Nonce));
                        context.TransactionHashes = transactions.Select(p => p.Hash).ToArray();
                        context.Transactions = transactions.ToDictionary(p => p.Hash);
                        context.NextConsensus = Blockchain.GetConsensusAddress(Blockchain.Default.GetValidators(transactions).ToArray());
                        context.Signatures[context.MyIndex] = context.MakeHeader().Sign(context.KeyPair);
                    }
                    SignAndRelay(context.MakePrepareRequest());
                    timer.Change(TimeSpan.FromSeconds(Blockchain.SecondsPerBlock << (timer_view + 1)), Timeout.InfiniteTimeSpan);
                }
                else if ((context.State.HasFlag(ConsensusState.Primary) && context.State.HasFlag(ConsensusState.RequestSent)) || context.State.HasFlag(ConsensusState.Backup))
                {
                    RequestChangeView();
                }

                Log($"end{nameof(OnTimeout)}: elapsed={sw.Elapsed.ToString()}");
                sw.Stop();
            }
        }

        private void RequestChangeView()
        {
            Stopwatch sw = Stopwatch.StartNew();

            context.State |= ConsensusState.ViewChanging;
            context.ExpectedView[context.MyIndex]++;
            Log($"{nameof(RequestChangeView)}: height={context.BlockIndex} view={context.ViewNumber} nv={context.ExpectedView[context.MyIndex]} state={context.State}");
            timer.Change(TimeSpan.FromSeconds(Blockchain.SecondsPerBlock << (context.ExpectedView[context.MyIndex] + 1)), Timeout.InfiniteTimeSpan);
            SignAndRelay(context.MakeChangeView());
            CheckExpectedView(context.ExpectedView[context.MyIndex]);

            Log($"end{nameof(RequestChangeView)}: elapsed={sw.Elapsed.ToString()}");
            sw.Stop();
        }

        private void SignAndRelay(ConsensusPayload payload)
        {
            Stopwatch sw = Stopwatch.StartNew();
            Log($"{nameof(SignAndRelay)}");

            ContractParametersContext sc;
            try
            {
                sc = new ContractParametersContext(payload);
                wallet.Sign(sc);
            }
            catch (InvalidOperationException e)
            {
                NeoPlugin.BroadcastLog(e);
                return;
            }
            sc.Verifiable.Scripts = sc.GetScripts();
            localNode.RelayDirectly(payload, true);

            Log($"end{nameof(SignAndRelay)}: elapsed={sw.Elapsed.ToString()}");
            sw.Stop();
        }

        public void Start()
        {
            Log("OnStart");
            started = true;
            Blockchain.PersistCompleted += Blockchain_PersistCompleted;
            LocalNode.InventoryReceiving += LocalNode_InventoryReceiving;
            LocalNode.InventoryReceived += LocalNode_InventoryReceived;
            InitializeConsensus(0);
        }
    }
}