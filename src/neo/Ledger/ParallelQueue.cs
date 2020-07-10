using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace Neo.Ledger
{
    public class ParallelQueue<T>
    {
        private long _isStarted = 0;
        private CancellationTokenSource _cancel;

        /// <summary>
        /// Sorted Queue for oracle tasks
        /// </summary>
        private readonly BlockingCollection<T> _processingQueue;

        /// <summary>
        /// Number of threads for processing the oracle
        /// </summary>
        private Task[] _tasks;

        /// <summary>
        /// Processor
        /// </summary>
        private readonly Action<T> Processor;

        /// <summary>
        /// Is started
        /// </summary>
        public bool IsStarted => Interlocked.Read(ref _isStarted) == 1;

        /// <summary>
        /// Total entries in the pool.
        /// </summary>
        public int PendingCount => _processingQueue.Count;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="action">Action</param>
        public ParallelQueue(Action<T> action)
        {
            if (action == null) throw new ArgumentNullException(nameof(action));

            Processor = action;
            _processingQueue = new BlockingCollection<T>();
        }

        /// <summary>
        /// Start oracle
        /// </summary>
        /// <param name="numberOfTasks">Number of tasks</param>
        public void Start(byte numberOfTasks = 4)
        {
            if (Interlocked.Exchange(ref _isStarted, 1) != 0) return;

            // Create tasks

            _cancel = new CancellationTokenSource();
            _tasks = new Task[numberOfTasks];

            for (int x = 0; x < _tasks.Length; x++)
            {
                _tasks[x] = new Task(() =>
                {
                    foreach (var item in _processingQueue.GetConsumingEnumerable(_cancel.Token))
                    {
                        Processor.Invoke(item);
                    }
                },
                _cancel.Token);
            }

            // Start tasks

            foreach (var task in _tasks) task.Start();
        }

        /// <summary>
        /// Stop oracle
        /// </summary>
        public void Stop()
        {
            if (Interlocked.Exchange(ref _isStarted, 0) != 1) return;

            _cancel.Cancel();

            for (int x = 0; x < _tasks.Length; x++)
            {
                try { _tasks[x].Wait(); } catch { }
                try { _tasks[x].Dispose(); } catch { }
            }

            _cancel.Dispose();
            _cancel = null;
            _tasks = null;

            // Clean queue

            while (_processingQueue.Count > 0) _processingQueue.TryTake(out _);
        }

        /// <summary>
        /// Enqueue entry
        /// </summary>
        /// <param name="item">Entry</param>
        public void Enqueue(T item)
        {
            _processingQueue.Add(item);
        }
    }
}
