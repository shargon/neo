using Neo.IO;
using Neo.Network.Payloads;
using System.Collections.Generic;
using System.Linq;

namespace Neo.Network.Queues
{
    public class SendMessageQueue : MessageQueue<Message>
    {
        bool IsHighPriorityMessage(MessageCommand command, ISerializable payload, out bool isSingle)
        {
            switch (command)
            {
                case MessageCommand.addr:
                case MessageCommand.getaddr:
                case MessageCommand.getblocks:
                case MessageCommand.getheaders:
                case MessageCommand.mempool: isSingle = true; break;
                default: isSingle = false; break;
            }

            switch (command)
            {
                case MessageCommand.block:
                case MessageCommand.merkleblock:
                case MessageCommand.invpool:
                case MessageCommand.alert:
                case MessageCommand.consensus:
                case MessageCommand.filteradd:
                case MessageCommand.filterclear:
                case MessageCommand.filterload:
                case MessageCommand.getaddr:
                case MessageCommand.getdata:
                case MessageCommand.mempool: return true;
                case MessageCommand.inv:
                    {
                        if (payload is InvPayload p && p.Type != InventoryType.TX)
                            return true;

                        return false;
                    }
                default: return false;
            }
        }
        /// <summary>
        /// Enqueue a message
        /// </summary>
        /// <param name="command">Command</param>
        /// <param name="payload">Payload</param>
        public void Enqueue(MessageCommand command, ISerializable payload)
        {
            Queue<Message> message_queue =
                IsHighPriorityMessage(command, payload, out bool isSingle) ?
                QueueHigh : QueueLow;

            lock (message_queue)
            {
                if (!isSingle || message_queue.All(p => p.Command != command))
                {
                    message_queue.Enqueue(Message.Create(command, payload));
                }
            }
        }
    }
}