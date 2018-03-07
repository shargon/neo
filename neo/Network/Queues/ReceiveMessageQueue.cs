using Neo.IO;
using Neo.Network.Payloads;
using System.Collections.Generic;

namespace Neo.Network.Queues
{
    public class ReceiveMessageQueue : MessageQueue<ParsedMessage>
    {
        bool IsHighPriorityMessage(MessageCommand command, ISerializable payload)
        {
            switch (command)
            {
                case MessageCommand.block:
                case MessageCommand.merkleblock:
                case MessageCommand.consensus:
                case MessageCommand.getheaders:
                case MessageCommand.getblocks:
                case MessageCommand.invpool:
                case MessageCommand.getdata:
                    {
                        return true;
                    }
                case MessageCommand.inv:
                    {
                        if (payload is InvPayload inv && inv.Type != InventoryType.TX)
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
            Queue<ParsedMessage> message_queue =
                IsHighPriorityMessage(command, payload) ?
                QueueHigh : QueueLow;

            lock (message_queue)
            {
                message_queue.Enqueue(new ParsedMessage(command, payload));
            }
        }
    }
}