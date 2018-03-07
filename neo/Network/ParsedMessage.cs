using Neo.IO;

namespace Neo.Network
{
    public class ParsedMessage
    {
        public readonly MessageCommand Command;
        public readonly ISerializable Payload;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="command">Message command</param>
        /// <param name="payload">Message payload</param>
        public ParsedMessage(MessageCommand command, ISerializable payload)
        {
            Command = command;
            Payload = payload;
        }
    }
}