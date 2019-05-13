﻿using Neo.Network.P2P;
using System.Net;

namespace Neo
{
    public class ChannelsStartConfig
    {
        /// <summary>
        /// Tcp configuration
        /// </summary>
        public IPEndPoint Tcp { get; set; }

        /// <summary>
        /// Udp configuration
        /// </summary>
        public IPEndPoint Udp { get; set; }

        /// <summary>
        /// Web socket configuration
        /// </summary>
        public IPEndPoint WebSocket { get; set; }

        /// <summary>
        /// Minimum desired connections
        /// </summary>
        public int MinDesiredConnections { get; set; } = Peer.DefaultMinDesiredConnections;

        /// <summary>
        /// Max allowed connections
        /// </summary>
        public int MaxConnections { get; set; } = Peer.DefaultMaxConnections;

        /// <summary>
        /// Max allowed connections per address
        /// </summary>
        public int MaxConnectionsPerAddress { get; set; } = 3;
    }
}