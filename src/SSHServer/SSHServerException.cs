using SSHServer.Packets;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SSHServer
{
    public class SSHServerException : Exception
    {
        public DisconnectReason Reason { get; set; }

        public SSHServerException(DisconnectReason reason, string message) : base(message)
        {
            Reason = reason;
        }
    }
}
