using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SSHServer.Packets
{
    public class KexDHInit : Packet
    {
        public override PacketType PacketType
        {
            get
            {
                return PacketType.SSH_MSG_KEXDH_INIT;
            }
        }

        public byte[] ClientValue { get; set; }

        protected override void InternalGetBytes(ByteWriter writer)
        {
            // Server never sends this
            throw new SSHServerException(DisconnectReason.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "SSH Server should never send a SSH_MSG_KEXDH_INIT message");
        }

        public override void Load(ByteReader reader)
        {
            // First, the client sends the following:
            //  byte SSH_MSG_KEXDH_INIT (handled by base class)
            //  mpint e
            ClientValue = reader.GetMPInt();
        }
    }
}
