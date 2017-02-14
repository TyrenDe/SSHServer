using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SSHServer.Packets
{
    public class Unimplemented : Packet
    {
        public override PacketType PacketType
        {
            get
            {
                return PacketType.SSH_MSG_UNIMPLEMENTED;
            }
        }

        public uint RejectedPacketNumber { get; set; }

        public override void Load(ByteReader reader)
        {
            RejectedPacketNumber = reader.GetUInt32();
        }

        protected override void InternalGetBytes(ByteWriter writer)
        {
            // uint32 packet sequence number of rejected message
            writer.WriteUInt32(RejectedPacketNumber);
        }
    }
}
