using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SSHServer.Packets
{
    public class NewKeys : Packet
    {
        public override PacketType PacketType
        {
            get
            {
                return PacketType.SSH_MSG_NEWKEYS;
            }
        }

        protected override void InternalGetBytes(ByteWriter writer)
        {
            // No data, nothing to write
        }

        public override void Load(ByteReader reader)
        {
            // No data, nothing to load
        }
    }
}
