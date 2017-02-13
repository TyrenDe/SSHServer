using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SSHServer.MACAlgorithms
{
    public interface IMACAlgorithm : IAlgorithm
    {
        uint KeySize { get; }
        uint DigestLength { get; }
        void SetKey(byte[] key);
        byte[] ComputeHash(uint packetNumber, byte[] data);
    }
}
