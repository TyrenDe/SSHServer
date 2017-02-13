using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SSHServer.Compressions
{
    public interface ICompression : IAlgorithm
    {
        byte[] Compress(byte[] data);
        byte[] Decompress(byte[] data);
    }
}
