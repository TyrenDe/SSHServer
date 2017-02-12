using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SSHServer.KexAlgorithms
{
    public interface IKexAlgorithm : IAlgorithm
    {
        byte[] CreateKeyExchange();
        byte[] DecryptKeyExchange(byte[] keyEx);
        byte[] ComputeHash(byte[] value);
    }
}
