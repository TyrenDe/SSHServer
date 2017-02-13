using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SSHServer.Ciphers
{
    public interface ICipher : IAlgorithm
    {
        uint BlockSize { get; }
        uint KeySize { get; }
        byte[] Encrypt(byte[] data);
        byte[] Decrypt(byte[] data);
        void SetKey(byte[] key, byte[] iv);
    }
}
