using SSHServer.Ciphers;
using SSHServer.Compressions;
using SSHServer.HostKeyAlgorithms;
using SSHServer.KexAlgorithms;
using SSHServer.MACAlgorithms;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SSHServer
{
    public class ExchangeContext
    {
        public IKexAlgorithm KexAlgorithm { get; set; } = null;
        public IHostKeyAlgorithm HostKeyAlgorithm { get; set; } = null;
        public ICipher CipherClientToServer { get; set; } = new NoCipher();
        public ICipher CipherServerToClient { get; set; } = new NoCipher();
        public IMACAlgorithm MACAlgorithmClientToServer { get; set; } = null;
        public IMACAlgorithm MACAlgorithmServerToClient { get; set; } = null;
        public ICompression CompressionClientToServer { get; set; } = new NoCompression();
        public ICompression CompressionServerToClient { get; set; } = new NoCompression();
    }
}
