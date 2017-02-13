using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SSHServer.HostKeyAlgorithms
{
    public interface IHostKeyAlgorithm : IAlgorithm
    {
        void ImportKey(string keyXml);
        byte[] CreateKeyAndCertificatesData();
        byte[] CreateSignatureData(byte[] hash);
    }
}
