using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace SSHServer
{
    public class Client
    {
        private Socket m_Socket;
        private ILogger m_Logger;

        // We are considered connected if we have a valid socket object
        public bool IsConnected { get { return m_Socket != null; } }

        public Client(Socket socket, ILogger logger)
        {
            m_Socket = socket;
            m_Logger = logger;
        }

        public void Poll()
        {
            // TODO: Implement reading/processing of data
        }

        public void Disconnect()
        {
            m_Logger.LogDebug($"Disconnected");
            if (m_Socket != null)
            {
                try
                {
                    m_Socket.Shutdown(SocketShutdown.Both);
                }
                catch (Exception) { }

                m_Socket = null;
            }
        }
    }
}
