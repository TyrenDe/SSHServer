using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace SSHServer
{
    public class Server
    {
        public const string ProtocolVersionExchange = "SSH-2.0-SSHServer";

        private const int DefaultPort = 22;
        private const int ConnectionBacklog = 64;

        private IConfigurationRoot m_Configuration;
        private LoggerFactory m_LoggerFactory;
        private ILogger m_Logger;

        private TcpListener m_Listener;
        private List<Client> m_Clients = new List<Client>();

        public Server()
        {
            m_Configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("sshserver.json", optional: false)
                .Build();

            m_LoggerFactory = new LoggerFactory();
            m_LoggerFactory.AddConsole(m_Configuration.GetSection("Logging"));
            m_Logger = m_LoggerFactory.CreateLogger("SSHServer");
        }

        public void Start()
        {
            // Ensure we are stopped before we start listening
            Stop();

            m_Logger.LogInformation("Starting up...");

            // Create a listener on the required port
            int port = m_Configuration.GetValue<int>("port", DefaultPort);
            m_Listener = new TcpListener(IPAddress.Any, port);
            m_Listener.Start(ConnectionBacklog);

            m_Logger.LogInformation($"Listening on port: {port}");
        }

        public void Poll()
        {
            // Check for new connections
            while (m_Listener.Pending())
            {
                Task<Socket> acceptTask = m_Listener.AcceptSocketAsync();
                acceptTask.Wait();

                Socket socket = acceptTask.Result;
                m_Logger.LogDebug($"New Client: {socket.RemoteEndPoint.ToString()}");

                // Create and add client list
                m_Clients.Add(new Client(socket, m_LoggerFactory.CreateLogger(socket.RemoteEndPoint.ToString())));
            }

            // Poll each client for activity
            m_Clients.ForEach(c => c.Poll());

            // Remove all disconnected clients
            m_Clients.RemoveAll(c => c.IsConnected == false);
        }

        public void Stop()
        {
            if (m_Listener != null)
            {
                m_Logger.LogInformation("Shutting down...");

                // Disconnect clients and clear clients
                m_Clients.ForEach(c => c.Disconnect());
                m_Clients.Clear();

                m_Listener.Stop();
                m_Listener = null;

                m_Logger.LogInformation("Stopped!");
            }
        }
    }
}
