using System;

namespace SSHServer
{
    public class Program
    {
        private static bool s_IsRunning = true;
        public static void Main(string[] args)
        {
            Console.CancelKeyPress += Console_CancelKeyPress;

            Server server = new Server();
            server.Start();

            while (s_IsRunning)
            {
                server.Poll();
                System.Threading.Thread.Sleep(25);
            }

            server.Stop();
        }

        private static void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
            e.Cancel = true;
            s_IsRunning = false;
        }
    }
}
