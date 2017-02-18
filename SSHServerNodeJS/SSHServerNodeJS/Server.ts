import { SSHLogger } from "./SSHLogger";
import { Configuration } from "./Configuration";
import { Client } from "./Client";

import net = require("net");
import util = require("util");

let config: Configuration = require("./sshserver.json");

export class Server {
    public static ProtocolVersionExchange: string = "SSH-2.0-SSHServer";

    public static SupportedKexAlgorithms: Array<string> = ["diffie-hellman-group14-sha1"];
    public static SupportedHostKeyAlgorithms: Array<string> = ["ssh-rsa"];
    public static SupportedCiphers: Array<string> = ["3des-cbc"];
    public static SupportedMACAlgorithms: Array<string> = ["hmac-sha1"];
    public static SupportedCompressions: Array<string> = ["none"];

    private static DefaultPort: number = 22;

    private m_Server: net.Server;
    private m_Clients: Array<Client> = new Array<Client>();

    public start(): void {
        // ensure we are stopped before we start listening
        this.stop();

        SSHLogger.logInfo("Starting up...");

        // create a listener on the required port
        let port: number = config.port;
        if (isNaN(port)) {
            port = Server.DefaultPort;
        }

        let server: net.Server = net.createServer();
        this.m_Server = server.listen(port, null, 64);

        this.m_Server.on("connection", this.connectionReceived.bind(this));

        SSHLogger.logInfo(util.format("Listening on port: %d", port));
    }

    public poll(): void {

        // poll each client for activity
        this.m_Clients.forEach((client: Client) => client.poll());

        // remove all disconnected clients
        this.m_Clients = this.m_Clients.filter((client: Client): boolean => {
            return client.getIsConnected();
        });
    }

    public stop(): void {
        if (this.m_Server != null) {
            SSHLogger.logInfo("Shutting down...");

            // disconnect clients and clear clients
            for (let client of this.m_Clients) {
                client.disconnect();
            }

            this.m_Clients = [];

            this.m_Server.close();
            this.m_Server = null;

            SSHLogger.logInfo("Stopped!");
        }
    }

    private connectionReceived(socket: net.Socket): void {
        SSHLogger.logInfo("New Client: " + socket.remoteAddress);
        this.m_Clients.push(new Client(socket));
    }
}
