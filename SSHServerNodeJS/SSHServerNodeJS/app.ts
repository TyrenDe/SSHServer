import { SSHLogger } from "./SSHLogger";
import { Server } from "./Server";

const sleep: any = require("sleep2");

let isRunning: boolean = true;
process.on("SIGINT", function (): void {

    SSHLogger.logInfo("Gracefully shutting down from SIGINT (Ctrl+C)");

    isRunning = false;
});

let server: Server = new Server();
server.start();

(async () => {
    while (isRunning) {
        server.poll();
        await sleep(25);
    }

    server.stop();

    process.exit(0);
})();
