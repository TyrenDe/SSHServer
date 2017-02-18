export class SSHLogger {
    static logError(message: string): void {
        console.log("ERROR: " + message);
    }

    static logDebug(message: string): void {
        console.log("DEBUG: " + message);
    }

    static logWarning(message: string): void {
        console.log(" WARN: " + message);
    }

    static logInfo(message: string): void {
        console.log(" INFO: " + message);
    }
}
