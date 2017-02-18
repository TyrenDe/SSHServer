import { DisconnectReason } from "./Packets/DisconnectReason";

export class SSHServerException extends Error {
    public reason: DisconnectReason;

    constructor(reason: DisconnectReason, message: string) {
        super(message);

        this.reason = reason;
    }
}

export * from "./Packets/DisconnectReason";
