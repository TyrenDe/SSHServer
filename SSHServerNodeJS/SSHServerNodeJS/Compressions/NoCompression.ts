import { ICompression } from "./ICompression";

export class NoCompression implements ICompression {
    public getName(): string {
        return "none";
    }

    public compress(data: Buffer): Buffer {
        return data;
    }

    public decompress(data: Buffer): Buffer {
        return data;
    }
}
