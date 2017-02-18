export class ByteReader {
    private m_Data: Buffer;
    private m_Offset: number = 0;

    constructor(data: Buffer) {
        this.m_Data = data;
    }

    public isEOF(): boolean {
        return (this.m_Offset >= this.m_Data.length);
    }

    public getBytes(length: number): Buffer {
        let results: Buffer = this.m_Data.slice(this.m_Offset, this.m_Offset + length);
        this.m_Offset += length;
        return results;
    }

    public getMPInt(): Buffer {
        let size: number = this.getUInt32();

        if (size === 0) {
            return Buffer.alloc(1);
        }

        let data: Buffer = this.getBytes(size);
        if (data[0] === 0) {
            return data.slice(1);
        }

        return data;
    }

    public getUInt32(): number {
        let data: Buffer = this.getBytes(4);
        return new Buffer(data).readUInt32BE(0);
    }

    public getString(encoding?: string): string {
        if (encoding === null) {
            encoding = "ASCII";
        }

        let length: number = this.getUInt32();

        if (length === 0) {
            return "";
        }

        return this.getBytes(length).toString(encoding);
    }

    public getNameList(): Array<string> {
        return this.getString().split(",");
    }

    public getBoolean(): boolean {
        return (this.getByte() !== 0);
    }

    public getByte(): number {
        return this.getBytes(1)[0];
    }
}
