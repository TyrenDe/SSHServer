import { IKexAlgorithm } from "./KexAlgorithms/IKexAlgorithm";
import { IHostKeyAlgorithm } from "./HostKeyAlgorithms/IHostKeyAlgorithm";
import { ICipher } from "./Ciphers/ICipher";
import { NoCipher } from "./Ciphers/NoCipher";
import { IMACAlgorithm } from "./MACAlgorithms/IMACAlgorithm";
import { ICompression } from "./Compressions/ICompression";
import { NoCompression } from "./Compressions/NoCompression";

export class ExchangeContext {
    public kexAlgorithm: IKexAlgorithm = null;
    public hostKeyAlgorithm: IHostKeyAlgorithm = null;
    public cipherClientToServer: ICipher = new NoCipher();
    public cipherServerToClient: ICipher = new NoCipher();
    public macAlgorithmClientToServer: IMACAlgorithm = null;
    public macAlgorithmServerToClient: IMACAlgorithm = null;
    public compressionClientToServer: ICompression = new NoCompression();
    public compressionServerToClient: ICompression = new NoCompression();
}
