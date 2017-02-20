export class Key {
    algorithm: string;
    key: any;
}

export class Configuration {
    port: number;
    keys: Key[];
}
