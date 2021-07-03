import {
    ABIDecoder,
    ABIEncoder,
    ABISerializableObject,
    Base58,
    Bytes,
    BytesType,
    Checksum256,
    CurveType,
    isInstanceOf,
    PrivateKey,
    PrivateKeyType,
    UInt8,
    UInt8Type,
} from '@greymass/eosio'
import {ProgressCallback, scrypt as scryptJs} from 'scrypt-js'
import {AES_CBC} from 'asmcrypto.js'
import {SecurityLevel, SecurityLevelType} from './security-level'

type ScryptInterface = typeof scryptJs

export type {ProgressCallback, ScryptInterface}

export type EncryptedPrivateKeyType = EncryptedPrivateKey | string

export class EncryptedPrivateKey implements ABISerializableObject {
    static abiName = 'encrypted_private_key'

    static scrypt: ScryptInterface = scryptJs

    static async encrypt(
        key: PrivateKeyType,
        password: BytesType,
        progress?: ProgressCallback,
        security: SecurityLevelType = SecurityLevel.default
    ) {
        key = PrivateKey.from(key)
        password = Bytes.from(password)
        const checksum = getChecksum(key)
        const level = SecurityLevel.from(security)
        const params = SecurityLevel.paramsFor(level)

        const cbc = await CBC(password, checksum, params, this.scrypt, progress)
        const ciphertext = cbc.encrypt(key.data.array)

        return new this(key.type, level, checksum, ciphertext)
    }

    static from(value: EncryptedPrivateKeyType) {
        if (isInstanceOf(value, this)) {
            return value
        }
        return this.fromString(value)
    }

    static fromABI(decoder: ABIDecoder) {
        const type = CurveType.from(decoder.readByte())
        const flags = decoder.readByte()
        const checksum = decoder.readArray(4)
        let ciphertext: Uint8Array
        switch (type) {
            case CurveType.K1:
            case CurveType.R1:
                ciphertext = decoder.readArray(32)
                break
            default:
                throw new Error(`Unsupported key type: ${type}`)
        }
        return new this(type, flags, checksum, ciphertext)
    }

    static fromString(string: string) {
        const parts = string.split('_')
        if (parts.length != 3 || parts[0] !== 'SEC') {
            throw new Error('Invalid encrypted private key string')
        }
        const type = CurveType.from(parts[1])
        const decoded = Base58.decodeRipemd160Check(parts[2], undefined, type).array
        return new this(type, decoded[0], decoded.subarray(1, 5), decoded.subarray(5))
    }

    readonly type: CurveType
    private level: UInt8
    private checksum: Bytes
    private ciphertext: Bytes

    constructor(type: CurveType, level: UInt8Type, checksum: BytesType, ciphertext: BytesType) {
        this.type = type
        this.level = UInt8.from(level)
        this.checksum = Bytes.from(checksum)
        this.ciphertext = Bytes.from(ciphertext)
    }

    get params() {
        return SecurityLevel.paramsFor(this.level.value)
    }

    equals(other: EncryptedPrivateKeyType) {
        return EncryptedPrivateKey.from(other).toString() === this.toString()
    }

    async decrypt(password: BytesType, progress?: ProgressCallback) {
        const cbc = await CBC(
            Bytes.from(password),
            this.checksum,
            this.params,
            (this.constructor as typeof EncryptedPrivateKey).scrypt,
            progress
        )
        const data = cbc.decrypt(this.ciphertext.array)

        const key = new PrivateKey(this.type, Bytes.from(data))
        const checksum = getChecksum(key)

        if (!this.checksum.equals(checksum)) {
            throw new Error('Invalid password')
        }

        return key
    }

    private toData() {
        return Bytes.from([this.level.value]).appending(this.checksum).appending(this.ciphertext)
    }

    toString() {
        return `SEC_${this.type}_${Base58.encodeRipemd160Check(this.toData(), this.type)}`
    }

    toABI(encoder: ABIEncoder) {
        encoder.writeByte(CurveType.indexFor(this.type))
        encoder.writeArray(this.toData().array)
    }

    toJSON() {
        return this.toString()
    }
}

async function CBC(
    password: Bytes,
    salt: Bytes,
    params: {N: number; r: number; p: number},
    scrypt: ScryptInterface,
    progress?: ProgressCallback
) {
    const hash = await scrypt(
        password.array,
        salt.array,
        params.N,
        params.r,
        params.p,
        32 + 16,
        progress
    )
    const iv = hash.slice(0, 16)
    const key = hash.slice(16, 48)
    return new AES_CBC(key, iv, false)
}

// First 4 bytes of double sha256 over key string (`PUB_<type>_<base58check>`)
function getChecksum(key: PrivateKey) {
    const pub = Bytes.from(key.toPublic().toString(), 'utf8')
    return Bytes.from(Checksum256.hash(Checksum256.hash(pub).array).array.subarray(0, 4))
}
