import {BytesType, PrivateKeyType} from '@greymass/eosio'
import {ProgressCallback} from 'scrypt-js'
import {EncryptedPrivateKey, EncryptedPrivateKeyType} from './encrypted-private-key'

export async function encrypt(
    key: PrivateKeyType,
    password: BytesType,
    progress?: ProgressCallback
) {
    return await EncryptedPrivateKey.encrypt(key, password, progress)
}

export async function decrypt(
    key: EncryptedPrivateKeyType,
    password: BytesType,
    progress?: ProgressCallback
) {
    return await EncryptedPrivateKey.from(key).decrypt(password, progress)
}

export * from './encrypted-private-key'
export * from './security-level'
