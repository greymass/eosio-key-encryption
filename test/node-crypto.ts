import 'mocha'

import {Bytes, PrivateKey} from '@greymass/eosio'
import {strict as assert} from 'assert'
import crypto from 'crypto'

import {EncryptedPrivateKey} from '../src/encrypted-private-key'

function scryptAdapter(
    password: ArrayLike<number>,
    salt: ArrayLike<number>,
    N: number,
    r: number,
    p: number,
    dkLen: number
): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
        crypto.scrypt(
            Buffer.from(password as any),
            Buffer.from(salt as any),
            dkLen,
            {N, r, p, maxmem: 512 * 1024 * 1024},
            (error, derivedKey) => {
                if (error) {
                    reject(error)
                } else {
                    resolve(
                        new Uint8Array(
                            derivedKey.buffer,
                            derivedKey.byteOffset,
                            derivedKey.byteLength
                        )
                    )
                }
            }
        )
    })
}

suite('node.js crypto', function () {
    this.timeout(20 * 1000)

    const origAdapter = EncryptedPrivateKey.scrypt
    this.beforeAll(function () {
        EncryptedPrivateKey.scrypt = scryptAdapter
    })
    this.afterAll(function () {
        EncryptedPrivateKey.scrypt = origAdapter
    })

    test('encryption', async function () {
        this.slow(2 * 1000)

        const keyString = 'PVT_K1_jsufMdV436e3vbj45mUXNESb3juT6LFDj7rpr7Ar3Gajf3f5G'
        const key = PrivateKey.from(keyString)
        const password = Bytes.from('foobar', 'utf8')
        const encrypted = await EncryptedPrivateKey.encrypt(key, password)

        assert.equal(
            String(encrypted),
            'SEC_K1_8vWLjFLTcvWNKY8wwfMKJJ3Sf278qb5xQgqXFzrRF44ECxACwoC3RPTj'
        )

        const decrypted = await encrypted.decrypt(password)

        assert.equal(String(decrypted), keyString)

        await assert.rejects(() => encrypted.decrypt('beef'))
    })
})
