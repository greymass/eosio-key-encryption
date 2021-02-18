import 'mocha'

import {Bytes, PrivateKey, Serializer} from '@greymass/eosio'
import {strict as assert} from 'assert'

import {EncryptedPrivateKey} from '../src/encrypted-private-key'
import {SecurityLevel} from '../src/security-level'

suite('EncryptedPrivateKey', function () {
    this.timeout(20 * 1000)

    test('encoding', function () {
        const keyString = 'SEC_K1_8vWLjFLTcvWNKY8wwfMKJJ3Sf278qb5xQgqXFzrRF44ECxACwoC3RPTj'
        const key = EncryptedPrivateKey.from(keyString)
        assert.equal(String(key), keyString)

        const data = '00241feb8491b4fd5745396bb401bac0be2c7a85855b3b2b79eaafced1396765e315b7a93fec'
        assert.equal(Serializer.encode({object: key}).hexString, data)
        assert.equal(Serializer.decode({data, type: EncryptedPrivateKey}).toString(), keyString)
    })

    test('encryption', async function () {
        this.slow(5 * 1000)

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

    test('scrypt params', function () {
        assert.deepEqual(SecurityLevel.paramsFor(0), {N: 16384, r: 8, p: 1})
        assert.deepEqual(SecurityLevel.paramsFor(0xff), {N: 2097152, r: 1024, p: 8})
        assert.deepEqual(SecurityLevel.paramsFor(SecurityLevel.default), {N: 32768, r: 16, p: 1})
        assert.deepEqual(SecurityLevel.paramsFor(SecurityLevel.high), {N: 65536, r: 16, p: 1})
        assert.deepEqual(SecurityLevel.paramsFor(SecurityLevel.paranoid), {N: 131072, r: 32, p: 1})

        assert.equal(SecurityLevel.from({N: 16384, r: 8, p: 1}), 0)
        assert.equal(SecurityLevel.from({N: 2097152, r: 1024, p: 8}), 0xff)
        assert.equal(SecurityLevel.from({N: 32768, r: 16, p: 1}), SecurityLevel.default)
        assert.equal(SecurityLevel.from({N: 65536, r: 16, p: 1}), SecurityLevel.high)
        assert.equal(SecurityLevel.from({N: 131072, r: 32, p: 1}), SecurityLevel.paranoid)
        assert.equal(SecurityLevel.from(104), SecurityLevel.paranoid)

        assert.throws(() => SecurityLevel.from({N: 8192, r: 8, p: 1}), /Invalid N/)
        assert.throws(() => SecurityLevel.from({N: 4194304, r: 8, p: 1}), /Invalid N/)
        assert.throws(() => SecurityLevel.from({N: 20201, r: 8, p: 1}), /Invalid N/)

        assert.throws(() => SecurityLevel.from({N: 16384, r: 4, p: 1}), /Invalid r/)
        assert.throws(() => SecurityLevel.from({N: 16384, r: 2048, p: 1}), /Invalid r/)
        assert.throws(() => SecurityLevel.from({N: 16384, r: 1000, p: 1}), /Invalid r/)

        assert.throws(() => SecurityLevel.from({N: 16384, r: 8, p: 0}), /Invalid p/)
        assert.throws(() => SecurityLevel.from({N: 16384, r: 8, p: 16}), /Invalid p/)
        assert.throws(() => SecurityLevel.from({N: 16384, r: 8, p: 3}), /Invalid p/)

        assert.throws(() => SecurityLevel.from(-1), /Invalid security level/)
        assert.throws(() => SecurityLevel.from(2000), /Invalid security level/)
    })
})
