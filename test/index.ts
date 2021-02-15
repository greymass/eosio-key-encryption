import 'mocha'

import {Bytes, PrivateKey, Serializer} from '@greymass/eosio'
import {strict as assert} from 'assert'

import {EncryptedPrivateKey} from '../src/encrypted-private-key'

suite('EncryptedPrivateKey', function () {
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
})
