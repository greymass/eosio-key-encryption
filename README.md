EOSIO Key Encryption / EEP-8
============================

Specification and reference implementation of EOSIO Key Encryption (EEP-8).

## Installation

The `eosio-key-encryption` package is distributed as a module on [npm](https://www.npmjs.com/package/eosio-key-encryption).

```
yarn add eosio-key-encryption
# or
npm install --save eosio-key-encryption
```

## Usage

```ts
import {decrypt, encrypt} from 'eosio-key-encryption'

const wif = '5JiAW9u8f2bwV2KcQRRt7WYMQnEdXwSxSDX2hnM2EccuX8eAXcP'
const password = [104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100] // utf-8 "hello world"

encrypt(wif, password).then((encrypted) => {
    console.log(JSON.stringify(encrypted)) // "SEC_K1_8xacaDNEJyzqu1RG4dG7sBwo9QCA24EePExWLPPTBWVDiMo6BpAw7DHq"
})

decrypt('SEC_K1_8xacaDNEJyzqu1RG4dG7sBwo9QCA24EePExWLPPTBWVDiMo6BpAw7DHq', password).then((key) => {
    console.log(key.toWif()) // 5JiAW9u8f2bwV2KcQRRt7WYMQnEdXwSxSDX2hnM2EccuX8eAXcP
})
```

## Developing

You need [Make](https://www.gnu.org/software/make/), [node.js](https://nodejs.org/en/) and [yarn](https://classic.yarnpkg.com/en/docs/install) installed.

Clone the repository and run `make` to checkout all dependencies and build the project. See the [Makefile](./Makefile) for other useful targets. Before submitting a pull request make sure to run `make lint`.

---

Made with ☕️ & ❤️ by [Greymass](https://greymass.com), if you find this useful please consider [supporting us](https://greymass.com/support-us).
