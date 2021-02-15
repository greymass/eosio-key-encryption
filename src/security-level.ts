export enum SecurityLevel {
    default = 0b0010_0100, // N=32768 p=16 r=1
    high = 0b0100_0100, // N=65536 p=16 r=1
    paranoid = 0b0110_0100, // N=131072 p=16 r=1
}

export namespace SecurityLevel {
    export function paramsFor(value: SecurityLevel | number) {
        const nExp = ((value & 0b1110_0000) >> 5) + 14 // First 3 bits is N starting at 14
        const rExp = ((value & 0b0001_1100) >> 2) + 3 // Next 3 bits is r starting at 3
        const pExp = value & 0b0000_0011 // Last two bits is p
        // raise to power of 2
        const N = 1 << nExp
        const r = 1 << rExp
        const p = 1 << pExp
        return {N, r, p}
    }
}
