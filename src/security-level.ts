export type SecurityLevelType = number | {N: number; r: number; p: number}

export enum SecurityLevel {
    default = 0b001_001_00, // N=32768 r=16 p=1
    high = 0b010_001_00, // N=65536 r=16 p=1
    paranoid = 0b011_010_00, // N=131072 r=32 p=1
}

export namespace SecurityLevel {
    export function from(value: SecurityLevelType) {
        if (typeof value === 'number') {
            if ((value & 0xff) !== value) {
                throw new Error('Invalid security level, must be in range 0-255')
            }
            return value
        } else {
            return headerFor(value)
        }
    }

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

    export function headerFor({N, r, p}: {N: number; r: number; p: number}) {
        const nExp = Math.log2(N) - 14
        if (~~nExp != nExp || nExp > 7 || nExp < 0) {
            throw new Error('Invalid N value, must be a power of two in the range 16384-2097152')
        }
        const rExp = Math.log2(r) - 3
        if (~~rExp != rExp || rExp > 7 || rExp < 0) {
            throw new Error('Invalid r value, must be a power of two in the range 8-1024')
        }
        const pExp = Math.log2(p)
        if (~~pExp != pExp || pExp > 3) {
            throw new Error('Invalid p value, must be a power of two and no larger than 8')
        }
        let rv = 0
        rv |= nExp << 5
        rv |= rExp << 2
        rv |= pExp
        return rv
    }
}
