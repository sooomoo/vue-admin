
export interface Signer {
    sign(data: Uint8Array): Uint8Array
    verify(data: Uint8Array, sign: Uint8Array): boolean
    signatureLen(): number
}
export interface Crypter {
    encrypt(data: Uint8Array): Uint8Array
    decrypt(data: Uint8Array): Uint8Array
}