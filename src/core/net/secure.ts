/* eslint-disable @typescript-eslint/no-explicit-any */

import * as base64 from '@juanelas/base64'
import nacl from 'tweetnacl';
import log from 'loglevel';

export const encoder = new TextEncoder()
export const decoder = new TextDecoder()

export const generateUUID = () => {
    return crypto.randomUUID().replace(/-/g, '')
}

export const base64Encode = (input: ArrayBufferLike | base64.TypedArray | Buffer | string, urlsafe?: boolean, padding?: boolean): string => {
    return base64.encode(input, urlsafe, padding)
}

export const base64Decode = (input: string): Uint8Array => {
    return base64.decode(input)
}

const encodePubString = (signKey: Uint8Array, boxKey: Uint8Array): string => {
    const randomBytes = nacl.randomBytes(24)
    const arr = [...signKey, ...boxKey]
    const all = new Uint8Array(arr)

    // for (let index = 17; index < all.length; index++) {
    //     const element = all[index];
    //     all[index] = element ^ all[index % 17]
    // }
    const val = base64Encode(all)
    log.debug(`encodeSecureString, after:`, base64Decode(val))
    return val
}

const encodePriString = (signKey: Uint8Array, boxKey: Uint8Array): string => {
    const randomBytes = nacl.randomBytes(24)
    const arr = [...signKey, ...boxKey]
    const all = new Uint8Array(arr)

    // for (let index = 17; index < all.length; index++) {
    //     const element = all[index];
    //     all[index] = element ^ all[index % 17]
    // }
    const val = base64Encode(all)
    log.debug(`encodeSecureString, after:`, base64Decode(val))
    return val
}

const decodePubString = (input: string): {
    sign: Uint8Array | null
    box: Uint8Array | null
} => {
    const all = base64Decode(input)
    log.debug(`decodePubString, after:`, all)
    // for (let index = 17; index < all.length; index++) {
    //     const element = all[index];
    //     all[index] = element ^ all[index % 17]
    // }
    const signPubKeySecure = all.subarray(0, 0 + nacl.sign.publicKeyLength)
    const boxPubKeySecure = all.subarray(0 + nacl.sign.publicKeyLength)
    if (signPubKeySecure.length != nacl.sign.publicKeyLength || boxPubKeySecure.length != nacl.box.publicKeyLength) {

        return { sign: null, box: null }
    }

    return { sign: signPubKeySecure, box: boxPubKeySecure }
}

const decodePriString = (input: string): {
    sign: Uint8Array | null
    box: Uint8Array | null
} => {
    const all = base64Decode(input)
    log.debug(`decodePriString, after:`, all)
    // for (let index = 17; index < all.length; index++) {
    //     const element = all[index];
    //     all[index] = element ^ all[index % 17]
    // }

    const signPriKeySecure = all.subarray(0, 0 + nacl.sign.secretKeyLength)
    const boxPriKeySecure = all.subarray(0 + nacl.sign.secretKeyLength)
    if (signPriKeySecure.length != nacl.sign.secretKeyLength || boxPriKeySecure.length != nacl.box.secretKeyLength) {
        return { sign: null, box: null }
    }

    return { sign: signPriKeySecure, box: boxPriKeySecure }
}
const isEqualSimpleArrays = (arr1: Uint8Array, arr2: Uint8Array) => {
    if (arr1.length !== arr2.length) {
        return false;
    }
    for (let i = 0; i < arr1.length; i++) {
        if (arr1[i] !== arr2[i]) {
            return false;
        }
    }
    return true;
}

export const decodeSecrets = (): [nacl.BoxKeyPair, nacl.SignKeyPair, string] => {
    // 当前会话的公钥藏在会话Id中，私钥藏在 ck 中
    let sessionId = document.cookie.split(';').find(c => c.trim().startsWith('sessionid='))?.split('=')[1] ?? ''
    let clientKey = document.cookie.split(';').find(c => c.trim().startsWith('clientid='))?.split('=')[1] ?? ''
    const pubKeys = decodePubString(sessionId)
    const priKeys = decodePriString(clientKey)
    if (!pubKeys.box || !pubKeys.sign || !priKeys.box || !priKeys.sign) {
        // 需要重新生成
        const signKeyPair = nacl.sign.keyPair.fromSeed(nacl.randomBytes(nacl.sign.seedLength))
        const boxKeyPair = nacl.box.keyPair.fromSecretKey(nacl.randomBytes(nacl.box.secretKeyLength))
        log.debug(`【decodeSecrets】new sign keypair `, signKeyPair)
        log.debug(`【decodeSecrets】new box keypair `, boxKeyPair)
        sessionId = encodePubString(signKeyPair.publicKey, boxKeyPair.publicKey)
        clientKey = encodePriString(signKeyPair.secretKey, boxKeyPair.secretKey,)
        document.cookie = `sessionid=${sessionId};path=/;samesite=lax`
        document.cookie = `clientid=${clientKey};path=/;samesite=lax`
        const pubKeys1 = decodePubString(sessionId)
        const priKeys1 = decodePriString(clientKey)
        log.debug('xxxxxx sign', pubKeys1.sign, priKeys1.sign)
        log.debug('xxxxxx box', pubKeys1.box, priKeys1.box)
        log.debug('sign pub key eq', isEqualSimpleArrays(pubKeys1.sign!, signKeyPair.publicKey))
        log.debug('box pub key eq', isEqualSimpleArrays(pubKeys1.box!, boxKeyPair.publicKey))
        log.debug('sign pri key eq', isEqualSimpleArrays(priKeys1.sign!, signKeyPair.secretKey))
        log.debug('box pri key eq', isEqualSimpleArrays(priKeys1.box!, boxKeyPair.secretKey))

        return [boxKeyPair, signKeyPair, sessionId]
    } else {
        // const boxKeyPair = { publicKey: boxPubKey, secretKey: boxPriKey }
        // const signKeyPair = { publicKey: signPubKey, secretKey: singPriKey }
        // log.debug(`【decodeSecrets】decode from cookie `, sessionId, clientKey, boxKeyPair, signKeyPair)
        // return [boxKeyPair, signKeyPair, sessionId]
        return [
            { publicKey: pubKeys.box, secretKey: priKeys.box },
            { publicKey: pubKeys.sign, secretKey: priKeys.sign },
            sessionId
        ]
    }
}

export const encryptData = (kp: nacl.BoxKeyPair, data: string): string => {
    const rawData = encoder.encode(data)
    const serverExPubKey = base64Decode(import.meta.env.VITE_SERVER_EX_PUB_KEY)
    const nonce = nacl.randomBytes(nacl.box.nonceLength)
    const res = nacl.box(rawData, nonce, serverExPubKey, kp.secretKey)
    return decoder.decode(new Uint8Array([...res, ...nonce]))
}

export const decryptData = (kp: nacl.BoxKeyPair, data: string): string => {
    const rawData = encoder.encode(data)
    const body = rawData.slice(0, rawData.length - nacl.box.nonceLength)
    const nonce = rawData.slice(rawData.length - nacl.box.nonceLength)
    const serverExPubKey = base64Decode(import.meta.env.VITE_SERVER_EX_PUB_KEY)
    const decrypted = nacl.box.open(body, nonce, serverExPubKey, kp.secretKey)
    if (!decrypted) {
        return ""
    }
    return decoder.decode(decrypted)
}

export const stringifyObj = (obj: any) => {
    const keys = Object.keys(obj).sort()
    const strObj = keys.map(k => `${k}=${obj[k]}`).join('&')
    log.debug(`【stringifyObj】strObj is`, obj, strObj)
    return strObj
}

export const generateSignature = (kp: nacl.SignKeyPair, data: string): string => {
    // Signs the message using the secret key and returns a signature.
    const arr = nacl.sign.detached(encoder.encode(data), kp.secretKey)
    return base64Encode(arr, true, false)
}

export const verifySignature = (data: string, signature: string) => {
    const signData = encoder.encode(data)
    const serverSignPubKey = base64Decode(import.meta.env.VITE_SERVER_SIGN_PUB_KEY)
    // Verifies the signature for the message and returns true if verification succeeded or false if it failed.
    return nacl.sign.detached.verify(signData, base64Decode(signature), serverSignPubKey)
}

export const getPlatform = () => {
    let platform = document.cookie.split(';').find(c => c.trim().startsWith('p='))?.split('=')[1]
    if (!platform) {
        platform = '8'
        document.cookie = `p=${platform};path=/;samesite=lax`
        log.debug(`【getPlatform】new platform id is`, platform)
    }
    return platform
}

export const isCryptoEnabled = () => {
    return import.meta.env.VITE_ENABLE_CRYPTO === 'true'
}