
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

export const encodeSecureString = (signKey: Uint8Array, boxKey: Uint8Array): string => {
    const randomBytes = nacl.randomBytes(24)
    const nonce = randomBytes.slice(0, 17)
    const arr = new Uint8Array([...randomBytes.slice(17), ...signKey, ...boxKey])
    for (let index = 0; index < arr.length; index++) {
        const element = arr[index];
        arr[index] = element ^ nonce[index % 17]
    }
    const final = new Uint8Array([...nonce, ...arr])
    return base64Encode(final, true, false)
}

export const decodeSecureString = (str: string, isPri: boolean): [Uint8Array | null, Uint8Array | null] => {
    let totalLength = 24 + nacl.sign.publicKeyLength + nacl.box.publicKeyLength
    if (isPri) {
        totalLength = 24 + nacl.sign.secretKeyLength + nacl.box.secretKeyLength
    }
    if (!str || str.length <= totalLength) {
        return [null, null]
    }
    const arr = base64Decode(str)
    if (arr.length != totalLength) {
        return [null, null]
    }
    const nonce = arr.slice(0, 17)
    const remain = arr.slice(17)
    for (let index = 0; index < remain.length; index++) {
        const element = remain[index];
        remain[index] = element ^ nonce[index % 17]
    }
    if (isPri){
        const signPubKeySecure = remain.slice(7, 7 + nacl.sign.secretKeyLength)
        const start = 7 + nacl.sign.secretKeyLength
        const boxPubKeySecure = remain.slice(start, start + nacl.box.secretKeyLength)
        if (signPubKeySecure.length != nacl.sign.secretKeyLength || boxPubKeySecure.length != nacl.box.secretKeyLength) {
            return [null, null]
        }
    
        return [signPubKeySecure, boxPubKeySecure]
    } else {
        const signPubKeySecure = remain.slice(7, 7 + nacl.sign.publicKeyLength)
        const start = 7 + nacl.sign.publicKeyLength
        const boxPubKeySecure = remain.slice(start, start + nacl.box.publicKeyLength)
        if (signPubKeySecure.length != nacl.sign.publicKeyLength || boxPubKeySecure.length != nacl.box.publicKeyLength) {
            return [null, null]
        }
    
        return [signPubKeySecure, boxPubKeySecure]
    }

}

export const decodeSecrets = (): [nacl.BoxKeyPair, nacl.SignKeyPair, string] => {
    // 当前会话的公钥藏在会话Id中，私钥藏在 ck 中
    let sessionId = document.cookie.split(';').find(c => c.trim().startsWith('sid='))?.split('=')[1] ?? ''
    let clientKey = document.cookie.split(';').find(c => c.trim().startsWith('cid='))?.split('=')[1] ?? ''
    const [signPubKey, boxPubKey] = decodeSecureString(sessionId, false)
    const [singPriKey, boxPriKey] = decodeSecureString(clientKey, true)
    if (!signPubKey || !boxPubKey || !singPriKey || !boxPriKey) {
        // 需要重新生成
        const boxKeyPair = nacl.box.keyPair()
        const signKeyPair = nacl.sign.keyPair()
        sessionId = encodeSecureString(boxKeyPair.publicKey, signKeyPair.publicKey)
        clientKey = encodeSecureString(boxKeyPair.secretKey, signKeyPair.secretKey)
        document.cookie = `sid=${sessionId};path=/;samesite=lax`
        document.cookie = `cid=${clientKey};path=/;samesite=lax`
        log.debug(`【decodeSecrets】new keypairs `, boxKeyPair, signKeyPair)
        return [boxKeyPair, signKeyPair, sessionId]
    } else {
        const boxKeyPair = { publicKey: boxPubKey, secretKey: boxPriKey }
        const signKeyPair = { publicKey: signPubKey, secretKey: singPriKey }
        log.debug(`【decodeSecrets】decode from cookie `, sessionId, clientKey, boxKeyPair, signKeyPair)
        return [boxKeyPair, signKeyPair, sessionId]
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
    log.debug(`【stringifyObj】strObj is`,obj, strObj)
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