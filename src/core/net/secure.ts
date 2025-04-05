/* eslint-disable @typescript-eslint/no-explicit-any */

import * as base64 from '@juanelas/base64'
import log from 'loglevel';
import { gcm } from '@noble/ciphers/aes';
import { bytesToHex, bytesToUtf8, equalBytes, hexToBytes, utf8ToBytes } from '@noble/ciphers/utils';
import { randomBytes } from '@noble/ciphers/webcrypto';
import { x25519, ed25519 } from '@noble/curves/ed25519';

export interface KeyPair {
    publicKey: Uint8Array
    privateKey: Uint8Array
}

// 生成一个新的加密密钥对
export const newBoxKeyPair = (): KeyPair => {
    const privateKey = x25519.utils.randomPrivateKey()
    const publicKey = x25519.getPublicKey(privateKey)
    return { publicKey, privateKey }
}

// 此处的公钥与私钥都是32位
export const newBoxKeyPairFromArray = (pub: Uint8Array, pri: Uint8Array): KeyPair => {
    return { publicKey: pub, privateKey: pri }
}

// 生成一个新的签名密钥对；如果私钥是64位，那么其后32位是公钥
export const newSignKeyPair = (): KeyPair => {
    const privateKey = ed25519.utils.randomPrivateKey()
    const publicKey = ed25519.getPublicKey(privateKey)
    return { publicKey, privateKey }
}

// 此处的公钥与私钥都是32位
export const newSignKeyPairFromArray = (pub: Uint8Array, pri: Uint8Array): KeyPair => {
    return { publicKey: pub, privateKey: pri }
}

export const generateUUID = () => {
    return crypto.randomUUID().replace(/-/g, '')
}

export const base64Encode = (input: ArrayBufferLike | base64.TypedArray | Buffer | string): string => {
    return base64.encode(input, true, false)
}

export const base64Decode = (input: string): Uint8Array => {
    return base64.decode(input)
}

export const encodeSecureString = (signKey: Uint8Array, boxKey: Uint8Array): string => {
    const randomBts = randomBytes(24)
    const arr = [...randomBts, ...signKey, ...boxKey]
    const all = new Uint8Array(arr)
    for (let index = 17; index < all.length; index++) {
        const element = all[index];
        all[index] = element ^ all[index % 17]
    }
    return base64Encode(all)
}

export const decodeSecureString = (str: string): {
    sign: Uint8Array | null
    box: Uint8Array | null
} => {
    if (!str || str.length <= 88) {
        return { sign: null, box: null }
    }
    const all = base64Decode(str)
    if (all.length != 88) {
        return { sign: null, box: null }
    }
    for (let index = 17; index < all.length; index++) {
        const element = all[index];
        all[index] = element ^ all[index % 17]
    }
    const signPubKeySecure = all.slice(24, 56)
    const boxPubKeySecure = all.slice(56)
    if (signPubKeySecure.length != 32 || boxPubKeySecure.length != 32) {
        return { sign: null, box: null }
    }

    return { sign: signPubKeySecure, box: boxPubKeySecure }
}

export const decodeSecrets = (): [KeyPair, KeyPair, string] => {
    // 当前会话的公钥藏在会话Id中，私钥藏在 ck 中
    let sessionId = document.cookie.split(';').find(c => c.trim().startsWith('sid='))?.split('=')[1] ?? ''
    let clientKey = document.cookie.split(';').find(c => c.trim().startsWith('cid='))?.split('=')[1] ?? ''
    const pubKeys = decodeSecureString(sessionId)
    const priKeys = decodeSecureString(clientKey)
    if (!pubKeys.box || !pubKeys.sign || !priKeys.box || !priKeys.sign) {
        // 需要重新生成
        const boxKeyPair = newBoxKeyPair()
        const signKeyPair = newSignKeyPair()
        sessionId = encodeSecureString(signKeyPair.publicKey, boxKeyPair.publicKey)
        clientKey = encodeSecureString(signKeyPair.privateKey, boxKeyPair.privateKey)
        document.cookie = `sid=${sessionId};path=/;samesite=lax`
        document.cookie = `cid=${clientKey};path=/;samesite=lax`
        log.debug(`【decodeSecrets】new sign keypair `, signKeyPair)
        log.debug(`【decodeSecrets】new box keypair `, boxKeyPair)

        const pubKeys1 = decodeSecureString(sessionId)
        const priKeys1 = decodeSecureString(clientKey)
        log.debug('xxxxxx sign', pubKeys1.sign, priKeys1.sign)
        log.debug('xxxxxx box', pubKeys1.box, priKeys1.box)
        log.debug('sign pub key eq', equalBytes(pubKeys1.sign!, signKeyPair.publicKey))
        log.debug('box pub key eq', equalBytes(pubKeys1.box!, boxKeyPair.publicKey))
        log.debug('sign pri key eq', equalBytes(priKeys1.sign!, signKeyPair.privateKey))
        log.debug('box pri key eq', equalBytes(priKeys1.box!, boxKeyPair.privateKey))

        return [boxKeyPair, signKeyPair, sessionId]
    } else {
        const boxKeyPair = newBoxKeyPairFromArray(pubKeys.box, priKeys.box)
        const signKeyPair = newSignKeyPairFromArray(pubKeys.sign, priKeys.sign)
        log.debug(`【decodeSecrets】decode from cookie `, sessionId, clientKey, signKeyPair, boxKeyPair)
        return [boxKeyPair, signKeyPair, sessionId]
    }
}

// 加密数据
export const encryptData = (key: KeyPair, data: string): string => {
    const serverExPubKey = base64Decode(import.meta.env.VITE_SERVER_EX_PUB_KEY)
    const shareKey = x25519.getSharedSecret(key.privateKey, serverExPubKey)
    const rawData = utf8ToBytes(data)
    const nonce = randomBytes(12)
    const aes = gcm(shareKey, nonce)
    const res = aes.encrypt(rawData)
    log.debug(`【encryptData】secret is`, shareKey)
    log.debug(`【encryptData】nonce is`, nonce)
    log.debug(`【encryptData】result is`, res)
    return base64Encode(new Uint8Array([...nonce, ...res]))
}

// 解密数据
export const decryptData = (key: KeyPair, data: string): string => {
    const serverExPubKey = base64Decode(import.meta.env.VITE_SERVER_EX_PUB_KEY)
    const shareKey = x25519.getSharedSecret(key.privateKey, serverExPubKey)
    const rawData = base64Decode(data)
    const nonce = rawData.slice(0, 12)
    const body = rawData.slice(12)
    log.debug(`【decryptData】secret is`, shareKey)
    log.debug(`【decryptData】rawData is`, rawData)
    log.debug(`【decryptData】nonce is`, nonce)
    log.debug(`【decryptData】body is`, body)
    const aes = gcm(shareKey, nonce)
    const decrypted = aes.decrypt(body)
    if (!decrypted) {
        return ""
    }
    return bytesToUtf8(decrypted)
}

export const stringifyObj = (obj: any) => {
    const keys = Object.keys(obj).sort()
    const strObj = keys.map(k => `${k}=${obj[k]}`).join('&')
    log.debug(`【stringifyObj】strObj is`, obj, strObj)
    return strObj
}

// 给对象按照指定的规则签名
export const signData = (kp: KeyPair, data: string): string => {
    const rawData = utf8ToBytes(data)
    const out = ed25519.sign(rawData, kp.privateKey)
    return base64Encode(out)
}

// 验证对象的签名是否正确
export const verifyDataSign = (data: string, signature: string) => {
    const rawData = utf8ToBytes(data)
    const sigData = base64Decode(signature)
    const serverSignPubKey = base64Decode(import.meta.env.VITE_SERVER_SIGN_PUB_KEY)
    return ed25519.verify(sigData, rawData, serverSignPubKey)
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