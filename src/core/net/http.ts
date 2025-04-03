import axios from 'axios';
import * as base64 from '@juanelas/base64'
import nacl from 'tweetnacl';
import log from 'loglevel';

const encoder = new TextEncoder()
const decoder = new TextDecoder()

const signHeaderTimestamp = "x-timestamp";
const signHeaderNonce = "x-nonce";
const signHeaderSignature = "x-signature";
const signHeaderPlatform = "x-platform";
const signHeaderClientId = "x-client";
const contentTypeEncrypted = "application/x-encrypted;charset=utf-8"

export interface ResponseDto<T> {
    code: string
    msg: string
    data: T
}

const generateUUID = () => {
    return crypto.randomUUID().replace(/-/g, '')
}

export const getClientId = (): string => {
    const cookie = document.cookie
    // 获取客户端唯一Id
    let clientId = cookie.split(';').find(c => c.trim().startsWith('ci='))?.split('=')[1]
    if (!clientId) {
        clientId = generateUUID()
        document.cookie = `ci=${clientId};path=/;samesite=lax`
        log.debug(`【getClientId】new clientId is`, clientId)
    }
    return clientId
}

const obscureKeyPair = (boxKeyPair: nacl.BoxKeyPair, signKeyPair: nacl.SignKeyPair): string => {
    const publicKey = boxKeyPair.publicKey
    const secretKey = boxKeyPair.secretKey
    const signPublicKey = signKeyPair.publicKey
    const signSecretKey = signKeyPair.secretKey
    const nonce = nacl.randomBytes(24)
    const joined = new Uint8Array([...publicKey, ...secretKey, ...signPublicKey, ...signSecretKey])
    for (let i = 0; i < joined.length; i++) {
        const char = joined[i]
        const code = nonce[i % 24]
        joined[i] = char ^ code
    }
    const final = new Uint8Array([...nonce, ...joined])
    return base64.encode(final)
}

const decodeKeyPair = (encoded: string): [nacl.BoxKeyPair | null, nacl.SignKeyPair | null] => {
    const totalLength = 24 + nacl.box.publicKeyLength + nacl.box.secretKeyLength + nacl.sign.publicKeyLength + nacl.sign.secretKeyLength
    if (!encoded || encoded.length < totalLength) {
        return [null, null]
    }
    const decoded = base64.decode(encoded)
    if (decoded.length != totalLength) {
        return [null, null]
    }
    const nonce = decoded.slice(0, 24)
    const joined = decoded.slice(24)
    for (let i = 0; i < joined.length; i++) {
        const char = joined[i]
        const code = nonce[i % 24]
        joined[i] = char ^ code
    }
    let start = 0
    const publicKey = joined.slice(start, nacl.box.publicKeyLength)
    start += nacl.box.publicKeyLength
    const secretKey = joined.slice(start, start + nacl.box.secretKeyLength)
    start += nacl.box.secretKeyLength
    const signPublicKey = joined.slice(start, start + nacl.sign.publicKeyLength)
    start += nacl.sign.publicKeyLength
    const signSecretKey = joined.slice(start, start + nacl.sign.secretKeyLength)
    return [{ publicKey, secretKey }, { publicKey: signPublicKey, secretKey: signSecretKey }]
}

export const decodeSecrets = (): [nacl.BoxKeyPair, nacl.SignKeyPair] => {
    const cookie = document.cookie
    // 获取客户端公私钥
    let clientKey = cookie.split(';').find(c => c.trim().startsWith('ck='))?.split('=')[1]
    let keyPair: nacl.BoxKeyPair | null = null
    let signKeyPair: nacl.SignKeyPair | null = null
    if (clientKey) {
        [keyPair, signKeyPair] = decodeKeyPair(clientKey)
        log.debug(`【decodeSecrets】decode from cookie `, clientKey)
    }
    if (!keyPair || !signKeyPair) {
        keyPair = nacl.box.keyPair()
        signKeyPair = nacl.sign.keyPair()
        clientKey = obscureKeyPair(keyPair, signKeyPair)
        document.cookie = `ck=${clientKey};path=/;samesite=lax`
        log.debug(`【decodeSecrets】new keypairs `, clientKey)
    }
    return [keyPair, signKeyPair]
}

// 协商以后得到一个 keyid，以后的通信都传输这个 key id，这样服务器就知道当前请求使用的哪个 key 来解密数据
const negotiateIfNeeded = async () => {
    // 获取客户端唯一Id
    const clientId = getClientId()
    const [keyPair, signKeyPair] = decodeSecrets()

    const serverSignPubKey = base64.decode(import.meta.env.VITE_SERVER_SIGN_PUB_KEY)
    const serverExPubKey = base64.decode(import.meta.env.VITE_SERVER_EX_PUB_KEY)

    // 加密
    const res = nacl.box(new Uint8Array(), new Uint8Array(), serverExPubKey, keyPair.secretKey)

    // 解密
    const decrypted = nacl.box.open(res, new Uint8Array(), serverExPubKey, keyPair.publicKey)

    const publicKey = base64.encode(keyPair.publicKey)
    const secretKey = base64.encode(keyPair.secretKey)
    return { publicKey, secretKey }
}

const encryptData = (kp: nacl.BoxKeyPair, data: string): string => {
    const rawData = encoder.encode(data)
    const serverExPubKey = base64.decode(import.meta.env.VITE_SERVER_EX_PUB_KEY)
    const res = nacl.box(rawData, new Uint8Array(), serverExPubKey, kp.secretKey)
    return base64.encode(res)
}

const decryptData = (kp: nacl.BoxKeyPair, data: string): string => {
    const rawData = base64.decode(data)
    const serverExPubKey = base64.decode(import.meta.env.VITE_SERVER_EX_PUB_KEY)
    const decrypted = nacl.box.open(rawData, new Uint8Array(), serverExPubKey, kp.secretKey)
    if (!decrypted) {
        return ""
    }
    return base64.encode(decrypted)
}

const stringifyObj = (obj: any) => {
    const keys = Object.keys(obj).sort()
    return keys.map(k => `${k}=${obj[k]}`).join('&')
}

const generateSignature = (kp: nacl.SignKeyPair, data: string): string => {
    // Signs the message using the secret key and returns a signature.
    const arr = nacl.sign.detached(encoder.encode(data), kp.secretKey)
    return base64.encode(arr)
}

const verifySignature = (data: string, signature: string) => {
    const signData = encoder.encode(data)
    const serverSignPubKey = base64.decode(import.meta.env.VITE_SERVER_SIGN_PUB_KEY)
    // Verifies the signature for the message and returns true if verification succeeded or false if it failed.
    return nacl.sign.detached.verify(signData, base64.decode(signature), serverSignPubKey)
}

// get 请求不需要加密，因为没有请求体；只需要做签名即可
export const doGet = async  <T = any>(path: string, query?: Record<string, any>): Promise<T | null> => {
    try {
        const [, signKeyPair] = decodeSecrets()
        // 需要对请求进行签名
        const nonce = generateUUID()
        const timestamp = (Date.now() / 1000).toString()
        const clientId = getClientId()
        const str = stringifyObj({
            "clientId": clientId,
            "nonce": nonce,
            "timestamp": timestamp,
            "platform": "web",
            "method": "GET",
            "path": path,
            "query": query ? stringifyObj(query) : "",
        })
        const reqSignature = generateSignature(signKeyPair, str)

        const resp = await axios.get<String>(path, {
            baseURL: import.meta.env.VITE_API_BASE_URL,
            params: query,
            headers: {
                signHeaderPlatform: "web",
                signHeaderTimestamp: timestamp,
                signHeaderNonce: nonce,
                signHeaderSignature: reqSignature,
                signHeaderClientId: clientId,
            },
            validateStatus: (_e: any) => true,
        })
        if (resp.status != 200 || typeof (resp.data) !== 'string') {
            log.debug(`【${path}】<GET> response fail detail is:`, resp)
            return null
        }

        const respTimestamp = resp.headers[signHeaderTimestamp] as string | undefined ?? ''
        const respNonce = resp.headers[signHeaderNonce] as string | undefined ?? ''
        const respSignature = resp.headers[signHeaderSignature] as string | undefined ?? ''
        const tmpArr = [respTimestamp, respNonce, resp.data]
        const signData = tmpArr.join(':')
        const signArr = encoder.encode(signData)
        const pubKeyArray = base64.decode(import.meta.env.VITE_SERVER_SIGN_PUB_KEY)
        if (nacl.sign.detached.verify(signArr, base64.decode(respSignature), pubKeyArray)) {
            const val = JSON.parse(resp.data)
            log.debug(`【${path}】<GET> response data is`, resp.data)
            return val
        } else {
            log.debug(`【${path}】<GET> response data signature verify fail`)
        }
    } catch (error) {
        log.error(`【${path}<GET> fail detail is:`, error)
    }
    return null
}

// post 请求需要加密，因为有请求体；同时，还需要做签名
export const doPost = async  <T = any>(path: string, data?: Record<string, any>, query?: Record<string, any>): Promise<T | null> => {
    try {
        // 需要对请求进行加密
        const [, signKeyPair] = decodeSecrets()
        // 需要对请求进行签名
        const nonce = generateUUID()
        const timestamp = (Date.now() / 1000).toString()
        const clientId = getClientId()
        const str = stringifyObj({
            "clientId": clientId,
            "nonce": nonce,
            "timestamp": timestamp,
            "platform": "web",
            "method": "GET",
            "path": path,
            "query": query ? stringifyObj(query) : "",
        })
        const reqSignature = generateSignature(signKeyPair, str)


        const resp = await axios.post<String>(path, data, {
            baseURL: import.meta.env.VITE_API_BASE_URL,
            validateStatus: (_e: any) => true,
            params: query,
            headers: {
                signHeaderPlatform: "web",
                signHeaderTimestamp: timestamp,
                signHeaderNonce: nonce,
                signHeaderSignature: reqSignature,
                signHeaderClientId: clientId,
            },
        })
        if (resp.status != 200 || typeof (resp.data) !== 'string') {
            log.debug(`【${path}】<POST> response fail detail is:`, resp)
            return null
        }

        const respTimestamp = resp.headers[signHeaderTimestamp] as string | undefined ?? ''
        const respNonce = resp.headers[signHeaderNonce] as string | undefined ?? ''
        const respSignature = resp.headers[signHeaderSignature] as string | undefined ?? ''
        const signArr = encoder.encode([respTimestamp, respNonce, resp.data].join(':'))
        const pubKeyArray = base64.decode(import.meta.env.VITE_SERVER_SIGN_PUB_KEY)
        if (nacl.sign.detached.verify(signArr, base64.decode(respSignature), pubKeyArray)) {
            const val = JSON.parse(resp.data)
            log.debug(`【${path}】<POST> response data is`, resp.data)
            return val
        } else {
            log.debug(`【${path}】<POST> response data signature verify fail`)
        }
    } catch (error) {
        log.error(`【${path}<POST> fail detail is:`, error)
    }
    return null
}
