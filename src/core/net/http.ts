import axios from 'axios';
import * as base64 from '@juanelas/base64'
import nacl from 'tweetnacl';
import log from 'loglevel';

const decoder = new TextEncoder()

const signHeaderTimestamp = "x-timestamp";
const signHeaderNonce = "x-nonce";
const signHeaderSignature = "x-signature";
const signHeaderPlatform = "x-platform";
const contentTypeEncrypted = "application/x-encrypted;charset=utf-8"

export interface ResponseDto<T> {
    code: string
    msg: string
    data: T
}

export const getClientId = (): string=>{
    const cookie = document.cookie
    // 获取客户端唯一Id
    let clientId = cookie.split(';').find(c => c.trim().startsWith('ci='))?.split('=')[1]
    if (!clientId) {
        clientId = crypto.randomUUID().replace(/-/g, '')
        document.cookie = `ci=${clientId};path=/;samesite=lax`
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
        const code = nonce[i%24]
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
        const code = nonce[i%24]
        joined[i] = char ^ code
    }
    let start = 0
    const publicKey = joined.slice(start, nacl.box.publicKeyLength)
    start += nacl.box.publicKeyLength
    const secretKey = joined.slice(start, start+nacl.box.secretKeyLength)
    start += nacl.box.secretKeyLength
    const signPublicKey = joined.slice(start, start+nacl.sign.publicKeyLength)
    start += nacl.sign.publicKeyLength
    const signSecretKey = joined.slice(start, start+nacl.sign.secretKeyLength)
    return [{ publicKey, secretKey },{ publicKey: signPublicKey, secretKey: signSecretKey }]
}

export const decodeSecrets = ():[nacl.BoxKeyPair , nacl.SignKeyPair]=>{
    const cookie = document.cookie
    // 获取客户端公私钥
    let clientKey = cookie.split(';').find(c => c.trim().startsWith('ck='))?.split('=')[1]
    let keyPair: nacl.BoxKeyPair | null = null
    let signKeyPair: nacl.SignKeyPair | null = null
    if (clientKey) {
        [keyPair, signKeyPair] = decodeKeyPair(clientKey) 
    }
    if (!keyPair || !signKeyPair) {
        keyPair = nacl.box.keyPair()
        signKeyPair = nacl.sign.keyPair()
        clientKey = obscureKeyPair(keyPair, signKeyPair)
        document.cookie = `ck=${clientKey};path=/;samesite=lax`
    }
    return [keyPair, signKeyPair]
}

const negotiateIfNeeded = async () => { 
    // 获取客户端唯一Id
    const clientId = getClientId()
    const [keyPair, signKeyPair] = decodeSecrets() 

    const publicKey = base64.encode(keyPair.publicKey)
    const secretKey = base64.encode(keyPair.secretKey)
    return { publicKey, secretKey }
}

// get 请求不需要加密，因为没有请求体；只需要做签名即可
export const doGet = async  <T = any>(path: string, query?: Record<string, any>): Promise<T | null> => {
    try {
        
        // 需要对请求进行签名
        const nonce = nacl.randomBytes(24)
        const nonceBase64 = base64.encode(nonce)
        const timestamp = Date.now().toString()
        const reqSignature = ""

        const resp = await axios.get<String>(path, {
            baseURL: import.meta.env.VITE_API_BASE_URL,
            params: query,
            headers: {
                [signHeaderPlatform]: "web",
                [signHeaderTimestamp]: timestamp,
                [signHeaderNonce]: nonceBase64,
                [signHeaderSignature]: reqSignature,
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
        const signArr = decoder.encode(signData)
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
export const doPost = async  <T = any>(path: string, data?: Record<string, any>): Promise<T | null> => {
    try {
        // 需要对请求进行加密
        const nonce = nacl.randomBytes(24)
        const nonceBase64 = base64.encode(nonce)
        const timestamp = Date.now().toString()
        const reqSignature = ""

        const resp = await axios.post<String>(path, data, {
            baseURL: import.meta.env.VITE_API_BASE_URL,
            validateStatus: (_e: any) => true,
            headers: {
                [signHeaderPlatform]: "web",
                [signHeaderTimestamp]: timestamp,
                [signHeaderNonce]: nonceBase64,
                [signHeaderSignature]: reqSignature,
                'Content-Type': contentTypeEncrypted,
            },
        })
        if (resp.status != 200 || typeof (resp.data) !== 'string') {
            log.debug(`【${path}】<POST> response fail detail is:`, resp)
            return null
        }

        const respTimestamp = resp.headers[signHeaderTimestamp] as string | undefined ?? ''
        const respNonce = resp.headers[signHeaderNonce] as string | undefined ?? ''
        const respSignature = resp.headers[signHeaderSignature] as string | undefined ?? ''
        const signArr = decoder.encode([respTimestamp, respNonce, resp.data].join(':'))
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

// 协商密钥，并保存至 session 中
const negotiateSecretKey = async () => {

}
