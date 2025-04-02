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
