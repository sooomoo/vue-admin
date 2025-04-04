/* eslint-disable @typescript-eslint/no-explicit-any */
import axios, { type AxiosRequestConfig } from 'axios';
import log from 'loglevel';
import {
    decodeSecrets,
    generateUUID,
    getPlatform,
    stringifyObj,
    generateSignature,
    verifySignature,
    decryptData,
    encryptData,
    isCryptoEnabled,
    base64Decode
} from './secure';

const signHeaderTimestamp = "X-Timestamp";
const signHeaderNonce = "X-Nonce";
const signHeaderSignature = "X-Signature";
const signHeaderPlatform = "X-Platform";
const signHeaderSession = "X-Session";
const contentTypeEncrypted = "application/x-encrypted"

export interface ResponseDto<T> {
    code: string
    msg: string
    data: T
}

const getToken = () => {
    return document.cookie.split(';').find(c => c.trim().startsWith('token='))?.split('=')[1]
}

// 创建一个实例并设置 baseURL
const httpInstance = axios.create({
    baseURL: import.meta.env.VITE_API_BASE_URL,
    timeout: 15000,
    withCredentials: false,
    validateStatus: (_e: number) => true,
});



// get 请求不需要加密，因为没有请求体；只需要做签名即可
export const doGet = async  <T = any>(path: string, query?: Record<string, any>): Promise<T | null> => {
    try {
        const [boxKeyPair, signKeyPair, sessionId] = decodeSecrets()
        // 需要对请求进行签名
        const nonce = generateUUID()
        const timestamp = (Date.now() / 1000).toFixed()
        const platform = getPlatform()
        const str = stringifyObj({
            "session": sessionId,
            "nonce": nonce,
            "timestamp": timestamp,
            "platform": platform,
            "method": "GET",
            "path": path,
            "query": query ? stringifyObj(query) : "",
        })
        const reqSignature = generateSignature(signKeyPair, str)
        const headers: Record<string, string> = {
            [signHeaderPlatform]: platform,
            [signHeaderSession]: sessionId,
            [signHeaderTimestamp]: timestamp,
            [signHeaderNonce]: nonce,
            [signHeaderSignature]: reqSignature,
        }
        const token = getToken()
        if (token) {
            headers['Authorization'] = `Bearer ${token}`
        }

        const resp = await httpInstance.get<String>(path, {
            params: query,
            headers: headers,
        } as AxiosRequestConfig<any>)
        if (resp.status != 200 || typeof (resp.data) !== 'string') {
            log.debug(`【${path}】<GET> response fail detail is:`, resp)
            return null
        }

        const respTimestamp = resp.headers[signHeaderTimestamp] as string | undefined ?? ''
        const respNonce = resp.headers[signHeaderNonce] as string | undefined ?? ''
        const respSignature = resp.headers[signHeaderSignature] as string | undefined ?? ''
        const respStr = stringifyObj({
            "session": sessionId,
            "nonce": respNonce,
            "platform": platform,
            "timestamp": respTimestamp,
            "method": "GET",
            "path": path,
            "query": query ? stringifyObj(query) : "",
            "body": resp.data,
        })
        if (verifySignature(respStr, respSignature)) {
            let respData = resp.data
            if (isCryptoEnabled() && resp.headers['Content-Type'] === contentTypeEncrypted) {
                // 解密
                respData = decryptData(boxKeyPair, resp.data)
            }
            const val = JSON.parse(respData)
            log.debug(`【${path}】<GET> response data is`, respData, val)
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
        const [boxKeyPair, signKeyPair, sessionId] = decodeSecrets()
        // 加密请求体
        let reqData = ''
        if (data) {
            reqData = JSON.stringify(data)
            if (isCryptoEnabled()) {
                reqData = encryptData(boxKeyPair, reqData)
            }
        }
        // 需要对请求进行签名
        const nonce = generateUUID()
        const timestamp = (Date.now() / 1000).toFixed()
        const platform = getPlatform()
        const str = stringifyObj({
            "session": sessionId,
            "nonce": nonce,
            "timestamp": timestamp,
            "platform": platform,
            "method": "POST",
            "path": path,
            "query": query ? stringifyObj(query) : "",
            "body": reqData,
        })

        const reqSignature = generateSignature(signKeyPair, "12345")
        log.debug(`【${path}】<POST> request data is`, reqData, str, base64Decode(reqSignature))
        const headers: Record<string, string> = {
            [signHeaderPlatform]: platform,
            [signHeaderSession]: sessionId,
            [signHeaderTimestamp]: timestamp,
            [signHeaderNonce]: nonce,
            [signHeaderSignature]: reqSignature,
        }
        const token = getToken()
        if (token) {
            headers['Authorization'] = `Bearer ${token}`
        }
        if (isCryptoEnabled()) {
            headers['Content-Type'] = contentTypeEncrypted
        }
        const resp = await httpInstance.post<String>(path, reqData, {
            params: query,
            headers: headers,
        } as AxiosRequestConfig<any>)
        if (resp.status != 200 || typeof (resp.data) !== 'string') {
            log.debug(`【${path}】<GET> response fail detail is:`, resp)
            return null
        }

        const respTimestamp = resp.headers[signHeaderTimestamp] as string | undefined ?? ''
        const respNonce = resp.headers[signHeaderNonce] as string | undefined ?? ''
        const respSignature = resp.headers[signHeaderSignature] as string | undefined ?? ''
        const respStr = stringifyObj({
            "session": sessionId,
            "nonce": respNonce,
            "platform": platform,
            "timestamp": respTimestamp,
            "method": "POST",
            "path": path,
            "query": query ? stringifyObj(query) : "",
            "body": resp.data,
        })
        if (verifySignature(respStr, respSignature)) {
            let respData = resp.data
            if (isCryptoEnabled() && resp.headers['Content-Type'] === contentTypeEncrypted) {
                // 解密
                respData = decryptData(boxKeyPair, resp.data)
            }
            const val = JSON.parse(respData)
            log.debug(`【${path}】<GET> response data is`, respData, val)
        } else {
            log.debug(`【${path}】<POST> response data signature verify fail`)
        }
    } catch (error) {
        log.error(`【${path}<POST> fail detail is:`, error)
    }
    return null
}
