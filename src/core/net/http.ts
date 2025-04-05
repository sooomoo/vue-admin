/* eslint-disable @typescript-eslint/no-explicit-any */
import axios, { type AxiosRequestConfig } from 'axios';
import log from 'loglevel';
import {
    decodeSecrets,
    generateUUID,
    getPlatform,
    signData,
    verifyDataSign,
    decryptData,
    encryptData,
    isCryptoEnabled,
    stringifyObj,
    type KeyPair
} from './secure';

const signHeaderTimestamp = "x-timestamp";
const signHeaderNonce = "x-nonce";
const signHeaderSignature = "x-signature";
const signHeaderPlatform = "x-platform";
const signHeaderSession = "x-session";
const contentTypeEncrypted = "application/x-encrypted;charset=utf-8"

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

const encryptRequestBodyIfNeeded = (kp: KeyPair, data: any): any => {
    if (!data) {
        return data
    }
    const reqData = JSON.stringify(data)
    if (isCryptoEnabled()) {
        return encryptData(kp, reqData)
    }
    return reqData
}
const appendTokenToHeader = (headers: Record<string, string>) => {
    const token = getToken()
    if (token) {
        headers['Authorization'] = `Bearer ${token}`
    }
}
const appendContentTypeEncryptedIfNeeded = (headers: Record<string, string>) => {
    if (isCryptoEnabled()) {
        headers['Content-Type'] = contentTypeEncrypted
    }
}

// get 请求不需要加密，因为没有请求体；只需要做签名即可
export const doGet = async  <T = any>(path: string, query?: Record<string, any>): Promise<T | null> => {
    const strQuery = query ? stringifyObj(query) : ""
    const tag = `【GET: ${path}?${strQuery}】`
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
            "query": strQuery,
        })
        const reqSignature = signData(signKeyPair, str)
        log.debug(`${tag} request BEGIN........`)
        log.debug(`${tag} request data to sign: `, str)
        log.debug(`${tag} request sign keypair: `, signKeyPair)
        log.debug(`${tag} request signature: `, reqSignature)
        const headers: Record<string, string> = {
            [signHeaderPlatform]: platform,
            [signHeaderSession]: sessionId,
            [signHeaderTimestamp]: timestamp,
            [signHeaderNonce]: nonce,
            [signHeaderSignature]: reqSignature,
        }
        appendTokenToHeader(headers)

        log.debug(`${tag} request header: `, headers)
        log.debug(`${tag} request END........`)

        const resp = await httpInstance.get<String>(path, {
            params: query,
            headers: headers,
            responseType: 'text',
        } as AxiosRequestConfig<any>)
        log.debug(`${tag} response BEGIN........`)
        log.debug(`${tag} response: `, resp)
        if (resp.status != 200 || typeof (resp.data) !== 'string') {
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
            "query": strQuery,
            "body": resp.data,
        })
        log.debug(`${tag} response sign header: `, { respTimestamp, respNonce, respSignature })
        log.debug(`${tag} response data to sign: `, respStr)
        if (!verifyDataSign(respStr, respSignature)) {
            log.debug(`${tag} response sign verify: FAIL`)
            return null
        }

        log.debug(`${tag} response sign verify: PASS`)
        let respData = resp.data
        if (isCryptoEnabled() && resp.headers['Content-Type'] === contentTypeEncrypted) {
            // 解密
            log.debug(`${tag} response <decrypt> BEFORE: `, resp.data)
            respData = decryptData(boxKeyPair, resp.data)
            log.debug(`${tag} response <decrypt> AFTER: `, respData)
        }
        log.debug(`${tag} response <JSON.parse> BEFORE: `, respData)
        const val = JSON.parse(respData)
        log.debug(`${tag} response <JSON.parse> AFTER: `, val)
        return val
    } catch (error) {
        log.error(`【${path}【FAILED】 error is:`, error)
    } finally {
        log.debug(`${tag} response END........`)
    }
    return null
}

// post 请求需要加密，因为有请求体；同时，还需要做签名
export const doPost = async  <T = any>(path: string, data?: Record<string, any>, query?: Record<string, any>): Promise<T | null> => {
    const strQuery = query ? stringifyObj(query) : ""
    const tag = `【POST: ${path}?${strQuery}】`
    try {
        const [boxKeyPair, signKeyPair, sessionId] = decodeSecrets()
        // 加密请求体
        const reqData = encryptRequestBodyIfNeeded(boxKeyPair, data)
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
            "query": strQuery,
            "body": reqData,
        })

        const reqSignature = signData(signKeyPair, str)
        log.debug(`${tag} request BEGIN........`)
        log.debug(`${tag} request data: `, reqData)
        log.debug(`${tag} request data to sign: `, str)
        log.debug(`${tag} request sign keypair: `, signKeyPair)
        log.debug(`${tag} request signature: `, reqSignature)
        const headers: Record<string, string> = {
            [signHeaderPlatform]: platform,
            [signHeaderSession]: sessionId,
            [signHeaderTimestamp]: timestamp,
            [signHeaderNonce]: nonce,
            [signHeaderSignature]: reqSignature,
        }
        appendTokenToHeader(headers)
        appendContentTypeEncryptedIfNeeded(headers)

        log.debug(`${tag} request header: `, headers)
        log.debug(`${tag} request END........`)

        const resp = await httpInstance.post<String>(path, reqData, {
            params: query,
            headers: headers,
            responseType: 'text',
        } as AxiosRequestConfig<any>)
        log.debug(`${tag} response BEGIN........`)
        log.debug(`${tag} response: `, resp)
        if (resp.status != 200 || typeof (resp.data) !== 'string') {
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
            "query": strQuery,
            "body": resp.data,
        })
        log.debug(`${tag} response sign header: `, { respTimestamp, respNonce, respSignature })
        log.debug(`${tag} response data to sign: `, respStr)
        if (!verifyDataSign(respStr, respSignature)) {
            log.debug(`${tag} response sign verify: FAIL`)
            return null
        }

        log.debug(`${tag} response sign verify: PASS`)
        let respData = resp.data
        if (isCryptoEnabled() && resp.headers['content-type'] == contentTypeEncrypted) {
            // 解密
            log.debug(`${tag} response <decrypt> BEFORE: `, resp.data)
            respData = decryptData(boxKeyPair, resp.data)
            log.debug(`${tag} response <decrypt> AFTER: `, respData)
        }
        log.debug(`${tag} response <JSON.parse> BEFORE: `, respData)
        const val = JSON.parse(respData)
        log.debug(`${tag} response <JSON.parse> AFTER: `, val)
        return val
    } catch (error) {
        log.error(`【${path}【FAILED】 error is:`, error)
    } finally {
        log.debug(`${tag} response END........`)
    }
    return null
}
