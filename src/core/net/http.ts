import axios from 'axios';
import * as base64 from '@juanelas/base64'
import nacl from 'tweetnacl';

const decoder = new TextEncoder()

const signHeaderTimestamp = "x-timestamp";
const signHeaderNonce = "x-nonce";
const signHeaderSignature = "x-signature";
const signHeaderPlatform = "x-platform";
const contentTypeEncrypted = "application/x-encrypted;charset=utf-8"
let globalBaseURL: string = ''
let globalApiPubKey: string = ''
let globalApiPubKeyArray: Uint8Array = new Uint8Array()

export const doInit = (baseURL: string, apiPubKey: string) => {
    globalBaseURL = baseURL
    globalApiPubKey = apiPubKey
    globalApiPubKeyArray = base64.decode(globalApiPubKey) 
}

export const doGet = async  <T = any>(path: string, query?: Record<string, any>): Promise<T | null> => {
    try {
        const resp = await axios.get<String>(path, {
            baseURL: globalBaseURL,
            params: query,
            validateStatus: (_e: any) => true,
            responseType: 'text',
        })
        if (resp.status == 200 && typeof (resp.data) === 'string') {
            const timestamp = resp.headers[signHeaderTimestamp] as string | undefined ?? ''
            const nonce = resp.headers[signHeaderNonce] as string | undefined ?? ''
            const signature = resp.headers[signHeaderSignature] as string | undefined ?? ''
            const signatureArr = base64.decode(signature)

            const tmpArr = [timestamp, nonce, resp.data]
            const signData = tmpArr.join(':')
            const signArr = decoder.encode(signData)
            const verifyRes = nacl.sign.detached.verify(signArr, signatureArr, globalApiPubKeyArray)
            if (verifyRes) {
                return JSON.parse(resp.data)
            }
        }
    } catch (error) {
        // do nothing
    }
    return null
}

export const doPost = async  <T = any>(path: string, data?: Record<string, any>): Promise<T | null> => {
    try {
        const resp = await axios.post<String>(path, data, {
            baseURL: globalBaseURL,
            validateStatus: (_e: any) => true,
            headers: {
                'Content-Type': 'application/json',
            },
            responseType: 'text',
        })
        if (resp.status == 200 && typeof (resp.data) === 'string') {
            const timestamp = resp.headers[signHeaderTimestamp] as string | undefined ?? ''
            const nonce = resp.headers[signHeaderNonce] as string | undefined ?? ''
            const signature = resp.headers[signHeaderSignature] as string | undefined ?? ''
            const signatureArr = base64.decode(signature)

            const tmpArr = [timestamp, nonce, resp.data]
            const signData = tmpArr.join(':')
            const signArr = decoder.encode(signData)
            const verifyRes = nacl.sign.detached.verify(signArr, signatureArr, globalApiPubKeyArray)
            if (verifyRes) {
                return JSON.parse(resp.data)
            }
        }
    } catch (error) {
        console.log(error)
        // do nothing
    }
    return null
}

export interface ResponseDto<T> {
    code: string
    msg: string
    data: T
}