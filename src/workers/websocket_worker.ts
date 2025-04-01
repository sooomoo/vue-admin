/// <reference lib="webworker" />

import { WebSocketClientBase } from "@/core/net/websocket_client";
import { type IWebSocketCmd, WebSocketCmdConnect } from "./websocket_cmd";
import { ExponentialRetryStrategy } from "@/core/retry_strategy";
import log from "loglevel";

const ports: MessagePort[] = [];
let websocket: WebSocketClient | undefined

const scope = self as unknown as SharedWorkerGlobalScope
if (!scope) {
    throw new Error('scope is not SharedWorkerGlobalScope')
}

scope.onconnect = (e: MessageEvent) => {
    const port = e.ports[0]
    ports.push(port)

    port.onmessage = (e: MessageEvent<IWebSocketCmd>) => {
        log.debug(' 收到消息 ', e.data)
        if (e.data.cmd === WebSocketCmdConnect) {
            if (websocket) {
                log.debug('websocket 已连接')
                return
            }

            websocket = new WebSocketClient(e.data.data)
        }
        ports.forEach(p => p.postMessage("i've received your message"))
    }
} 

 class WebSocketClient extends WebSocketClientBase {
    // readonly msgProtocol: MessageProtocol
 
    constructor(url: string) {
        super(url, ['niu-v1'], 'arraybuffer', new ExponentialRetryStrategy(1000, 5))
        // this.msgProtocol = msgProtocol
    }

    onData(data: string | ArrayBuffer): void {
        if (typeof data == 'string') {
            log.debug('text message: ', data)
        } else if (data instanceof ArrayBuffer) {
            // const [msgType, reqId, payload] = this.msgProtocol.decode(new Uint8Array(data))
            // log.debug('binary message: ', msgType, reqId, payload)
        }
    }

    onHeartbeatTick(): void {
        //this.sendMsg(MsgType.ping, new Uint8Array(0));
    }

    onConnected(): void {
        log.debug('connected')
    }
    onWillReconnect(durationMs: number): void {
        log.debug(`reconnect after ${durationMs}ms`)
    }

    // sendMsg(msgType: MsgType, payload: Uint8Array): RequestId {
    //     // const id = RequestId.next();
    //     // const data = this.msgProtocol.encode(msgType, id, payload);
    //     // this.send(data);
    //     // return id;
    // }
}


export enum MsgType {
    ready = 0,
    ping = 1,
    pong = 2,

    bizUserReq = 50,
    bizUserRes = 51,
}

export class RequestId {
    readonly timestamp: number
    readonly seq: number

    constructor(timestamp: number, seq: number) {
        this.timestamp = timestamp
        this.seq = seq
    }

    static origin = Date.UTC(2024, 1) / 1000
    static _lastTimestap = 0;
    static _seq = 0;
    static next(): RequestId {
        const timestamp = Date.now() / 1000 -
            RequestId.origin;
        if (timestamp == RequestId._lastTimestap) {
            // 同一秒内
            RequestId._seq++;
        } else {
            RequestId._seq = 0;
            RequestId._lastTimestap = timestamp;
        }
        return new RequestId(timestamp, RequestId._seq);
    }

    static fromArray(arr: Uint8Array): RequestId {
        return new RequestId((arr[0] << 24) | (arr[1] << 16) | (arr[2] << 8) | arr[3], arr[4]);
    }

    toArray(): Uint8Array {
        const list = new Uint8Array(5)
        list[0] = (this.timestamp & 0xff000000) >> 24;
        list[1] = (this.timestamp & 0x00ff0000) >> 16;
        list[2] = (this.timestamp & 0x0000ff00) >> 8;
        list[3] = this.timestamp & 0x000000ff;
        list[4] = this.seq;
        return list;
    }

    toString(): string {
        return `${this.timestamp}:${this.seq}`;
    }
}

export class MessageProtocol {
    encode(msgType: MsgType, reqId: RequestId, payload: Uint8Array): Uint8Array {
        const list = new Uint8Array(6 + payload.length);
        list[0] = msgType;
        list.set(reqId.toArray(), 1)
        if (payload.length > 0) list.set(payload, 6);
        return list;
    }

    decode(data: Uint8Array): [MsgType, RequestId, Uint8Array] {
        console.assert(data.length >= 6, "must at least have msgtype and request id.");
        return [
            data[0],
            RequestId.fromArray(data.subarray(1, 6)),
            data.length > 6 ? data.subarray(6) : new Uint8Array(0)
        ]
    }
}