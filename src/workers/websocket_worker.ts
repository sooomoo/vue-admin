/// <reference lib="webworker" />

import { type IWebSocketCmd, WebSocketCmdConnect } from "./websocket_cmd";

let counter = 0
const ports: MessagePort[] = [];
let websocket: WebSocket | null

(self as unknown as SharedWorkerGlobalScope).onconnect = (e: MessageEvent) => {
    const port = e.ports[0]
    ports.push(port)

    port.onmessage = (e: MessageEvent<IWebSocketCmd>) => {
        console.log(' 收到消息 ', e.data)
        if (e.data.cmd === WebSocketCmdConnect) {
            if (websocket) {
                console.log('websocket 已连接')
                return
            }

            websocket = new WebSocket(e.data.data)
        }
        ports.forEach(p => p.postMessage("i've received your message"))
    }
}