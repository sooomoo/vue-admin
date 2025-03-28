/// <reference lib="webworker" />

import { type IWebSocketCmd, WebSocketCmdConnect } from "./websocket_cmd";

const ports: MessagePort[] = [];
let websocket: WebSocket | null

const scope = self as unknown as SharedWorkerGlobalScope
if (!scope) {
    throw new Error('scope is not SharedWorkerGlobalScope')
}

scope.onconnect = (e: MessageEvent) => {
    const port = e.ports[0]
    ports.push(port)

    port.postMessage({
        cmd: "token",
        data: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30',
    })

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