/// <reference lib="webworker" />

import type { IWebSocketCmd } from "./websocket_cmd";

let counter = 0
const ports: MessagePort[] = [];

(self as unknown as SharedWorkerGlobalScope).onconnect = (e: MessageEvent) => {
    const port = e.ports[0]
    ports.push(port)

    port.onmessage = (e: MessageEvent<IWebSocketCmd>) => {
        // if (e.data === 'counter++') counter++
        // ports.forEach(p => p.postMessage(counter))
        console.log(' 收到消息 ', e.data)
        ports.forEach(p => p.postMessage("i've received your message"))
    }
}