import { ref } from "vue";
import { WebSocketCmdConnect, type IWebSocketCmd } from "./websocket_cmd";

const sharedWorker = ref<SharedWorker>(new SharedWorker(new URL('./websocket_worker.ts', import.meta.url), { type: 'module' }));

export const startWebSocket = () => {
    sharedWorker.value = new SharedWorker(new URL('./websocket_worker.ts', import.meta.url), { type: 'module' });
    sharedWorker.value?.port.start()
}

export const onWebSocketMessage = (callback: (event: MessageEvent) => void) => {
    if (sharedWorker.value) {
        sharedWorker.value.port.onmessage = callback
    }
}

export const closeWebSocket = () => {
    if (sharedWorker.value) {
        sharedWorker.value.port.onmessage = null
        sharedWorker.value.port.close()
    }
}

export const postMessageToWebSocket = (message: IWebSocketCmd) => {
    sharedWorker.value?.port.postMessage(message)
}

export const postConnectCmdToWebSocket = (url: string) => {
    sharedWorker.value?.port.postMessage({
        cmd: WebSocketCmdConnect,
        data: url,
    })
}