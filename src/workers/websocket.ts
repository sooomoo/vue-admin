import { ref } from "vue";
import { WebSocketCmdConnect, type IWebSocketCmd } from "./websocket_cmd";

const sharedWorker = ref<SharedWorker>();

export const startWebSocket = () => {
    sharedWorker.value = new SharedWorker(
        new URL('./websocket_worker.ts', import.meta.url),
        { type: 'module', name: 'niu_websocket_worker', credentials: 'same-origin' });
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

// 跨标签页通信可以使用： BroadcastChannel，sharedWorker，localStorage触发storage事件
// API	            核心功能	                                                        通信模型	        典型用途
// MessageChannel	在同一页面的不同线程（如主线程与 Web Worker）或跨 iframe 建立双向通信通道	点对点（1 对 1）	复杂任务分流（如 Web Worker 计算）、跨域 iframe 通信
// BroadcastChannel	在同源的不同标签页、窗口或 Worker 之间实现消息广播	                    发布 - 订阅（1 对多）  多标签页状态同步（如用户登录 / 注销）、实时通知
// RTCDataChannel	通过 WebRTC 建立点对点数据通道，支持低延迟、高可靠性的跨浏览器通信	        点对点（1 对 1）     实时协作（如在线白板）、文件传输、游戏控制