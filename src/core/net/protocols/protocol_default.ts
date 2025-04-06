import type { Marshaler } from "./marshaler"
import type { Protocol } from "./protocol"

export class DefaultMessageProtocol implements Protocol {
    timestamp: number = 0
    seqNumber: number = 0
    marshaler!: Marshaler

    encodeReq<T = unknown>(msgType: number, payload: T): Uint8Array {
        return new Uint8Array()
    }
    decodeResp<T = unknown>(data: Uint8Array): [number, number, T] {
        return [0, 0, {} as T]
    }
}