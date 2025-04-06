export interface Protocol {
    encodeReq<T = unknown>(msgType: number, payload: T): Uint8Array;
    decodeResp<T = unknown>(data: Uint8Array): [number, number, T];
}


export const protocolStartTime = new Date(2025, 0, 1, 0, 0, 0, 0)
