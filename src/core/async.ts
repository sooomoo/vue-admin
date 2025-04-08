/**
 * 休眠当前的Promise
 * @param ms 需要休眠的毫秒数
 * @returns Promise
 */
export const sleep = (ms: number): Promise<unknown> => {
    return new Promise(resolve => setTimeout(resolve, ms));
}