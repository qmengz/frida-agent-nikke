import "frida-il2cpp-bridge";
import * as NK from "./NikkeMapping.js";

const logFile = new File("E:\\Documents\\nikke\\NikkeLog.txt", "a+");
function logToFile(message: string): void {
    const line = `[${getTimestamp()}] ${message}\n`;
    logFile.write(line);
    logFile.flush(); // 确保立即写入
}

// 格式化时间戳函数
function getTimestamp() {
    const now = new Date();
    const yyyy = now.getFullYear();
    const MM = String(now.getMonth() + 1).padStart(2, '0');
    const dd = String(now.getDate()).padStart(2, '0');
    const hh = String(now.getHours()).padStart(2, '0');
    const mm = String(now.getMinutes()).padStart(2, '0');
    const ss = String(now.getSeconds()).padStart(2, '0');
    return `${yyyy}-${MM}-${dd} ${hh}:${mm}:${ss}`;
}

// 将托管 byte[] 转换为 JS Uint8Array
function toUint8Array(il2cppByteArray: Il2Cpp.Array<number>) {

    let length = il2cppByteArray.length;
    let buffer = new Uint8Array(length);

    for (let i = 0; i < length; i++) {
        buffer[i] = il2cppByteArray.get(i);
    }
    return buffer;
}

const delayss = 50;
logToFile(`DLL loading, waiting time: ${delayss} seconds ...`);
setTimeout(() => {

    Il2Cpp.perform(() => {
        logToFile(`Enter Il2Cpp.perform() `);

        // 获取dll 
        // const NK_Runtime = Il2Cpp.domain.assembly("NK.Runtime").image;
        const Net_Http = Il2Cpp.domain.assembly("System.Net.Http").image;


        // 获取类 
        // const ResponseDecryptor = NK_Runtime.class("NK.Network.PacketEncryption.ResponseDecryptor");
        const Net_HttpClient = Net_Http.class("System.Net.Http.HttpClient");
        // const Net_HttpRequestMessage = Net_Http.class("System.Net.Http.HttpRequestMessage");

        // 获取所有方法
        // Net_HttpRequestMessage.methods.forEach(m => {
        //     console.log(`[method] - [${m.name}] - [${m.isStatic}] - ${m.toString()}`);
        // });


        // 获取方法
        // const Decrypt = ResponseDecryptor.method("Decrypt", 1);
        // logToFile(`[Method] - [${Decrypt.name}] - ${Decrypt.toString()}`);

        // Hook
        // Decrypt.implementation = function (encrypted: any): Il2Cpp.Array<number> {
        //     logToFile(`[Hook] - [${Decrypt.name}] called`);
        //     logToFile(`[Hook] - [${Decrypt.name}] Input data type: ${encrypted.class.name}`);

        //     // 调用原始方法
        //     const result = this.method<Il2Cpp.Array<number>>("Decrypt", 1).invoke(encrypted);

        //     const byteArray = result;
        //     const hex = Array.from(byteArray).map(b =>
        //         ('0' + (b & 0xff).toString(16)).slice(-2)
        //     ).join('');

        //     logToFile(`[Hook] - [${Decrypt.name}] Return data hex: ${hex}`);

        //     // 返回结果
        //     return result;
        // }

        Net_HttpClient.methods.forEach(nhc => {
            // hook
            // SendAsync(System.Net.Http.HttpRequestMessage request, System.Threading.CancellationToken cancellationToken);
            if (nhc.name.endsWith("Async") && !nhc.isStatic) {
                try {
                    let uri = "";
                    Interceptor.attach(nhc.virtualAddress, {
                        onEnter(args) {
                            logToFile(`[Hook] - [${nhc.name}] - [VA: ${nhc.virtualAddress}] called `);
                            const params = nhc.parameters;
                            for (let index = 0; index < params.length; index++) {
                                // 检查参数类型
                                try {
                                    const paramaddr = args[index + 1]; // Exclude args[0] = this

                                    if (!paramaddr.isNull() && params[index].name === "request") {
                                        try {
                                            const request = new Il2Cpp.Object(paramaddr); // HttpRequestMessage
                                            const content = request.method("get_Content").invoke() as Il2Cpp.Object;
                                            const requestUri = request.method("get_RequestUri").invoke() as Il2Cpp.Object;
                                            uri = requestUri.toString();

                                            logToFile(`[Hook] - [${nhc.name}] - [VA: ${nhc.virtualAddress}] url: ${uri}`);
                                            // const requestHeaders = request.method("get_Headers").invoke() as Il2Cpp.Object;

                                            // ReadAsByteArrayAsync() -> Task<byte[]>
                                            const byteTask = content.method("ReadAsByteArrayAsync").invoke() as Il2Cpp.Object;

                                            // Task<byte[]>.Result
                                            let byteArrObj = byteTask.method("get_Result").invoke() as Il2Cpp.Array<number>;
                                            // 转成 Uint8Array
                                            let rawBytes = toUint8Array(byteArrObj);
                                            try {
                                                Object.keys(NK.requestMap).forEach((key) => {
                                                    if (uri.endsWith(key)) {
                                                        const decodedRes = NK.requestMap[key].decode(rawBytes);
                                                        logToFile(`[Hook] - [${nhc.name}] - [VA: ${nhc.virtualAddress}] - [uri:${key}] Input data json: ${JSON.stringify(decodedRes)}`);
                                                        // return decoded;
                                                    }
                                                });
                                                // const decodedRes = Nikke.ResGetSimRoom.decode(rawBytes);
                                            } catch (dre) {
                                                logToFile(`[Hook] - [${nhc.name}] - [VA: ${nhc.virtualAddress}] Input data protobuf exception: ${dre}`);
                                            }

                                        } catch (dec) {

                                        }
                                    }
                                } catch (pe) {
                                    logToFile(`[Hook] - [${nhc.name}] - [VA: ${nhc.virtualAddress}] Input data processing exception: ${pe} `);
                                }
                            }
                        },
                        onLeave(retval) {
                            try {
                                const taskObj = new Il2Cpp.Object(retval); // Task<HttpResponseMessage>

                                // 调用 Task().GetAwaiter 拿到 AwaiterTask
                                let awaiter = taskObj.method("GetAwaiter").invoke() as Il2Cpp.Object;

                                // 调用 GetAwaiter().GetResult() 拿到 HttpResponseMessage
                                let response = awaiter.method("GetResult").invoke() as Il2Cpp.Object;

                                let statusCode = response.method("get_StatusCode").invoke() as Il2Cpp.Object;
                                logToFile(`[Hook] - [${nhc.name}] - [VA: ${nhc.virtualAddress}] StatusCode: ${statusCode.toString()}`);

                                let content = response.method("get_Content").invoke() as Il2Cpp.Object;

                                // ReadAsByteArrayAsync() -> Task<byte[]>
                                let byteTask = content.method("ReadAsByteArrayAsync").invoke() as Il2Cpp.Object;

                                // Task<byte[]>.Result
                                let byteArrObj = byteTask.method("get_Result").invoke() as Il2Cpp.Array<number>;

                                // 转成 Uint8Array
                                let rawBytes = toUint8Array(byteArrObj);
                                try {
                                    Object.keys(NK.responseMap).forEach((key) => {
                                        if (uri.endsWith(key)) {
                                            const decodedRes = NK.responseMap[key].decode(rawBytes);
                                            logToFile(`[Hook] - [${nhc.name}] - [VA: ${nhc.virtualAddress}] - [uri:${key}] Return data json: ${JSON.stringify(decodedRes)}`);
                                            // return decoded;
                                        }
                                    });
                                    // const decodedRes = Nikke.ResGetSimRoom.decode(rawBytes);
                                } catch (dre) {
                                    logToFile(`[Hook] - [${nhc.name}] - [VA: ${nhc.virtualAddress}] Return data protobuf exception: ${dre}`);
                                }

                                uri = "";
                            } catch (re) {
                                logToFile(`[Hook] - [${nhc.name}] - [VA: ${nhc.virtualAddress}] Return data processing exception: ${re} `);
                            }
                            logToFile(`[Hook] - [${nhc.name}] - [VA: ${nhc.virtualAddress}] returned`);
                            return retval;
                        }
                    });
                } catch (error) {
                    logToFile(`[Hook] - [${nhc.name}] - [VA: ${nhc.virtualAddress}] exception: ${error}`);
                }
            }

        });

    });
}, delayss * 1000);

