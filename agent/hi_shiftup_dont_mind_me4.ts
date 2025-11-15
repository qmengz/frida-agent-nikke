import "frida-il2cpp-bridge";

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

const delayss = 50;
logToFile(`等待Dll加载中,等待时间: ${delayss} 秒 ...`);
setTimeout(() => {

    Il2Cpp.perform(() => {
        logToFile(`进入 Il2Cpp.perform() `);

        // 获取dll 
        const NK_Runtime = Il2Cpp.domain.assembly("NK.Runtime").image;
        const Net_Http = Il2Cpp.domain.assembly("System.Net.Http").image;


        // 获取类 
        const ResponseDecryptor = NK_Runtime.class("NK.Network.PacketEncryption.ResponseDecryptor");
        const Net_HttpClient = Net_Http.class("System.Net.Http.HttpClient");

        // 获取方法
        const Decrypt = ResponseDecryptor.method("Decrypt", 1);
        logToFile(`[Method] - [${Decrypt.name}] - ${Decrypt.toString()}`);

        // Hook
        Decrypt.implementation = function (encrypted: any): Il2Cpp.Array<number> {
            logToFile(`[Hook] - [${Decrypt.name}] called`);
            logToFile(`[Hook] - [${Decrypt.name}] 参数类型: ${encrypted.class.name}`);

            // 调用原始方法
            const result = this.method<Il2Cpp.Array<number>>("Decrypt", 1).invoke(encrypted);

            const byteArray = result;
            const hex = Array.from(byteArray).map(b =>
                ('0' + (b & 0xff).toString(16)).slice(-2)
            ).join('');

            logToFile(`[Hook] - [${Decrypt.name}] 返回数据 (hex): ${hex}`);

            // 返回结果
            return result;
        }

        Net_HttpClient.methods.forEach(nhc => {
            // hook
            // SendAsync(System.Net.Http.HttpRequestMessage request, System.Threading.CancellationToken cancellationToken);
            if (nhc.name.endsWith("Async") && !nhc.isStatic) {
                try {
                    Interceptor.attach(nhc.virtualAddress, {
                        onEnter(args) {
                            logToFile(`[Hook] - [${nhc.name}] called}`);
                            const params = nhc.parameters;
                            for (let index = 0; index < params.length; index++) {
                                // 检查参数类型
                                try {
                                    const paramaddr = args[index];
                                    const addrprt = paramaddr.toString();
                                    let uri = "";
                                    if ("0x0" !== addrprt &&
                                        (params[index].name === "cancellationToken" || params[index].name === "completionOption")) {
                                        const base = ptr(addrprt);
                                        const uriPtr = base.add(0x30).readPointer();
                                        if (!uriPtr.isNull()) {
                                            const strPtr = uriPtr.add(0x10).readPointer(); // Uri.m_String
                                            if (!strPtr.isNull()) {
                                                uri = strPtr.add(0x14).readUtf16String() ?? "";
                                            }
                                        }
                                        logToFile(`[Hook] - [${nhc.name}] url: ${uri}`);
                                    }
                                } catch (pe) {
                                    logToFile(`[Hook] - [${nhc.name}] 输入值处理异常: ${pe} `);
                                }
                            }
                        },
                        onLeave(retval) {
                            logToFile(`[Hook] - [${nhc.name}] returned`);
                            return retval;
                        }
                    });
                } catch (error) {
                    logToFile(`[Hook] - [${nhc.name}] error: ${error}`);
                }
            }

        });

    });
}, delayss * 1000);

