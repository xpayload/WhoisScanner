const https = require('https');
const http = require('http');
const dns = require('dns');
const net = require('net');
const crypto = require('crypto');
const { promisify } = require('util');
const { exec } = require('child_process');
const { WAFChecker } = require('./wafdetector');

const resolve = promisify(dns.resolve);
const reverse = promisify(dns.reverse);
const lookup = promisify(dns.lookup);
const execPromise = promisify(exec);

class WhoisScanner {
    constructor(target) {
        this.target = target;
        this.isIP = /^\d+\.\d+\.\d+\.\d+$/.test(target);
        this.wafChecker = new WAFChecker();
        this.vtApiKey = Buffer.from('NWI2NTdiZDAwOWU3MGZlYjA1YzE1NTViYTY5ZjJhYjU1ODI4MjFjYmI5YTA4NGMyMjI5MDNhZTcxMmY2YTZiNQ==', 'base64').toString();
        this.ip2locationKey = Buffer.from('MkNCN0JEOERENzZGRTQ0MzJFMzhCNUVGQkVGMkE2MDY=', 'base64').toString();
        this.ip2whoisKey = Buffer.from('MkNCN0JEOERENzZGRTQ0MzJFMzhCNUVGQkVGMkE2MDY=', 'base64').toString();
        
        this.info = {
            target: target,
            ip: null,
            domain: null,
            status: 'necunoscut',
            ping_status: 'necunoscut',
            ping_reason: '',
            geo: {},
            dns_data: {},
            ssl_info: {},
            open_ports: [],
            subdomains: [],
            found_files: [],
            protection: [],
            headers: {},
            technologies: [],
            emails: [],
            endpoints: [],
            domain_info: {},
            favicon_hash: null,
            blacklist_status: []
        };
    }

    async fullScan() {
        console.log(`scanare completa pentru: ${this.target}`);
        
        try {
            await this.resolveHost();
            await this.pingCheck();
            await this.geoIP();
            await this.dnsEnum();
            await this.scanPorts();
            await this.webAnalysis();
            await this.subdomainSearch();
            await this.directoryBruteforce();
            await this.emailHarvest();
            await this.whoisLookup();
            await this.blacklistCheck();
            await this.sslCheck();
            await this.faviconGet();
            
            const wafResults = await this.wafChecker.checkWAF(this.info.domain || this.target, this.info.open_ports.includes(443));
            this.info.protection = wafResults.detected;
            
        } catch (error) {
            console.log(`eroare scanare: ${error.message}`);
        }

        this.showResults();
        console.log('\nscanare finalizata cu succes!');
        process.exit(0);
    }

    async resolveHost() {
        if (this.isIP) {
            this.info.ip = this.target;
            try {
                const hostnames = await reverse(this.target);
                this.info.domain = hostnames[0];
                console.log(`rezolvat ip ${this.target} la ${hostnames[0]}`);
            } catch (e) {
                this.info.domain = 'fara reverse dns';
            }
        } else {
            this.info.domain = this.target;
            try {
                const result = await lookup(this.target);
                this.info.ip = result.address;
                console.log(`${this.target} rezolvat la ${result.address}`);
            } catch (e) {
                throw new Error(`nu pot rezolva ${this.target}`);
            }
        }
    }

    async pingCheck() {
        try {
            const pingCmd = process.platform === 'win32' ? 
                `ping -n 1 -w 3000 ${this.info.ip}` : 
                `ping -c 1 -W 3 ${this.info.ip}`;
            
            await execPromise(pingCmd);
            this.info.ping_status = 'raspunde';
            this.info.ping_reason = 'Target este online si raspunde la ping';
            console.log(`Target raspunde la ping`);
        } catch (e) {
            this.info.ping_status = 'nu raspunde';
            
            if (e.message.includes('timeout') || e.message.includes('unreachable')) {
                this.info.ping_reason = 'timeout sau host unreachable';
            } else if (e.message.includes('filtered')) {
                this.info.ping_reason = 'probabil filtrat de firewall';
            } else {
                this.info.ping_reason = 'Target offline sau ping blocat';
            }
            console.log(`Target nu raspunde la ping: ${this.info.ping_reason}`);
        }
    }

    async geoIP() {
        const geoServices = [
            `http://ip-api.com/json/${this.info.ip}?fields=status,country,city,region,isp,org,timezone,mobile,proxy,hosting`,
            `https://ipapi.co/${this.info.ip}/json/`
        ];

        for (let service of geoServices) {
            try {
                const data = await this.httpReq(service);
                const geo = JSON.parse(data);
                
                if (geo.country || geo.country_name || geo.country_code) {
                    this.info.geo = {
                        country: geo.country || geo.country_name || geo.country_code || 'necunoscut',
                        city: geo.city || geo.city_name || 'necunoscut',
                        region: geo.region || geo.region_name || geo.region_code || 'necunoscut',
                        isp: geo.isp || geo.as || 'necunoscut',
                        org: geo.org || geo.organization || geo.as_name || 'necunoscut',
                        timezone: geo.timezone || geo.time_zone || 'necunoscut',
                        mobile: geo.mobile || geo.is_mobile || false,
                        proxy: geo.proxy || geo.is_proxy || false,
                        hosting: geo.hosting || false
                    };
                    console.log(`locatie gasita: ${this.info.geo.city}, ${this.info.geo.country}`);
                    break;
                }
            } catch (e) {
                continue;
            }
        }
    }

    async dnsEnum() {
        if (this.info.domain === 'fara reverse dns') {
            console.log('Pas enumerarea dns - nu am domeniu');
            return;
        }

        const types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA'];
        
        for (let type of types) {
            try {
                const records = await resolve(this.info.domain, type);
                this.info.dns_data[type] = records;
            } catch (e) {
                this.info.dns_data[type] = [];
            }
        }

        if (this.info.dns_data.TXT) {
            const txtRecords = this.info.dns_data.TXT;
            this.info.dns_data.spf = txtRecords.find(r => r.includes('v=spf1'));
            this.info.dns_data.dmarc = txtRecords.find(r => r.includes('v=DMARC1'));
        }
        
        console.log(`inregistrari dns colectate pentru ${this.info.domain}`);
    }

    async scanPorts() {
        const commonPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306, 1433, 6379, 8080, 8443, 9200, 5900, 1723, 8000, 8888, 9999];
        
        console.log('scanez porturile...');
        
        const checkPromises = commonPorts.map(async (port) => {
            const isOpen = await this.checkPort(this.info.ip, port);
            if (isOpen) {
                this.info.open_ports.push(port);
                console.log(`portul ${port} este deschis`);
            }
            return isOpen;
        });
        
        await Promise.all(checkPromises);
        
        try {
            const checkHostData = await this.httpReq(`https://check-host.net/check-tcp?host=${this.info.ip}:80&max_nodes=1`);
            const checkResult = JSON.parse(checkHostData);
            if (checkResult.request_id) {
                console.log('verificare suplimentara tcp via check-host.net');
            }
        } catch (e) {
            // fallback local
        }
    }

    checkPort(host, port, timeout = 1500) {
        return new Promise((resolve) => {
            const socket = new net.Socket();
            
            socket.setTimeout(timeout);
            socket.on('connect', () => {
                socket.destroy();
                resolve(true);
            });
            
            socket.on('timeout', () => {
                socket.destroy();
                resolve(false);
            });
            
            socket.on('error', () => {
                resolve(false);
            });
            
            socket.connect(port, host);
        });
    }

    async webAnalysis() {
        if (!this.info.open_ports.includes(80) && !this.info.open_ports.includes(443) && !this.info.open_ports.includes(8080)) {
            console.log('nu am porturi web deschise, salt analiza web');
            return;
        }

        const protocols = ['https', 'http'];
        
        for (let proto of protocols) {
            try {
                const response = await this.httpReqFull(`${proto}://${this.info.domain || this.info.ip}/`);
                
                if (response.statusCode < 400) {
                    this.info.headers = response.headers;
                    this.info.status = `activ (${response.statusCode})`;
                    
                    if (response.headers.server) {
                        this.info.technologies.push(`Server: ${response.headers.server}`);
                    }
                    
                    if (response.headers['x-powered-by']) {
                        this.info.technologies.push(`X-Powered-By: ${response.headers['x-powered-by']}`);
                    }
                    
                    this.findTech(response.body);
                    this.extractEndpoints(response.body);
                    console.log(`serviciul web este activ, cod ${response.statusCode}`);
                    break;
                }
            } catch (e) {
                continue;
            }
        }
        
        if (this.info.status === 'necunoscut') {
            this.info.status = 'serviciu web inactiv sau filtrat';
            console.log('serviciul web pare sa fie oprit sau request-ul blocat');
        }
    }

    findTech(body) {
        const signatures = {
            'WordPress': ['/wp-content/', '/wp-includes/', 'wp-json', 'wp-admin', 'wp_'],
            'Drupal': ['drupal.js', '/sites/default/', 'drupal.settings', 'drupal-'],
            'Joomla': ['/components/', '/modules/', 'joomla', 'option=com_'],
            'Laravel': ['laravel_session=', 'csrf-token', '_token', 'laravel'],
            'Django': ['csrfmiddlewaretoken', 'django', 'djdt', '__admin_media_prefix__'],
            'React': ['react', '_react', 'react-dom', 'reactjs'],
            'Angular': ['ng-', 'angular', 'angularjs', 'ng-app'],
            'Vue.js': ['vue.js', '__vue__', 'vue-router', 'vue'],
            'jQuery': ['jquery', '$.', 'jquery-ui', 'jquery.min.js'],
            'Bootstrap': ['bootstrap', 'btn-primary', 'container-fluid', 'bootstrap.min.css'],
            'nginx': ['nginx', 'server: nginx'],
            'Apache': ['apache', 'mod_', 'server: apache'],
            'PHP': ['<?php', '.php', 'phpsessid', 'x-powered-by: php'],
            'ASP.NET': ['__viewstate', 'aspnet', '.aspx', 'x-aspnet-version'],
            'Node.js': ['express', 'nodejs', 'x-powered-by: express'],
            'IIS': ['iis', 'microsoft-iis', 'server: microsoft-iis'],
            'Magento': ['magento', 'mage/', 'varien/', 'magento_'],
            'Shopify': ['shopify', 'cdn.shopify.com', 'shopify-'],
            'Cloudflare': ['cf-ray', '__cfduid', 'cloudflare'],
            'Google Analytics': ['google-analytics', 'gtag(', 'ga('],
            'Yandex.Metrica': ['yandex_metrika', 'mc.yandex.ru'],
            'OpenSSL': ['openssl', 'ssl'],
            'MongoDB': ['mongodb', 'mongo'],
            'MySQL': ['mysql', 'phpmyadmin'],
            'PostgreSQL': ['postgresql', 'postgres'],
            'Redis': ['redis'],
            'Docker': ['docker', 'container'],
            'Kubernetes': ['kubernetes', 'k8s']
        };

        const bodyLower = body.toLowerCase();
        
        for (let [tech, patterns] of Object.entries(signatures)) {
            for (let pattern of patterns) {
                if (bodyLower.includes(pattern.toLowerCase())) {
                    if (!this.info.technologies.includes(tech)) {
                        this.info.technologies.push(tech);
                    }
                    break;
                }
            }
        }
    }

    extractEndpoints(body) {
        const urlRegex = /(?:href|src|action|data-url)=["']([^"']*)/gi;
        const jsApiRegex = /["'`](\/(?:api|admin|dashboard|login|user|profile|upload|download|search|contact)[^"'`\s]*?)["'`]/gi;
        
        let match;
        const endpoints = new Set();
        
        while ((match = urlRegex.exec(body)) !== null) {
            let url = match[1];
            if (url.startsWith('/') && !url.startsWith('//') && url.length > 2) {
                endpoints.add(url);
            }
        }
        
        while ((match = jsApiRegex.exec(body)) !== null) {
            endpoints.add(match[1]);
        }
        
        this.info.endpoints = Array.from(endpoints).slice(0, 25);
    }

    async subdomainSearch() {
        if (this.info.domain === 'fara reverse dns' || this.isIP) {
            console.log('Pas cautarea subdomeniilor - nu am domeniu');
            return;
        }

        console.log('Cautare subdomenii...');
        
        const sources = [
            `https://crt.sh/?q=%25.${this.info.domain}&output=json`,
            `https://api.certspotter.com/v1/issuances?domain=${this.info.domain}&include_subdomains=true&expand=dns_names`,
            `https://api.hackertarget.com/hostsearch/?q=${this.info.domain}`,
            `https://sonar.omnisint.io/subdomains/${this.info.domain}`
        ];
        
        const subs = new Set();
        
        for (let source of sources) {
            try {
                const data = await this.httpReq(source);
                
                if (source.includes('crt.sh')) {
                    const certs = JSON.parse(data);
                    certs.forEach(cert => {
                        const names = cert.name_value ? cert.name_value.split('\n') : [];
                        names.forEach(name => {
                            name = name.trim().toLowerCase();
                            if (name.includes(this.info.domain) && !name.startsWith('*') && name !== this.info.domain) {
                                subs.add(name);
                            }
                        });
                    });
                } else if (source.includes('certspotter')) {
                    const certData = JSON.parse(data);
                    certData.forEach(cert => {
                        if (cert.dns_names) {
                            cert.dns_names.forEach(name => {
                                name = name.toLowerCase();
                                if (name.includes(this.info.domain) && !name.startsWith('*') && name !== this.info.domain) {
                                    subs.add(name);
                                }
                            });
                        }
                    });
                } else if (source.includes('hackertarget')) {
                    const lines = data.split('\n');
                    lines.forEach(line => {
                        if (line.includes(',')) {
                            const subdomain = line.split(',')[0].trim().toLowerCase();
                            if (subdomain && subdomain !== this.info.domain) {
                                subs.add(subdomain);
                            }
                        }
                    });
                } else if (source.includes('omnisint')) {
                    const subData = JSON.parse(data);
                    if (subData && Array.isArray(subData)) {
                        subData.forEach(sub => {
                            if (typeof sub === 'string' && sub !== this.info.domain) {
                                subs.add(sub.toLowerCase());
                            }
                        });
                    }
                }
                
            } catch (e) {
                continue;
            }
        }
        
        const commonSubs = ['www', 'mail', 'ftp', 'admin', 'webmail', 'api', 'blog', 'dev', 'test', 'staging', 'cdn', 'shop', 'support', 'portal', 'app', 'mobile', 'secure', 'vpn', 'remote', 'cpanel', 'forum', 'help', 'docs', 'subdomain', 'ns1', 'ns2', 'mx', 'mx1', 'mx2', 'pop', 'smtp', 'imap'];
        
        for (let sub of commonSubs) {
            const fullSub = `${sub}.${this.info.domain}`;
            try {
                await lookup(fullSub);
                subs.add(fullSub);
            } catch (e) {
                // nu exista
            }
        }
        
        this.info.subdomains = Array.from(subs);
        console.log(`am gasit ${this.info.subdomains.length} subdomenii`);
    }

    async directoryBruteforce() {
        if (!this.info.open_ports.includes(80) && !this.info.open_ports.includes(443) && !this.info.open_ports.includes(8080)) {
            return;
        }

        const paths = [
            'robots.txt', 'sitemap.xml', '.htaccess', '.env', 'config.json', 'config.php',
            'admin/', 'admin.php', 'administrator/', 'login/', 'login.php', 'wp-login.php',
            'api/', 'api/v1/', 'api/v2/', 'test/', 'testing/', 'backup/', 'backups/',
            'upload/', 'uploads/', 'files/', 'images/', 'img/', 'docs/', 'documentation/',
            '.git/', '.svn/', 'phpinfo.php', 'info.php', 'phpmyadmin/', 'pma/',
            '.well-known/', 'security.txt', 'favicon.ico', 'apple-touch-icon.png',
            'wp-config.php', 'wp-content/', 'wp-admin/', 'wp-includes/',
            'database.yml', 'settings.py', 'web.config', 'app.config',
            'composer.json', 'package.json', 'gulpfile.js', 'webpack.config.js',
            'readme.txt', 'readme.md', 'changelog.txt', 'license.txt',
            'server-status', 'server-info', 'status/', 'health/', 'metrics/',
            'debug/', 'error/', 'logs/', 'log/', 'tmp/', 'temp/',
            'cgi-bin/', 'scripts/', 'css/', 'js/', 'assets/'
        ];

        const proto = this.info.open_ports.includes(443) ? 'https' : 'http';
        const target = this.info.domain || this.info.ip;
        
        console.log('verific fisiere si directoare vizibile...');
        
        const checkPromises = paths.map(async (path) => {
            try {
                const response = await this.httpReqFull(`${proto}://${target}/${path}`);
                if (response.statusCode === 200 || response.statusCode === 301 || response.statusCode === 302) {
                    return {
                        path: path,
                        url: `${proto}://${target}/${path}`,
                        status: response.statusCode,
                        size: response.headers['content-length'] || 'necunoscut',
                        type: response.headers['content-type'] || 'necunoscut'
                    };
                }
            } catch (e) {
                return null;
            }
            return null;
        });
        
        const results = await Promise.all(checkPromises);
        this.info.found_files = results.filter(r => r !== null);
        
        if (this.info.found_files.length > 0) {
            console.log(`am gasit ${this.info.found_files.length} fisiere/directoare`);
        }
    }

    async emailHarvest() {
        if (!this.info.open_ports.includes(80) && !this.info.open_ports.includes(443) && !this.info.open_ports.includes(8080)) {
            return;
        }

        try {
            const proto = this.info.open_ports.includes(443) ? 'https' : 'http';
            const target = this.info.domain || this.info.ip;
            
            const pagesToCheck = ['/', '/contact', '/about', '/team', '/staff'];
            const allEmails = new Set();
            
            for (let page of pagesToCheck) {
                try {
                    const response = await this.httpReq(`${proto}://${target}${page}`);
                    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
                    const emails = response.match(emailRegex) || [];
                    emails.forEach(email => allEmails.add(email.toLowerCase()));
                } catch (e) {
                    continue;
                }
            }
            
            for (let email of Array.from(allEmails).slice(0, 15)) {
                const domain = email.split('@')[1];
                try {
                    const mxRecords = await resolve(domain, 'MX');
                    this.info.emails.push({ email: email, valid_mx: mxRecords.length > 0 });
                } catch (e) {
                    this.info.emails.push({ email: email, valid_mx: false });
                }
            }
            
            if (this.info.emails.length > 0) {
                console.log(`am gasit ${this.info.emails.length} adrese email`);
            }
            
        } catch (e) {
            // skip
        }
    }

    async whoisLookup() {
        if (this.info.domain === 'fara reverse dns' || this.isIP) {
            return;
        }

        const whoisSources = [
            `https://api.ip2whois.com/v2?key=${this.ip2whoisKey}&domain=${this.info.domain}`,
            `https://rdap.verisign.com/com/v1/domain/${this.info.domain}`,
            `https://rdap.org/domain/${this.info.domain}`
        ];
        
        for (let source of whoisSources) {
            try {
                const whoisData = await this.httpReq(source);
                const data = JSON.parse(whoisData);
                
                if ((data.status === 'success' || data.objectClassName === 'domain') && !data.error) {
                    let registrar = 'necunoscut';
                    let created = null;
                    let expires = null;
                    let updated = null;
                    let adminEmail = null;
                    
                    if (source.includes('ip2whois')) {
                        registrar = data.registrar?.name || data.registrar || 'necunoscut';
                        created = data.create_date || data.created_date;
                        expires = data.expire_date || data.expiry_date;
                        updated = data.update_date || data.updated_date;
                        adminEmail = data.admin?.email || data.administrative?.email;
                    } else {
                        registrar = data.entities && data.entities[0] ? data.entities[0].handle : 'necunoscut';
                        if (data.events) {
                            const regEvent = data.events.find(e => e.eventAction === 'registration');
                            const expEvent = data.events.find(e => e.eventAction === 'expiration');
                            const updEvent = data.events.find(e => e.eventAction === 'last changed');
                            created = regEvent ? regEvent.eventDate : null;
                            expires = expEvent ? expEvent.eventDate : null;
                            updated = updEvent ? updEvent.eventDate : null;
                        }
                    }
                    
                    this.info.domain_info = {
                        registrar: registrar,
                        created: created ? new Date(created).toLocaleDateString('ro-RO') : 'necunoscut',
                        expires: expires ? new Date(expires).toLocaleDateString('ro-RO') : 'necunoscut',
                        updated: updated ? new Date(updated).toLocaleDateString('ro-RO') : 'necunoscut',
                        admin_email: adminEmail || 'necunoscut',
                        status: data.status_list || data.status || 'necunoscut'
                    };
                    
                    console.log(`informatii whois colectate pentru ${this.info.domain}`);
                    break;
                }
                
            } catch (e) {
                continue;
            }
        }
    }

    async blacklistCheck() {
        console.log('verificare reputatia ip-ului...');
        
        const checkers = [
            {
                name: 'virustotal',
                url: `https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=${this.vtApiKey}&ip=${this.info.ip}`,
                check: (data) => data.response_code === 1 && data.detected_urls && data.detected_urls.length > 0
            },
            {
                name: 'alienvault',
                url: `https://otx.alienvault.com/api/v1/indicators/IPv4/${this.info.ip}/general`,
                check: (data) => data.reputation && data.reputation > 0
            },
            {
                name: 'hybrid-analysis',
                url: `https://www.hybrid-analysis.com/api/v2/search/hash?hash=${this.info.ip}`,
                check: (data) => Array.isArray(data) && data.length > 0
            }
        ];
        
        let suspicious = false;
        
        for (let checker of checkers) {
            try {
                const response = await this.httpReq(checker.url);
                const data = JSON.parse(response);
                
                if (checker.check(data)) {
                    suspicious = true;
                    this.info.blacklist_status.push(`suspect pe ${checker.name}`);
                }
            } catch (e) {
                continue;
            }
        }
        
        if (!suspicious) {
            this.info.blacklist_status.push('reputatie curata');
        }
    }

    async sslCheck() {
        if (!this.info.open_ports.includes(443)) return;
        
        try {
            const target = this.info.domain || this.info.ip;
            const options = {
                host: target,
                port: 443,
                method: 'GET',
                path: '/',
                rejectUnauthorized: false
            };
            
            const cert = await new Promise((resolve, reject) => {
                const req = https.request(options, (res) => {
                    const certificate = res.socket.getPeerCertificate();
                    resolve(certificate);
                });
                req.on('error', reject);
                req.setTimeout(8000, () => reject(new Error('timeout ssl')));
                req.end();
            });
            
            const validFrom = new Date(cert.valid_from);
            const validTo = new Date(cert.valid_to);
            const now = new Date();
            const daysUntilExpiry = Math.ceil((validTo - now) / (1000 * 60 * 60 * 24));
            
            this.info.ssl_info = {
                subject: cert.subject,
                issuer: cert.issuer,
                valid_from: validFrom.toLocaleDateString('ro-RO'),
                valid_to: validTo.toLocaleDateString('ro-RO'),
                days_until_expiry: daysUntilExpiry,
                fingerprint: cert.fingerprint,
                serial: cert.serialNumber,
                expired: now > validTo,
                algorithm: cert.sigalg || 'necunoscut'
            };
            
            console.log('certificat ssl analizat');
            
        } catch (e) {
            this.info.ssl_info.error = e.message;
        }
    }

    async faviconGet() {
        if (!this.info.open_ports.includes(80) && !this.info.open_ports.includes(443) && !this.info.open_ports.includes(8080)) {
            return;
        }

        try {
            const proto = this.info.open_ports.includes(443) ? 'https' : 'http';
            const target = this.info.domain || this.info.ip;
            const faviconData = await this.httpReq(`${proto}://${target}/favicon.ico`);
            this.info.favicon_hash = crypto.createHash('sha1').update(faviconData).digest('hex');
        } catch (e) {
            this.info.favicon_hash = null;
        }
    }

    httpReq(url, options = {}) {
        return new Promise((resolve, reject) => {
            const client = url.startsWith('https') ? https : http;
            const req = client.get(url, {
                timeout: 10000,
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                },
                ...options
            }, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => resolve(data));
            });
            
            req.on('error', reject);
            req.on('timeout', () => {
                req.destroy();
                reject(new Error('timeout'));
            });
        });
    }

    httpReqFull(url, options = {}) {
        return new Promise((resolve, reject) => {
            const client = url.startsWith('https') ? https : http;
            const req = client.get(url, {
                timeout: 8000,
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                },
                ...options
            }, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => resolve({
                    statusCode: res.statusCode,
                    headers: res.headers,
                    body: data
                }));
            });
            
            req.on('error', reject);
            req.on('timeout', () => {
                req.destroy();
                reject(new Error('timeout'));
            });
        });
    }

    showResults() {
        console.log('\n' + '═'.repeat(80));
        console.log('                         REZULTATE SCANARE WhoisScan');
        console.log('═'.repeat(80));
        
        console.log(`\nTARGET: ${this.info.target}`);
        console.log(`ADRESA IP: ${this.info.ip}`);
        console.log(`DOMENIU: ${this.info.domain}`);
        console.log(`STATUS PING: ${this.info.ping_status} - ${this.info.ping_reason}`);
        console.log(`STATUS WEB: ${this.info.status}`);
        
        if (Object.keys(this.info.geo).length > 0) {
            console.log(`\nGEOLOCATIE:`);
            Object.entries(this.info.geo).forEach(([key, value]) => {
                if (value) console.log(`  ${key.toUpperCase()}: ${value}`);
            });
        }
        
        if (Object.keys(this.info.domain_info).length > 0) {
            console.log(`\nINFORMATII DOMENIU:`);
            console.log(`  REGISTRAR: ${this.info.domain_info.registrar || 'necunoscut'}`);
            console.log(`  CREAT LA: ${this.info.domain_info.created || 'necunoscut'}`);
            console.log(`  EXPIRA LA: ${this.info.domain_info.expires || 'necunoscut'}`);
            console.log(`  ULTIMA ACTUALIZARE: ${this.info.domain_info.updated || 'necunoscut'}`);
            console.log(`  EMAIL ADMIN: ${this.info.domain_info.admin_email || 'necunoscut'}`);
            if (this.info.domain_info.status) {
                console.log(`  STATUS: ${this.info.domain_info.status}`);
            }
        }

        function getRecordsStr(records) {
            if (!Array.isArray(records)) return JSON.stringify(records);
            if (typeof records[0] === 'string') return records.join(', ');
            if (records[0].exchange) return records.map((r) => r.exchange).join(', ');
            return records.join(', ');
        }
        
        if (Object.keys(this.info.dns_data).length > 0) {
            console.log(`\nINREGISTRARI DNS:`);
            Object.entries(this.info.dns_data).forEach(([type, records]) => {
                if (records && records.length > 0) {
                    console.log(`  ${type}: ${getRecordsStr(records)}`);
                }
            });
        }
        
        console.log(`\nPORTURI DESCHISE: ${this.info.open_ports.join(', ') || 'niciunul gasit'}`);
        
        if (this.info.ssl_info.subject) {
            console.log(`\nCERTIFICAT SSL:`);
            console.log(`  Subiect: ${this.info.ssl_info.subject.CN || 'necunoscut'}`);
            console.log(`  Emitent: ${this.info.ssl_info.issuer.O || this.info.ssl_info.issuer.CN || 'necunoscut'}`);
            console.log(`  Valid de la: ${this.info.ssl_info.valid_from}`);
            console.log(`  Valid pana la: ${this.info.ssl_info.valid_to}`);
            console.log(`  Zile pana la expirare: ${this.info.ssl_info.days_until_expiry}`);
            console.log(`  Expirat: ${this.info.ssl_info.expired ? 'DA' : 'NU'}`);
            console.log(`  Algoritm: ${this.info.ssl_info.algorithm}`);
            console.log(`  Fingerprint: ${this.info.ssl_info.fingerprint}`);
        }
        
        console.log(`\nWAF TECH DETECTATE: ${this.info.technologies.join(', ') || 'nu s-au detectat'}`);
        
        console.log(`\nSECURITATE/WAF: ${this.info.protection.join(', ') || 'nu s-a detectat'}`);
        
        console.log(`\nREPUTATIE IP: ${this.info.blacklist_status.join(', ')}`);
        
        if (this.info.subdomains.length > 0) {
            console.log(`\nSUBDOMENII GASITE (${this.info.subdomains.length}):`);
            this.info.subdomains.slice(0, 25).forEach(sub => console.log(`  ${sub}`));
            if (this.info.subdomains.length > 25) {
                console.log(`  ...si inca ${this.info.subdomains.length - 25} subdomenii`);
            }
        }
        
        if (this.info.found_files.length > 0) {
            console.log(`\nFISIERE SI DIRECTOARE GASITE (${this.info.found_files.length}):`);
            this.info.found_files.forEach(file => {
                console.log(`  ${file.url} (${file.size} bytes, status: ${file.status})`);
            });
        }
        
        if (this.info.emails.length > 0) {
            console.log(`\nADRESE EMAIL GASITE (${this.info.emails.length}):`);
            this.info.emails.forEach(email => {
                const status = email.valid_mx ? 'mx valid' : 'fara mx';
                console.log(`  ${email.email} (${status})`);
            });
        }
        
        if (this.info.endpoints.length > 0) {
            console.log(`\nENDPOINT-URI GASITE (${this.info.endpoints.length}):`);
            this.info.endpoints.slice(0, 20).forEach(ep => console.log(`  ${ep}`));
        }
        
        if (this.info.favicon_hash) {
            console.log(`\nHASH FAVICON: ${this.info.favicon_hash}`);
        }
        
        if (Object.keys(this.info.headers).length > 0 && Object.keys(this.info.headers).length < 20) {
            console.log(`\nHEADERE HTTP IMPORTANTE:`);
            const importantHeaders = ['server', 'x-powered-by', 'x-frame-options', 'x-xss-protection', 'content-security-policy', 'strict-transport-security'];
            Object.entries(this.info.headers).forEach(([key, value]) => {
                if (importantHeaders.includes(key.toLowerCase()) || key.toLowerCase().startsWith('x-')) {
                    console.log(`  ${key}: ${value}`);
                }
            });
        }
        
        console.log('\n' + '═'.repeat(80));
        console.log('SCANAREA S-A INCHEIAT CU SUCCES!');
        console.log('═'.repeat(80));
    }
}

module.exports = { WhoisScanner };
