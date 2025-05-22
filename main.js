const { WhoisScanner } = require('./scan');

function showUsage() {
    console.log('');
    console.log('Whois Scanner Tool');
    console.log('==================');
    console.log('');
    console.log('Utilizare: node main.js <Target>');
    console.log('');
    console.log('Exemple:');
    console.log('  node main.js example.com');
    console.log('  node main.js 1.1.1.1');
    console.log('  node main.js subdomain.example.org');
    console.log('');
    process.exit(1);
}

function validateTarget(target) {
    const ipPattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const domainPattern = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
    
    return ipPattern.test(target) || domainPattern.test(target);
}

async function main() {
    const args = process.argv.slice(2);
    
    if (args.length === 0) {
        console.log('Eroare: Nu ai specificat un Target!');
        showUsage();
    }
    
    const target = args[0].trim();
    
    if (!validateTarget(target)) {
        console.log('Eroare: Targetul nu pare sa fie un IP sau domeniu valid!');
        console.log(`Tinta specificata: ${target}`);
        showUsage();
    }
    
    console.log('╔══════════════════════════════════════════════════════════════╗');
    console.log('║                   * Whois Scanner v1  *                      ║');
    console.log('║                      Full Scanner                            ║');
    console.log('╚══════════════════════════════════════════════════════════════╝');
    console.log('');
    console.log(`Initializez scanarea pentru: ${target}`);
    console.log('Te rog asteapta, procesul poate dura cateva minute...');
    console.log('');
    
    try {
        const scanner = new WhoisScanner(target);
        await scanner.fullScan();
    } catch (error) {
        console.log('');
        console.log('Eroare in timpul scanarii:');
        console.log(error.message);
        console.log('');
        process.exit(1);
    }
}

if (require.main === module) {
    main().catch(error => {
        console.log('Eroare neasteptata:', error.message);
        process.exit(1);
    });
}

module.exports = { main };

