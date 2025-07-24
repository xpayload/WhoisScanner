# WhoisScanner 🔍

Scanner ultra-complet pentru analiza domeniilor si IP-urilor. Asta e toolul care-ti trebuie cand vrei sa afli totul despre o tinta - de la DNS pana la subdomenii ascunse.

## Ce face exact?

WhoisScanner e un tool scris in Node.js care face analiza completa a unei tinte. Nu e doar un whois simplu - e mult mai mult:

- **Analiza DNS completa** - toate inregistrarile (A, MX, TXT, NS, etc.)
- **Port scanning** - gaseste ce porturi sunt deschise 
- **Subdomain enumeration** - cauta subdomenii din multiple surse
- **SSL certificate analysis** - verifica certificatele si expirarea
- **Web fingerprinting** - detecteaza tehnologiile folosite
- **WAF detection** - identifica firewall-urile web
- **Directory bruteforcing** - cauta fisiere si directoare
- **Email harvesting** - gaseste adresele de email
- **Geolocation** - localizarea IP-ului
- **Blacklist checking** - verifica reputatia IP-ului
- **Whois information** - detalii despre domeniu

## Instalare

Cloneaza repo-ul si porneste:

```bash
git clone https://github.com/xpayload/WhoisScanner.git
cd WhoisScanner
node main.js example.com
```

Nu ai nevoie de dependinte externe - totul e construit cu modulele native din Node.js.

## Utilizare

### Scanare domeniu
```bash
node main.js example.com
```

### Scanare IP
```bash
node main.js 1.1.1.1
```

### Scanare subdomeniu
```bash
node main.js subdomeniu.exemplu.com
```

## Exemple de output

Toolul iti va afisa informatii despre:

- **Target info** - IP, domeniu, status ping
- **Geolocatie** - tara, oras, ISP, organizatie
- **Informatii domeniu** - registrar, date de creare/expirare
- **DNS records** - toate inregistrarile DNS gasite
- **Porturi deschise** - lista cu porturile active
- **Certificat SSL** - detalii despre certificat daca exista
- **Tehnologii detectate** - frameworks, CMS, servere web
- **Securitate** - WAF-uri si sisteme de protectie
- **Subdomenii** - lista cu subdomeniile gasite
- **Fisiere gasite** - directoare si fisiere accesibile
- **Adrese email** - emailuri gasite pe site
- **Reputatie IP** - verificare in blacklist-uri

## De ce e diferit?

Spre deosebire de alte tool-uri, WhoisScanner:

- Nu necesita instalare de dependinte complicate
- Foloseste multiple surse pentru fiecare tip de informatie
- Are detectie avansata de WAF si tehnologii
- Colecteaza informatii din surse publice (crt.sh, VirusTotal, etc.)
- E scris sa fie rapid si eficient
- Output-ul e organizat si usor de citit

## Cum functioneaza?

Toolul face request-uri la diverse API-uri publice si servicii pentru a colecta informatii:

- **DNS enumeration** - foloseste modulele native dns din Node.js
- **Subdomain discovery** - cauta in crt.sh, certspotter, hackertarget
- **Port scanning** - conectare TCP directa
- **Web analysis** - request-uri HTTP/HTTPS cu analiza raspuns
- **Geolocation** - ip-api.com si ipapi.co
- **SSL analysis** - conectare directa la portul 443
- **WAF detection** - teste cu payload-uri specifice

## Limitari

- Nu e un tool de penetration testing - e pentru reconnaissance
- Respecta rate limits pentru API-urile publice
- Unele informatii depind de disponibilitatea serviciilor externe
- Nu face brute force agresiv - e discret

## Contributii

Daca vrei sa contribui:

1. Fork repo-ul
2. Creeaza branch pentru feature-ul tau
3. Commit si push
4. Fa pull request

## Note

Toolul e pentru uz educational si testare pe sistemele proprii. Nu-l folosi pe tinte fara permisiune.

## Licenta

MIT License - fa ce vrei cu el, dar mentine creditele.

---

**Autor**: xpayload  
**GitHub**: https://github.com/xpayload/WhoisScanner

Daca toolul ti-a fost util, lasa un star! ⭐
