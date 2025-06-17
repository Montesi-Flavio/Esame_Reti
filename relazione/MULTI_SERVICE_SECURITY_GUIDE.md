# Servizi di Sicurezza Multipli per l'Analisi Email

## Panoramica

Il sistema di analisi email è stato esteso per supportare **servizi di sicurezza multipli** oltre a VirusTotal, fornendo un'analisi più completa e affidabile delle minacce.

## Servizi Supportati

### 1. **VirusTotal** (Già implementato)
- **Tipo**: Analisi file, URL, IP, domini
- **Costo**: Gratuito con limiti, piani a pagamento disponibili
- **API Key**: Richiesta
- **Capacità**: 60+ motori antivirus, analisi dinamica

### 2. **URLScan.io**
- **Tipo**: Analisi URL e screenshot
- **Costo**: Gratuito con registrazione
- **API Key**: Opzionale (per funzionalità avanzate)
- **Capacità**: Sandbox, analisi JavaScript, screenshot

### 3. **URLVoid**
- **Tipo**: Reputazione domini
- **Costo**: Commerciale
- **API Key**: Richiesta
- **Capacità**: 30+ motori di reputazione

### 4. **PhishTank**
- **Tipo**: Database phishing
- **Costo**: Gratuito
- **API Key**: Non richiesta
- **Capacità**: Database verificato dalla community

### 5. **MalwareBazaar**
- **Tipo**: Database malware
- **Costo**: Gratuito
- **API Key**: Non richiesta
- **Capacità**: Campioni di malware, hash lookup

### 6. **AbuseIPDB Enhanced**
- **Tipo**: Reputazione IP
- **Costo**: Gratuito con registrazione
- **API Key**: Richiesta per funzionalità avanzate
- **Capacità**: Report abusi, geolocalizzazione, ISP info

## Configurazione

### 1. Chiavi API (Opzionali)

Configura le seguenti variabili d'ambiente per abilitare tutti i servizi:

```bash
# Windows PowerShell
$env:URLSCAN_API_KEY="your_urlscan_key"
$env:ABUSEIPDB_API_KEY="your_abuseipdb_key"
$env:URLVOID_API_KEY="your_urlvoid_key"
$env:HYBRIDANALYSIS_API_KEY="your_hybrid_analysis_key"

# Linux/Mac
export URLSCAN_API_KEY="your_urlscan_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_key"
export URLVOID_API_KEY="your_urlvoid_key"
export HYBRIDANALYSIS_API_KEY="your_hybrid_analysis_key"
```

### 2. Registrazione Servizi

#### URLScan.io
1. Vai su https://urlscan.io/
2. Registrati gratuitamente
3. Ottieni la API key dal profilo

#### AbuseIPDB
1. Vai su https://www.abuseipdb.com/
2. Registrati gratuitamente
3. Ottieni la API key dal dashboard

#### URLVoid (Commerciale)
1. Vai su https://www.urlvoid.com/
2. Acquista un piano API
3. Ottieni la API key

## Utilizzo

### 1. Analisi Completa

```python
from connectors import comprehensive_security_check

# Analisi URL
results = comprehensive_security_check("http://suspicious-site.com", "url")

# Analisi IP
results = comprehensive_security_check("192.168.1.1", "ip")

# Analisi Hash
results = comprehensive_security_check("abc123...", "hash")
```

### 2. Demo Completa

```bash
cd src
python multi_service_demo.py
```

### 3. Integrazione nell'Analyzer Esistente

Il sistema può essere facilmente integrato negli analyzer esistenti:

```python
# Nel link_analyzer.py
from connectors import comprehensive_security_check

def enhanced_link_investigation(url):
    # Invece di usare solo VirusTotal
    # safe, positives, error = check_url_safety(url)
    
    # Usa l'analisi multipla
    results = comprehensive_security_check(url, 'url')
    return results
```

## Vantaggi dell'Analisi Multipla

### 1. **Ridondanza**
- Se un servizio è down, altri continuano a funzionare
- Riduce falsi positivi/negativi

### 2. **Copertura Completa**
- VirusTotal: Ampia copertura antivirus
- URLScan: Analisi comportamentale
- PhishTank: Specializzato in phishing
- MalwareBazaar: Database malware specifico

### 3. **Diversi Punti di Vista**
- Motori diversi possono rilevare minacce diverse
- Approcci complementari (statico vs dinamico)

### 4. **Threat Intelligence**
- Dati da fonti multiple
- Informazioni contestuali aggiuntive

## Esempio di Output

```json
{
  "item": "http://suspicious-site.com",
  "item_type": "url",
  "overall_safe": false,
  "services": {
    "virustotal": {
      "safe": false,
      "positives": 3,
      "error": null
    },
    "urlscan": {
      "safe": true,
      "details": {"scan_id": "abc123"},
      "error": null
    },
    "phishtank": {
      "safe": false,
      "details": {"phish_id": 12345},
      "error": null
    }
  }
}
```

## Gestione Costi e Limiti

### Strategia Graduata:
1. **Livello Base**: VirusTotal + servizi gratuiti (PhishTank, MalwareBazaar)
2. **Livello Intermedio**: + URLScan.io + AbuseIPDB enhanced
3. **Livello Avanzato**: + URLVoid + Hybrid Analysis

### Ottimizzazione:
- Cache aggressiva per ridurre chiamate API
- Fallback graceful quando servizi non disponibili
- Prioritizzazione servizi basata su tipo di analisi

## Implementazione nell'HTML Output

I risultati multipli possono essere visualizzati nell'output HTML con:

```html
<div class="multi-service-analysis">
  <h4>🛡️ Analisi Sicurezza Multipla</h4>
  
  <div class="service-result">
    <span class="service-name">VirusTotal</span>
    <span class="result-badge danger">3/64 rilevamenti</span>
  </div>
  
  <div class="service-result">
    <span class="service-name">PhishTank</span>
    <span class="result-badge danger">Phishing confermato</span>
  </div>
  
  <div class="service-result">
    <span class="service-name">URLScan</span>
    <span class="result-badge success">Nessuna minaccia</span>
  </div>
</div>
```

## Prossimi Passi

1. **Test dei nuovi servizi** con chiavi API reali
2. **Integrazione nell'HTML output** per visualizzazione migliorata  
3. **Configurazione rate limiting** per rispettare limiti API
4. **Aggiunta metriche** per valutare efficacia servizi multipli
5. **Sistema di scoring** per combinare risultati da servizi diversi

---

**Nota**: Alcuni servizi richiedono registrazione e chiavi API. I servizi gratuiti hanno limitazioni che devono essere considerate in un ambiente di produzione.
