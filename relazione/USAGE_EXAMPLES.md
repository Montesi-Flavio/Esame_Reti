# Esempio di Utilizzo dei Servizi di Sicurezza Alternativi

## 🚀 Come Utilizzare i Nuovi Servizi

### 1. **Configurazione API Keys**

Aggiungi le seguenti variabili d'ambiente al tuo sistema:

```bash
# API Keys opzionali per servizi aggiuntivi
export URLSCAN_API_KEY="your_urlscan_api_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_api_key" 
export URLVOID_API_KEY="your_urlvoid_api_key"
export GOOGLE_SAFE_BROWSING_API_KEY="your_google_api_key"
export HYBRIDANALYSIS_API_KEY="your_hybrid_analysis_api_key"
```

### 2. **Utilizzo delle Nuove Funzioni**

#### Analisi Completa URL
```python
from connectors import comprehensive_url_analysis

# Analizza un URL con tutti i servizi disponibili
url = "http://suspicious-site.com"
results = comprehensive_url_analysis(url)

print(f"Risk Score: {results['risk_score']}/10")
print(f"Recommendation: {results['recommendation']}")

# Verifica risultati di ogni servizio
for service, result in results['services'].items():
    print(f"{service}: {result}")
```

#### Analisi Completa Hash
```python
from connectors import comprehensive_hash_analysis

# Analizza un hash con VirusTotal + MalwareBazaar
hash_value = "abc123def456..."
results = comprehensive_hash_analysis(hash_value)

print(f"Risk Score: {results['risk_score']}/10")
print(f"Recommendation: {results['recommendation']}")
```

#### Servizi Individuali
```python
from connectors import (
    check_phishtank_url,
    check_urlvoid_safety,
    check_google_safe_browsing,
    check_malwarebazaar_hash,
    check_spamhaus_domain,
    check_abuseipdb_enhanced
)

# PhishTank (Gratuito)
phish_result, error = check_phishtank_url("http://example.com")
if phish_result and phish_result.get('is_phish'):
    print("⚠️ URL trovato nel database PhishTank!")

# MalwareBazaar (Gratuito)
safe, details, error = check_malwarebazaar_hash("your_hash_here")
if not safe:
    print(f"🦠 Malware rilevato: {details.get('malware_family')}")

# Spamhaus Domain Check (Gratuito)
is_listed, list_type, error = check_spamhaus_domain("example.com")
if is_listed:
    print(f"🚫 Dominio in blacklist: {list_type}")

# AbuseIPDB Enhanced (API key richiesta)
result, error = check_abuseipdb_enhanced("192.168.1.1")
if result:
    confidence = result.get('abuse_confidence', 0)
    if confidence > 50:
        print(f"⚠️ IP sospetto - Confidenza: {confidence}%")
```

### 3. **Integrazione nell'Email Analyzer**

#### Modifica analyzer dei link
```python
# In src/analyzers/link_analyzer.py
from connectors import comprehensive_url_analysis

def analyze_links_enhanced(mail_data, investigation=False):
    # ... codice esistente ...
    
    if investigation:
        for link in unique_links:
            # Usa analisi completa invece di solo VirusTotal
            analysis = comprehensive_url_analysis(link)
            
            # Aggiungi risultati all'output
            link_data = {
                'url': link,
                'risk_score': analysis['risk_score'],
                'recommendation': analysis['recommendation'],
                'services': analysis['services']
            }
            
            result["investigation_results"].append(link_data)
```

#### Modifica analyzer degli allegati
```python
# In src/analyzers/attachment_analyzer.py
from connectors import comprehensive_hash_analysis

def analyze_attachments_enhanced(email_file, investigation=False):
    # ... codice esistente ...
    
    if investigation:
        for attachment in attachments:
            # Analisi hash completa
            for hash_type in ['md5', 'sha1', 'sha256']:
                hash_value = attachment[hash_type]
                analysis = comprehensive_hash_analysis(hash_value)
                
                attachment_info[f'{hash_type}_analysis'] = {
                    'risk_score': analysis['risk_score'],
                    'recommendation': analysis['recommendation'],
                    'services': analysis['services']
                }
```

### 4. **Strategie per Ridurre la Dipendenza da VirusTotal**

#### Strategia a Cascata
```python
def smart_url_check(url):
    """
    Controlla URL usando una strategia a cascata:
    1. Cache locale
    2. Servizi gratuiti (PhishTank, Spamhaus)
    3. VirusTotal (se necessario)
    """
    
    # 1. Controlla cache
    cached = get_from_cache(url)
    if cached:
        return cached
    
    # 2. Servizi gratuiti first
    phish_result, _ = check_phishtank_url(url)
    if phish_result and phish_result.get('is_phish'):
        return {'is_safe': False, 'source': 'PhishTank', 'confidence': 'high'}
    
    # 3. Controlla dominio con Spamhaus
    domain = extract_domain(url)
    is_listed, list_type, _ = check_spamhaus_domain(domain)
    if is_listed:
        return {'is_safe': False, 'source': 'Spamhaus', 'confidence': 'high'}
    
    # 4. Solo se necessario, usa VirusTotal
    vt_safe, vt_positives, vt_error = check_url_safety(url)
    if vt_error and "QuotaExceeded" in vt_error:
        # Quota exceeded - usa valutazione conservativa
        return {'is_safe': None, 'source': 'Conservative', 'confidence': 'low'}
    
    return {'is_safe': vt_safe, 'source': 'VirusTotal', 'confidence': 'medium'}
```

#### Configurazione Priorità Servizi
```python
# In src/config.py
SERVICE_PRIORITIES = {
    'high_confidence': ['phishtank', 'malwarebazaar', 'spamhaus'],
    'medium_confidence': ['virustotal', 'google_safe_browsing'],
    'low_confidence': ['urlvoid', 'urlscan']
}

FREE_SERVICES = ['phishtank', 'malwarebazaar', 'spamhaus']
PAID_SERVICES = ['virustotal', 'urlvoid', 'urlscan']
```

### 5. **Monitoraggio e Ottimizzazione**

#### Logging dei Servizi
```python
import logging

logger = logging.getLogger('security_services')

def log_service_usage():
    """Log dell'utilizzo dei servizi per ottimizzazione"""
    service_stats = {
        'virustotal_calls': 0,
        'quota_exceeded_count': 0,
        'free_service_hits': 0,
        'threat_detection_rate': {}
    }
    
    # Traccia usage per ottimizzare
    logger.info(f"Service stats: {service_stats}")
```

#### Implementazione Failover
```python
def resilient_threat_check(item, item_type='url'):
    """
    Sistema resiliente che prova multiple fonti
    """
    services = ['phishtank', 'spamhaus', 'virustotal', 'urlvoid']
    
    for service in services:
        try:
            result = call_service(service, item, item_type)
            if result and not result.get('error'):
                return result
        except Exception as e:
            logger.warning(f"Service {service} failed: {e}")
            continue
    
    # Se tutti falliscono, usa approccio conservativo
    return {'is_safe': None, 'recommendation': 'Manual review required'}
```

### 6. **Performance e Caching**

#### Cache Intelligente
```python
CACHE_PRIORITIES = {
    'malware_detected': 30,  # 30 giorni per malware confermato
    'phishing_detected': 30,  # 30 giorni per phishing
    'safe_confirmed': 7,      # 7 giorni per contenuto sicuro
    'unknown': 1              # 1 giorno per risultati incerti
}

def smart_cache_strategy(result):
    """Strategia di cache basata sul tipo di risultato"""
    if result.get('risk_score', 0) >= 7:
        return CACHE_PRIORITIES['malware_detected']
    elif result.get('is_phish'):
        return CACHE_PRIORITIES['phishing_detected']
    elif result.get('is_safe'):
        return CACHE_PRIORITIES['safe_confirmed']
    else:
        return CACHE_PRIORITIES['unknown']
```

### 7. **Piano di Migrazione**

#### Fase 1: Setup Servizi Gratuiti (Immediata)
1. ✅ Attiva PhishTank
2. ✅ Attiva MalwareBazaar  
3. ✅ Attiva Spamhaus DNS checks
4. ✅ Implementa cache intelligente

#### Fase 2: Riduzione Dipendenza VirusTotal (1-2 settimane)
1. 🔧 Implementa strategia a cascata
2. 🔧 Aggiungi failover logic
3. 🔧 Configura priorità servizi
4. 🔧 Test con email reali

#### Fase 3: Servizi Premium Opzionali (1 mese)
1. 🔧 Setup Google Safe Browsing
2. 🔧 Setup URLVoid/URLScan.io
3. 🔧 Setup AbuseIPDB premium
4. 🔧 Ottimizzazione performance

#### Risultati Attesi
- **-70% chiamate VirusTotal**: Tramite servizi gratuiti e cache
- **+95% uptime**: Failover su multiple fonti
- **+50% detection rate**: Combinazione multiple fonti
- **-60% costi API**: Meno dipendenza da servizi a pagamento

### 8. **Script di Test**

```python
# test_alternative_services.py
def test_all_services():
    """Test di tutti i servizi alternativi"""
    
    test_cases = {
        'safe_url': 'https://google.com',
        'phishing_url': 'http://known-phishing-site.com',
        'malware_hash': 'known_malware_hash_here',
        'safe_hash': 'known_safe_hash_here'
    }
    
    for test_name, test_data in test_cases.items():
        print(f"\n--- Testing {test_name} ---")
        
        if 'url' in test_name:
            result = comprehensive_url_analysis(test_data)
        else:
            result = comprehensive_hash_analysis(test_data)
        
        print(f"Risk Score: {result['risk_score']}")
        print(f"Recommendation: {result['recommendation']}")
        
        for service, data in result['services'].items():
            status = "✅" if not data.get('error') else "❌"
            print(f"{status} {service}: {data}")

if __name__ == "__main__":
    test_all_services()
```

Questo approccio ti permetterà di ridurre significativamente la dipendenza da VirusTotal mentre manterrai (o migliori) l'efficacia del rilevamento delle minacce.
