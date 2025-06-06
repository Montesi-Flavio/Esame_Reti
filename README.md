# Email Analyzer

Email Analyzer è uno strumento per analizzare le email scaricate da un server IMAP. 
Questo strumento estrae e analizza vari componenti delle email, inclusi gli header, i link e i digests, e fornisce informazioni di investigazione utilizzando servizi esterni come VirusTotal e AbuseIPDB.

## Funzionalità

- **Download delle Email**: Scarica le email da un server IMAP e le salva come file `.eml`.
- **Estrazione degli Header**: Estrae gli header delle email e fornisce informazioni di investigazione sugli indirizzi IP e altri componenti.
- **Analisi dei Link**: Estrae i link dal contenuto delle email e verifica se sono sospetti utilizzando VirusTotal.
- **Calcolo dei Digests**: Calcola gli hash MD5, SHA1 e SHA256 dei file e del contenuto delle email.
- **Informazioni di Investigazione**: Fornisce link a servizi esterni come VirusTotal e AbuseIPDB per ulteriori analisi.

## Requisiti

- Python 3.x
- Librerie Python:
  - `imaplib`
  - `email`
  - `os`
  - `json`
  - `re`
  - `hashlib`
  - `requests` (per l'integrazione con VirusTotal)

## Installazione

1. Clona il repository:
   ```sh
   git clone https://github.com/Montesi-Flavio/Esame_Reti.git
   cd email-analyzer
   ```
2. Esegui lo script:
   ```sh
    python app.py -s imap.server.com -u user@example.com -p password -m INBOX -o emails --complete --investigate
    ```
### Utilizzo

1. Configura le credenziali del server IMAP nel file app.py:
   ```python
    SERVER = 'imap.server.com'
    USERNAME = 'username'
    PASSWORD = 'password'
2. Esegui lo script:
    ```sh
     python app.py -s imap.server.com -user@example.com -p password -m INBOX -o emails --complete --investigate
    ```sh
        python app.py -s imap.server.com -u user@example.com -p password -m INBOX -o emails --complete --investigate
        ```
    ### Opzioni
    - `-s, --server`: Server IMAP
    - `-u, --username`: Nome utente
    - `-p, --password`: Password
    - `-m, --mailbox`: Casella di posta
    - `-d, --output-dir`: Download directory
    - `-h, --header`: Esegui l'analisi dell'header
    - `-l, --link`: Esegui l'analisi dei link
    - `-g, --digest`: Esegui l'analisi del digest
    - `-c, --complete`: Esegui l'analisi completa (header, link, digest)
    - `-i, --investigate`: Esegui l'investigazione utilizzando servizi esterni
    - `-o, --output`: Directory di output


## Esempi
L'output dell'analisi viene salvato in un file JSON o HTML specificato dall'utente. Ecco un esempio di output JSON:

```json
{
    "Information": {
        "Scan": {
            "Filename": "emails/1.eml",
            "Generated": "December 08, 2024 - 16:03:54"
        }
    },
    "Analysis": {
        "Headers": {
            "Data": {
                "received": "from montiit-dir05.it.dadainternal ([172.29.136.16]) by montiit-be16.it.dadainternal with LMTP id H3LmOhWxVWeyRQAAzKB61A (envelope-from <01070193a6bbba98-dc4fb71a-d4a7-4925-bfd3-0fecfc19b713-000000@eu-central-1.amazonses.com>) for <test@maurimori.eu>; Sun, 08 Dec 2024 15:45:41 +0100",
                "x-spam-status": "No, rspamdscore=5.11, required=10.00",
                "arc-seal": "i=1; a=rsa-sha256; d=securemail.pro; s=arc20240405; t=1733669141; cv=none; b=wWFm+sT23vRkd7EisTbwY1YBFsLmPmYZTq5XBa87w81w5wNio2VLbjRlTA/rYCZCK6UunmytRZcSYx8ClMY4KB9wwHVuOtTGN7RBJVPup5NUMjCWqNfYJzqbG/zxMNnd/s96T56ZlVozlXGcbnl2LM0SrRdB5ZNcq0R6Azaw4eWhuGW/FIyZQgRaYSXZRX3d9dIPRtWJrumi4P8B3GBuG93XiC80Vqi+VITiBlq3DQVnoELOY+XQeFiCH9Z0vtIMruJ7CX8kE0AJKVoaIUtypv5NLoKZJb8GKOvrHAXP9Tzv7fQkQcbLRlpToAL9b1/CGOyA+mx/NZzkpwDWeYj+SQ==",
                "dkim-signature": "v=1; a=rsa-sha256; q=dns/txt; c=relaxed/simple; s=iuoqqwfunilueazswvoxeow57fitvqzq; d=emailsecuritytester.com; t=1733669141; h=Date:To:From:Subject:Message-ID:MIME-Version:Content-Type:Content-Transfer-Encoding; bh=degWU8CUZ66IzYJXw+vtPc8FoRj1nDPQwTlHEQLSgCE=; b=Ewc83nR9DbtdcQOIxTXjoeVlLduw3RNNrjsgnDh2aMxsjvPy40YjNcNs/mv2DSGp Nli2UIbVBPPBxLRy4WLK21b/7zaDxx6QZVtzf/m56CIJjKU/ZlVtn1AWn29d0H5zEIe 1HVT45nL8DmKtCN9nFXo9PTziGKobhx9aAnSVW8M="
            },
            "Investigation": {
                "X-Sender-Ip": {
                    "Virustotal": "https://www.virustotal.com/gui/search/69.169.227.211",
                    "Abuseipdb": "https://www.abuseipdb.com/check/69.169.227.211"
                },
                "Spoof_check": {
                    "Reply-To": "spoof@example.com",
                    "From": "legit@example.com",
                    "Conclusion": "Reply Address and From Address is NOT Same. This mail may be SPOOFED."
                }
            }
        },
        "Digests": {
            "Data": {
                "File MD5": "a15fe2c5a7ee7223822af7df3e606a86",
                "File SHA1": "9e5099d6946ea25cbcff077120ad85df84b5b482",
                "File SHA256": "7538f2f5691d3f1b6c419e0d35ec48eb58a381094f71aabbb3b35f601eaf0d0d",
                "Content MD5": "4d8eb51d6337b46bfcb108354eaba273",
                "Content SHA1": "ae14f49e1e62847d4708a1282571db524a7537a5",
                "Content SHA256": "53baa51edd8ef5ddffc19256c72e82c386dcf8e06abc12159d27d25b77c8389e"
            },
            "Investigation": {
                "File MD5": {
                    "Virustotal": "https://www.virustotal.com/gui/search/a15fe2c5a7ee7223822af7df3e606a86"
                },
                "File SHA1": {
                    "Virustotal": "https://www.virustotal.com/gui/search/9e5099d6946ea25cbcff077120ad85df84b5b482"
                },
                "File SHA256": {
                    "Virustotal": "https://www.virustotal.com/gui/search/7538f2f5691d3f1b6c419e0d35ec48eb58a381094f71aabbb3b35f601eaf0d0d"
                },
                "Content MD5": {
                    "Virustotal": "https://www.virustotal.com/gui/search/4d8eb51d6337b46bfcb108354eaba273"
                },
                "Content SHA1": {
                    "Virustotal": "https://www.virustotal.com/gui/search/ae14f49e1e62847d4708a1282571db524a7537a5"
                },
                "Content SHA256": {
                    "Virustotal": "https://www.virustotal.com/gui/search/53baa51edd8ef5ddffc19256c72e82c386dcf8e06abc12159d27d25b77c8389e"
                }
            }
        },
        "Links": {
            "Data": {
                "1": "mailto:guida@tivu.programmi-tv.com",
                "2": "mailto:maurimori@hotmail.com",
                "3": "http://torymadd.me/rd/4Fenmy5760SJKz286hnjbfxcadp849RAQUHOGGPOUQMSM11100HRSX2287w10",
                "4": "/",
                "5": "https://fonts.googleapis.com/css2?family=Cookie&amp;family=Montserrat+Alternates:wght@500&amp;family=Poppins&amp;display=swap",
                "6": "http://torymadd.me/rd/4EqiEG5760zcSf286qgpnkhwctx849UPSGPULMPAXVXVE11100TJEU2287A10",
                "7": "http://torymadd.me/rd/5KvcwA5760gqsi286mynjghtnkp849GXLYQEABALGXMGP11100ISRF2287B10",
                "8": "http://torymadd.me/rd/6uRYQR5760EBXO286orrxdjzitn849IDYIVTJCVCPXSHB11100XHQY2287J10"
            },
            "Investigation": {
                "1": {
                    "Virustotal": "https://www.virustotal.com/gui/search/mailto:guida@tivu.programmi-tv.com",
                    "Urlscan": "https://urlscan.io/search/#mailto:guida@tivu.programmi-tv.com"
                },
                "2": {
                    "Virustotal": "https://www.virustotal.com/gui/search/mailto:maurimori@hotmail.com",
                    "Urlscan": "https://urlscan.io/search/#mailto:maurimori@hotmail.com"
                },
                "3": {
                    "Virustotal": "https://www.virustotal.com/gui/search/http://torymadd.me/rd/4Fenmy5760SJKz286hnjbfxcadp849RAQUHOGGPOUQMSM11100HRSX2287w10",
                    "Urlscan": "https://urlscan.io/search/#http://torymadd.me/rd/4Fenmy5760SJKz286hnjbfxcadp849RAQUHOGGPOUQMSM11100HRSX2287w10"
                },
                "4": {
                    "Virustotal": "https://www.virustotal.com/gui/search//",
                    "Urlscan": "https://urlscan.io/search/#/"
                },
                "5": {
                    "Virustotal": "https://www.virustotal.com/gui/search/https://fonts.googleapis.com/css2?family=Cookie&amp;family=Montserrat+Alternates:wght@500&amp;family=Poppins&amp;display=swap",
                    "Urlscan": "https://urlscan.io/search/#https://fonts.googleapis.com/css2?family=Cookie&amp;family=Montserrat+Alternates:wght@500&amp;family=Poppins&amp;display=swap"
                },
                "6": {
                    "Virustotal": "https://www.virustotal.com/gui/search/http://torymadd.me/rd/4EqiEG5760zcSf286qgpnkhwctx849UPSGPULMPAXVXVE11100TJEU2287A10",
                    "Urlscan": "https://urlscan.io/search/#http://torymadd.me/rd/4EqiEG5760zcSf286qgpnkhwctx849UPSGPULMPAXVXVE11100TJEU2287A10"
                },
                "7": {
                    "Virustotal": "https://www.virustotal.com/gui/search/http://torymadd.me/rd/5KvcwA5760gqsi286mynjghtnkp849GXLYQEABALGXMGP11100ISRF2287B10",
                    "Urlscan": "https://urlscan.io/search/#http://torymadd.me/rd/5KvcwA5760gqsi286mynjghtnkp849GXLYQEABALGXMGP11100ISRF2287B10"
                },
                "8": {
                    "Virustotal": "https://www.virustotal.com/gui/search/http://torymadd.me/rd/6uRYQR5760EBXO286orrxdjzitn849IDYIVTJCVCPXSHB11100XHQY2287J10",
                    "Urlscan": "https://urlscan.io/search/#http://torymadd.me/rd/6uRYQR5760EBXO286orrxdjzitn849IDYIVTJCVCPXSHB11100XHQY2287J10"
                }
            }
        }
    }
}
```

