# Phishing Email Analyzer - PyQt5 Desktop GUI

## Proqram Haqqında

Bu proqram, .eml və .msg formatlı e-poçt fayllarını təhlil etmək üçün hazırlanmış masaüstü tətbiqidir. Təhlil prosesi zamanı e-poçtun daxilindəki URL-lər, IP ünvanları, domainlər və hash dəyərləri aşkar edilir, həmçinin fayl əlavələri (attachments) yoxlanılır. Proqram, asinxron şəkildə müxtəlif təhlükəsizlik mənbələri ilə (VirusTotal, OTX, urlscan, GreyNoise, AbuseIPDB, WHOIS) əlaqə quraraq əlavə məlumatlar əldə edir və nəticələri vizual şəkildə təqdim edir.

## Xüsusiyyətlər

- **Dəstəklənən Fayl Formatları**: .eml, .msg
- **Təhlil Növləri**:
  - E-poçt başlıqlarının təhlili
  - IOC (Indicator of Compromise) aşkarlanması
  - Fayl əlavələrinin təhlili (makrolar, PE fayllar, skriptlər)
  - YARA qaydaları ilə uyğunluq yoxlanışı
  - URL genişləndirmə (redirect zəncirlərinin izlənməsi)
  - Təhlükəsizlik mənbələri ilə inteqrasiya
- **Vizual Təqdimat**:
  - IOC statistikası (bar qrafik)
  - Təhlükəsizlik skoru (donut diaqram)
  - Cədvəllər və mətn formatında nəticələr
- **Hesabat**: Nəticələrin Word (.docx) formatında ixracı

## Quraşdırma

### Tələb Olunan Kitabxanalar

Proqramı işlətmək üçün aşağıdakı Python kitabxanaları quraşdırılmalıdır:

```bash
pip install PyQt5 matplotlib python-docx eml-parser extract-msg oletools yara-python pefile beautifulsoup4 lxml tldextract chardet aiohttp aiodns requests[security] python-whois dnspython pyyaml rich jinja2 python-dateutil
```

### Konfiqurasiya

Proqram, `config.yaml` faylı vasitəsilə konfiqurasiya edilə bilər. Əgər konfiqurasiya faylı təmin edilməsə, proqram özündə olan standart konfiqurasıyadan istifadə edəcəkdir.

Nümunə `config.yaml` faylı:

```yaml
apis:
  virustotal_api_key: "your_virustotal_api_key"
  otx_api_key: "your_otx_api_key"
  urlscan_api_key: "your_urlscan_api_key"
  greynoise_api_key: "your_greynoise_api_key"
  abuseipdb_api_key: "your_abuseipdb_api_key"
network:
  user_agent: "Mansimov-Phish-Analyzer/1.0"
  timeout_sec: 10
  verify_tls: true
  safe_http_methods: ["HEAD", "GET"]
  expand_max_redirects: 5
scoring:
  weights:
    url_new_domain: 10
    url_sus_tld: 8
    url_ip_host: 12
    url_shortener: 6
    macro_autoexec: 20
    attachment_exe: 25
    attachment_script: 15
    vt_malicious_detection: 30
    brand_impersonation: 12
    dmarc_fail: 10
    replyto_mismatch: 8
    unicode_spoof: 10
    otx_pulse_hit: 10
    greynoise_malicious: 8
    abuseipdb_reports: 8
output:
  html_report: true
  markdown_report: true
  json_report: true
yara:
  rules_path: "yara_rules"
```

## İstifadə Qaydası

1. Proqramı işə saldıqdan sonra əsas pəncərə açılacaq.
2. **Email** bölməsində təhlil etmək istədiyiniz .eml və ya .msg faylını seçin.
3. (Opsional) **Config** bölməsində öz konfiqurasiya faylınızı seçə bilərsiniz.
4. (Opsional) **YARA Rules Dir** bölməsində YARA qaydalarının olduğu qovluğu seçə bilərsiniz.
5. **Expand URLs** seçimini işarələməklə URL-lərin genişləndirilməsini aktiv edə bilərsiniz.
6. **Analyze** düyməsini klikləməklə təhlil prosesini başladın.
7. Təhlil tamamlandıqdan sonra nəticələr müxtəlif vərəqlərdə göstəriləcək:
   - **Summary**: Ümumi məlumat və tapıntılar
   - **IOCs**: Aşkarlanmış indikatorlar
   - **Attachments**: Əlavə faylların təhlili
   - **Enrichment**: Xarici mənbələrdən əldə edilmiş məlumatlar
   - **Dashboard**: Vizual statistikalar
8. **Export Word Report** düyməsi ilə nəticələri Word sənədi şəklində ixrac edə bilərsiniz.

## Əlaqə

Proqramla bağlı suallar və ya problemlər üçün müəllif ilə əlaqə saxlayın (əlaqə məlumatları proqram kodunda mövcud deyil).
