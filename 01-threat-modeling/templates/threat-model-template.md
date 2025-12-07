# Threat Model Template

Template za dokumentiranje threat modela servisa. Koristiti za svaki kritični servis u sistemu.

---

## Naziv servisa

[Unesite naziv servisa]

## 1. Opis usluge

[Kratki opis šta servis radi i koja je njegova svrha]

## 2. Funkcije servis implementira/podržava

[Lista funkcionalnosti koje servis pruža]

## 3. Usluga vjerodajnica ima pristup

(Ocijenite ih visokim, srednjim, niskim u smislu radijusa eksplozije ako su izloženi)

| Vjerodajnica | Tip | Rizik | Napomena |
|--------------|-----|-------|----------|
| Npr. GitHub token | API ključ | Visok | Pristup svim repozitorijima |
| DB lozinka | Secret | Visok | Pristup svim podacima |
| GCE servisni račun | IAM | Srednji | Ograničen na specifične operacije |
| RabbitMQ propusnica | Secret | Srednji | Pristup message queue |

## 4. Usluga osjetljivih podataka se ili pohranjuje u db ili ima pristup u vrijeme izvođenja

(Ocijenite ih visokim, srednjim, niskim u smislu radijusa eksplozije ako su izloženi)

| Podatak | Lokacija | Rizik | Napomena |
|---------|----------|-------|----------|
| | | | |

## 5. Servisi koji se povezuju na ovaj servis

(sinhronizacija preko API-ja, ili asinhronizacija preko RabbitMQ)

| Servis | Tip komunikacije | Protokol | Port |
|--------|------------------|----------|------|
| | | | |

## 6. Usluga API-ja je razotkrivena

(može biti samo do veze do intern_api proto datoteke)

| Endpoint | Metoda | Autentifikacija | Pristup |
|----------|--------|-----------------|---------|
| | | | |

## 7. Koji su potencijalni vektori napada?

(Identifikujte moguće ulazne tačke za napadače, kao što su API-ji, daljinsko izvršavanje koda, eksterne zavisnosti, skladište podataka)

- [ ] API endpoint bez autentifikacije
- [ ] SQL injection
- [ ] Command injection
- [ ] Deserialization ranjivosti
- [ ] Eksterne zavisnosti sa poznatim ranjivostima
- [ ] Pristup bazama podataka
- [ ] SSRF (Server-Side Request Forgery)
- [ ] Privilege escalation

## 8. Evidencija i nadgledanje

Da li radimo dovoljno evidencije i nadgledanja da bismo mogli otkriti kompromitaciju usluge ili curenje podataka? Koju evidenciju i monitoring da dodamo?

### Postojeće logovanje
- [ ] Aplikacijski logovi
- [ ] Audit logovi
- [ ] Sigurnosni događaji

### Preporučeni dodaci
- [ ] Logovanje pristupa osjetljivim podacima
- [ ] Alerting na neobične aktivnosti
- [ ] Integracija sa SIEM

## 9. Dijagram toka visokog nivoa

(npr. preuzimanje webhooka sa GitHub-a, pohraniti ga, poslati vodoinstalateru, poslati zahtjev za posao serveru za izgradnju)

Može biti veza sa Whimsical boardom ili ugrađeni dijagram.

```
[Ulaz] --> [Servis] --> [Obrada] --> [Izlaz]
    |                       |
    v                       v
[Logovanje]          [Baza podataka]
```

---

## STRIDE Analiza

### Spoofing (Lažiranje identiteta)
- Rizik: [Visok/Srednji/Nizak]
- Mitigacija:

### Tampering (Neovlaštena izmjena)
- Rizik: [Visok/Srednji/Nizak]
- Mitigacija:

### Repudiation (Poricanje)
- Rizik: [Visok/Srednji/Nizak]
- Mitigacija:

### Information Disclosure (Curenje informacija)
- Rizik: [Visok/Srednji/Nizak]
- Mitigacija:

### Denial of Service (Uskraćivanje usluge)
- Rizik: [Visok/Srednji/Nizak]
- Mitigacija:

### Elevation of Privilege (Eskalacija privilegija)
- Rizik: [Visok/Srednji/Nizak]
- Mitigacija:

---

## Zaključak i preporuke

[Sumirajte ključne rizike i preporučene akcije]

## Autor i datum

- Autor:
- Datum:
- Revizija:
