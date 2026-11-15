# PASOPATI

**P**erlindungan **A**utentikasi **S**andi **O**perasi **P**asca-kuantum **A**nti **T**iruan & **I**ntersepsi

Purwarupa Kartika Cyber Hackathon 2026, kategori Penangkalan. Perintah operasi dan logistik militer yang **tak bisa ditiru** dan **tahan komputer kuantum**.

🔗 **Coba langsung:** https://missatha.github.io/pasopati/

Semua sandi berjalan **langsung di browser**, tanpa server:

| Fungsi | Algoritma | Standar |
|---|---|---|
| Paraf digital | ML-DSA-65 | NIST FIPS 204 |
| Kunci pasca-kuantum | ML-KEM-768 | NIST FIPS 203 |
| Kunci klasik (hibrida) | X25519 | RFC 7748 |
| Penurunan kunci | HKDF-SHA384 | RFC 5869 |
| Segel pesan | AES-256-GCM | NIST SP 800-38D |
| Rantai register | SHA-256 | FIPS 180-4 |

## Halaman

| Halaman | Isi |
|---|---|
| **Beranda** | Ancaman, ADAPT OR DIE, 3 lapis pelindung, studi kasus, FAQ |
| **Medan Uji** | Jadi penyerang: 5 serangan perintah + 3 serangan logistik. Semuanya ditolak |
| **Teknologi** | Alur perintah, algoritma, pengukuran kecepatan di perangkatmu |
| **Peta Jalan** | 4 langkah menyambut PQC, perangkat yang didukung, keselarasan BSSN/CNSA/NATO |
| **Modul** | Unduh modul Python `pasopati` (purwarupa) |
| **Masuk Konsol** | Login akun siap pakai (PUSKOM, Satuan Alfa/Bravo, Penyusup, Auditor). Tiap akun di tab berbeda saling kirim perintah lewat jaringan demo; ada mode panggung 3 layar, matriks hak akses, jejak audit, dan cabut akses |

## Cara memasang di GitHub Pages

1. Buat repo baru bernama `pasopati` (Public) di github.com/new.
2. Klik **uploading an existing file**, seret **semua isi folder ini** (termasuk folder `assets`, `unduh`, `sumber-mesin`, dan file `.nojekyll`), lalu **Commit changes**.
3. Buka **Settings → Pages**. Di **Build and deployment**, pilih **Source: Deploy from a branch**, **Branch: main**, folder **/ (root)**, lalu **Save**.
4. Tunggu 1–2 menit. Situs muncul di `https://<username>.github.io/pasopati/`.
5. Di halaman repo, klik ⚙️ pada **About** dan isi **Website** dengan link tersebut.

Situs juga bisa dibuka tanpa internet: klik dua kali `index.html`. Font dan animasi Motion butuh internet; tanpanya situs tetap berfungsi dengan tampilan cadangan.

## Struktur

```
index.html, medan-uji.html, ...   halaman situs
assets/pasopati-engine.js         mesin sandi (hasil build dari sumber-mesin/)
assets/site.css                   tampilan (palet Cyber Aurora)
unduh/                            modul Python untuk diunduh
sumber-mesin/engine.js            kode sumber mesin sandi
```

Membangun ulang mesin: `cd sumber-mesin && npm install && npm run build`

## Batasan purwarupa

- Pustaka sandi @noble (JavaScript) dan modul Python belum diaudit untuk penggunaan militer. Versi lapangan memakai pustaka teruji (liboqs / OpenSSL 3.5) dan kunci di HSM atau kartu pintar.
- Kunci dibuat ulang setiap halaman dibuka, dan semua node disimulasikan di satu browser.
- Paraf ML-DSA-65 berukuran 3,3 KB, perlu optimasi untuk radio taktis.

> Purwarupa untuk keperluan lomba. Semua perintah, satuan, dan data logistik adalah simulasi.

## Akun demo Konsol

Akun siap pakai: PUSKOM-01, SATUAN-ALFA, SATUAN-BRAVO, PENYUSUP-X, AUDITOR-01. PIN dibagikan tim saat presentasi.

Catatan: situs ini statis (tanpa server), jadi PIN hanya gerbang demo dan semua akun berjalan di satu browser. Pemisahan data tetap dipaksakan oleh sandi: tiap pesan disegel dengan kunci ML-KEM + X25519 milik penerimanya.
