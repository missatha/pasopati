# PASOPATI

**P**erlindungan **A**utentikasi **S**andi **O**perasi **P**asca-kuantum **A**nti **T**iruan & **I**ntersepsi

Purwarupa Kartika Cyber Hackathon 2026, kategori Penangkalan. Perintah operasi dan logistik militer yang **tak bisa ditiru** dan **tahan komputer kuantum**.

🔗 **Coba langsung:** https://missatha.github.io/pasopati/

## Tim Cyberbaddies

| Nama | Peran | Keahlian |
|---|---|---|
| **Mega Rosita, S.Tr.Kom.** | Project Lead · System Logic | Pengujian produk keamanan TI, evaluasi Common Criteria (ISO/IEC 15408), manajemen mutu (ISO/IEC 17025) |
| **Dr. Esti Rahmawati Agustina, S.ST., M.M.T.** | Cryptography | Kriptografi, standardisasi keamanan informasi, pengujian dan sertifikasi perangkat TI |
| **Wanodya Estithama, S.Tr.Kom.** ([@missatha](https://github.com/missatha)) | UI/UX & Creative Designer| Manajemen risiko siber sektoral, tata kelola keamanan siber, ketahanan infrastruktur informasi vital |

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
| **Masuk Konsol** | Login akun siap pakai (PUSKOM, Satuan Alfa/Bravo, Penyusup, Auditor). Tiap akun di tab berbeda saling kirim perintah lewat jaringan demo, lengkap dengan matriks hak akses, 2FA opsional, jejak audit, dan cabut akses |

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

Akun siap pakai: PUSKOM-01, SATUAN-ALFA, SATUAN-BRAVO, PENYUSUP-X, AUDITOR-01. Password dibagikan tim kepada juri (lihat Buku Panduan Demo).

Catatan: situs ini statis (tanpa server), jadi password hanya gerbang demo dan semua akun berjalan di satu browser. Pemisahan data tetap dipaksakan oleh sandi: tiap pesan disegel dengan kunci ML-KEM + X25519 milik penerimanya.
