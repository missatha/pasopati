# PASOPATI

**P**erlindungan **A**utentikasi **S**andi **O**perasi **P**asca-kuantum **A**nti-**T**iruan dan **I**ntersepsi

**PASOPATI** merupakan purwarupa sistem keamanan berbasis *Post-Quantum Cryptography* (PQC) yang dikembangkan dalam Kartika Cyber Hackathon 2026, kategori Penangkalan.

PASOPATI dirancang untuk melindungi keaslian perintah operasi dan integritas data logistik militer melalui mekanisme autentikasi, tanda tangan digital, serta komunikasi yang dipersiapkan untuk menghadapi ancaman komputasi kuantum.

Dengan PASOPATI, setiap instruksi dapat diverifikasi untuk memastikan identitas pengirim dan keutuhan pesan, sekaligus mengurangi risiko pemalsuan maupun pengiriman ulang perintah yang tidak sah.

🔗 **Coba langsung:** https://missatha.github.io/pasopati/

## Teknologi yang digunakan

Seluruh proses kriptografi pada purwarupa ini dijalankan langsung di browser pengguna, tanpa memerlukan server untuk pemrosesan kriptografi.

| Fungsi | Algoritma | Standar |
|---|---|---|
| Tanda tangan digital | ML-DSA-65 | NIST FIPS 204 |
| Pertukaran kunci pasca-kuantum | ML-KEM-768 | NIST FIPS 203 |
| Pertukaran kunci klasik (hibrida) | X25519 | RFC 7748 |
| Penurunan kunci | HKDF-SHA384 | RFC 5869 |
| Enkripsi dan autentikasi pesan | AES-256-GCM | NIST SP 800-38D |
| Integritas rantai catatan | SHA-256 | FIPS 180-4 |

## Fitur dan halaman platform

PASOPATI memiliki enam halaman utama yang dirancang untuk memperkenalkan teknologi, menguji mekanisme keamanan, dan memperlihatkan penerapannya dalam skenario operasi.

| Halaman | Deskripsi |
|---|---|
| **Beranda** | Memperkenalkan latar belakang ancaman, konsep *Adapt or Die*, tiga lapisan perlindungan PASOPATI, studi kasus, dan FAQ. |
| **Medan Uji** | Menyediakan simulasi pengujian keamanan dari sisi penyerang, mencakup lima skenario serangan terhadap perintah operasi dan tiga skenario serangan terhadap data logistik. Seluruh delapan skenario berhasil ditolak dalam pengujian purwarupa. |
| **Teknologi** | Menjelaskan alur pengamanan perintah, algoritma kriptografi yang digunakan, serta pengukuran kinerja algoritma pada perangkat pengguna. |
| **Peta Jalan** | Menampilkan empat tahapan persiapan menuju penerapan PQC, perangkat yang didukung, serta keselarasan pendekatan dengan arah kebijakan BSSN, CNSA, dan NATO. |
| **Modul** | Menyediakan modul Python `pasopati` yang dapat diunduh untuk keperluan pengembangan dan pengujian lebih lanjut. |
| **Masuk Konsol** | Menyediakan konsol simulasi berdasarkan peran pengguna: Pusat Komando, Satuan Lapangan, dan Auditor Logistik. |

## Panduan instalasi melalui GitHub Pages

Untuk menjalankan PASOPATI secara online menggunakan GitHub Pages, ikuti langkah berikut:

1. Buat repository baru bernama `pasopati` melalui [GitHub](https://github.com/new), kemudian atur visibilitas repository menjadi **Public**.
2. Pilih menu **uploading an existing file**, lalu unggah seluruh isi folder proyek, termasuk folder `assets`, `unduh`, `sumber-mesin`, serta file `.nojekyll`. Setelah itu, klik **Commit changes**.
3. Buka **Settings → Pages**. Pada bagian *Build and deployment*, pilih:
   - Source: Deploy from a branch
   - Branch: `main`
   - Folder: `/ (root)`
   
   Kemudian klik **Save**.
4. Tunggu proses deployment selesai. Website dapat diakses melalui alamat `https://<username>.github.io/pasopati/`.
5. Untuk menampilkan tautan website pada halaman repository, buka bagian **About**, klik ikon pengaturan, lalu masukkan URL website pada kolom **Website**.

### Penggunaan tanpa koneksi internet

PASOPATI juga dapat dijalankan secara lokal dengan membuka file `index.html` melalui browser.

Beberapa fitur tampilan, seperti pemuatan font dan animasi Motion, memerlukan koneksi internet. Jika koneksi tidak tersedia, website tetap dapat dijalankan menggunakan tampilan alternatif yang disediakan.

## Struktur direktori

Berikut struktur utama berkas proyek PASOPATI:

```text
index.html, medan-uji.html, ... 
    Halaman utama website

assets/
    pasopati-engine.js
    Mesin kriptografi hasil build dari sumber-mesin/

    site.css
    Stylesheet dan pengaturan tampilan website

unduh/
    Modul Python yang dapat diunduh

sumber-mesin/
    engine.js
    Kode sumber mesin kriptografi
```

### Membangun ulang mesin kriptografi

Untuk membangun ulang mesin kriptografi dari kode sumber, jalankan perintah berikut:

```bash
cd sumber-mesin
npm install
npm run build
```

## Batasan purwarupa

PASOPATI masih merupakan purwarupa yang dikembangkan untuk kebutuhan demonstrasi dan pengujian dalam kompetisi. Oleh karena itu, terdapat beberapa keterbatasan yang perlu diperhatikan sebelum sistem dikembangkan untuk penggunaan operasional.

1. **Pustaka kriptografi:** Implementasi saat ini menggunakan pustaka JavaScript `@noble` dan modul Python yang belum melalui audit keamanan untuk penggunaan militer. Pengembangan lebih lanjut memerlukan pustaka kriptografi yang telah teruji, seperti liboqs atau OpenSSL 3.5, serta pengelolaan kunci menggunakan HSM atau kartu pintar.
2. **Pengelolaan kunci:** Kunci kriptografi dibuat ulang setiap kali halaman dibuka. Selain itu, seluruh entitas dalam simulasi saat ini berjalan pada satu browser, sehingga belum merepresentasikan komunikasi antarsistem secara terdistribusi.
3. **Ukuran tanda tangan digital:** Tanda tangan ML-DSA-65 memiliki ukuran sekitar 3,3 KB. Ukuran ini perlu menjadi pertimbangan untuk komunikasi melalui radio taktis yang memiliki keterbatasan bandwidth.

> **Catatan:** PASOPATI merupakan purwarupa untuk keperluan kompetisi dan demonstrasi teknologi. Seluruh perintah operasi, satuan, serta data logistik yang digunakan merupakan data simulasi dan bukan informasi operasional sebenarnya.
