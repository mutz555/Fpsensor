# HyperOS Fingerprint Hardware Detection Bypasser

Modul Zygisk untuk mem-bypass deteksi hardware fingerprint pada perangkat Android, khususnya ditargetkan untuk HyperOS Android 15 namun juga mendukung Android 13+ dengan metode hook yang dinamis.

## Fitur

- Bypass deteksi hardware fingerprint dengan selalu mengembalikan nilai "True"
- Kompatibilitas khusus untuk HyperOS/Android 15 dengan dukungan untuk Android 13 dan 14
- Mendukung berbagai nama metode deteksi berdasarkan versi Android:
  - `isFpHardwareDetected()` (HyperOS)
  - `isFingerprintHardwareDetected()` (Android 14)
  - `isFingerprintHardwarePresent()` (Android 13)
- Terintegrasi dengan sistem biometrik Android 
- Mengelabui aplikasi bahwa perangkat memiliki sensor sidik jari

## Persyaratan

- Perangkat Android dengan Magisk v24+ terinstall
- Zygisk harus diaktifkan di pengaturan Magisk
- Android 13, 14, atau 15 (HyperOS)
- Root access

## Cara Penggunaan

1. Install Magisk dari [sini](https://github.com/topjohnwu/Magisk) (minimal v24.0)
2. Aktifkan fitur Zygisk di pengaturan Magisk
3. Download modul dari halaman [Releases](https://github.com/yourusername/fingerprint-hardware-bypasser/releases)
4. Install modul melalui Magisk Manager (Menu Modules > Install from storage)
5. Restart perangkat
6. Setelah restart, deteksi hardware fingerprint akan selalu mengembalikan nilai true

## Cara Build

### Metode 1: Build Manual

1. Install Android NDK
2. Clone repository ini
3. Masuk ke direktori `jni`
4. Jalankan perintah: `ndk-build`
5. File .so akan dihasilkan di direktori `libs/`

### Metode 2: GitHub Actions

Modul ini secara otomatis di-build menggunakan GitHub Actions. Untuk menggunakan fitur ini:

1. Fork repository ini
2. Buka halaman Actions di repository fork Anda
3. Jalankan workflow "Build Zygisk Module"
4. Download artifact yang dihasilkan

## Cara Kerja

Modul ini bekerja dengan:

1. Mem-hook metode deteksi hardware fingerprint di kelas `FingerprintServiceStubImpl`
2. Mendeteksi versi Android dan menggunakan metode hook yang sesuai
3. Selalu mengembalikan nilai `true` saat aplikasi memeriksa keberadaan sensor sidik jari

## Peringatan

Penggunaan modul ini adalah untuk tujuan pendidikan dan pengembangan. Pengguna bertanggung jawab atas segala konsekuensi dari penggunaan modul ini.

## Lisensi

Proyek ini dilisensikan dibawah lisensi MIT - lihat file [LICENSE](LICENSE) untuk detail lebih lanjut.
