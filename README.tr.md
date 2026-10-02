# PS5 Portal High Bitrate - Türkçe

**Yeni deneysel sürüm: Windows / Linux otomasyon + isteğe bağlı Proxmox / Docker kurulumu.** [v0.3.0-preview.3 indir](https://github.com/atameric/ps5-portal-high-bitrate/releases/tag/v0.3.0-preview.3) | [Adım adım otomatik kurulum](AUTOMATION.tr.md) | [Container kılavuzu (EN)](deploy/README.md). SDNick484, Alpine LXC/OpenRC ve Linux Docker macvlan paketlemesini ekledi. Windows otomasyonu fiziksel doğrulama bekliyor; Linux/Pi yeniden başlatma ve yeni bağlantı, Proxmox için gerçek cihaz başarı raporları var. Docker yalnız sahte ağ uçlarıyla test edildi. Proxmox kurulumundan önce kart firewall'u kapsamını oku. Mac mini prototipi kullanıcı tarafından doğrulandı; yeni ortak uygulama ayrıca platform testi gerektiriyor. Aşağıdaki eski kurulum adımları macOS elle başlatıcı içindir.

Mac üzerinden kendi PS5 ve Portal cihazların için **geçici yüksek bitrate isteği**. Çalışan prototip Portal 7.1.7 üzerinde denendi. Her firmware ve ağda çalışması garanti değil. Public paketleme çevrimdışı test edildi; başka cihazlarda canlı doğrulama bekliyor.

- 65 Mbps hedefinde PS5 yaklaşık 63 Mbps bildirdi; kullanıcı Portal'da 58 Mbps gördü.
- 100 Mbps hedefinde PS5 yaklaşık 97 Mbps bildirdi; kullanıcı 84 Mbps civarı gördü.
- 200 Mbps deneyinde PS5 önce 166,141, sonra yaklaşık 158,3 Mbps hedef bildirdi. Gerçek sürekli 200 Mbps doğrulanmadı.
- 200 profilinde üç kez art arda en az 160 Mbps hedef beklenir. İlk deneme 158 civarında kaldığı için kod 1 verdi; bu, bağlantı başarısız demek değildir.
- Bunlar sürekli hız veya gecikme garantisi değildir.
- 4K deneyi 720p'ye düştü. Bu pakette 4K seçeneği yok; çalışan seçenek 1080p yüksek bitrate.

## Kurulum

1. Python 3.10+ kurulu Mac'te projeyi indir veya klonla.
2. `Setup.command` aç. Bağımlılıklar yerel `.venv` klasörüne kurulur.
3. `config.json` içindeki örnek IP'leri kendi PS5 ve Portal adreslerinle değiştir; Mac ağ arayüzünü yaz. `networksetup -listallhardwareports` ile arayüzü bulabilirsin.
4. Cihazlar aynı yerel ağda olmalı. Konuk ağı/istemci izolasyonu olmamalı. PS5 için Ethernet tercih et.

## Kullanım

1. Portal'ın PS5 bağlantısını kes; PS5 açık kalsın.
2. `Start.command` aç, 65, 100 veya deneysel 200 seç, Enter'a bas. Parolayı yalnız Mac'in sudo istemine gir.
3. **READY** mesajından sonra Portal'dan bağlan.
4. `Startup packet modified` ve ardından hedef doğrulamasını bekle.
5. Program ağ yolunu geri yükleyince Mac aradan çıkar. Aynı oturumda yeniden çalıştırman gerekmez.

Kalıcı cihaz değişikliği yapılmaz. Her yeni oturumda işlem gerekir. Normal ayara dönmek için bağlantıyı kapatıp başlatıcı olmadan yeniden bağlan.

65/100/200 seçimini aynı hareketli sahnede karşılaştır. Yüksek bitrate daha fazla ağ yükü oluşturabilir; daha düşük gecikme garantisi yok. Mevcut ekran 1080p kalır.

## Sonuçlar ve hatalar

- `NOT APPLIED`: yeni başlangıç paketi yakalanmadı, değişiklik yapılmadı.
- `UNCONFIRMED`: paket değişti ama yüksek hedef doğrulanmadı.
- `restoration_errors`: boş olmalı. Hata varsa [İngilizce kurtarma adımlarını](README.md#troubleshooting-and-recovery) uygula.

Aktarma en fazla 40 saniye; başlangıç ve temizleme ek süre alabilir. Ayrı kurtarma süreci 55 saniye sonra özgün ağ ayarlarını geri yüklemeyi dener. Mac kapanırsa kurtarma çalışamaz.

Özel IP'ler, raporlar ve ham paket kayıtları yerel kalır. Ham kayıtları GitHub'a yükleme. Bu araç jailbreak değildir; Sony ile bağlantısı yoktur.


Linux kullanıcı raporu: [tissee](https://www.reddit.com/r/PlaystationPortal/comments/1wtyglf/comment/pd2k5ls/), EndeavourOS ve Ethernet bağlı Raspberry Pi OS / Pi 3B üzerinde başarı bildirdi. Pi yeniden başlatma, yeni Portal bağlantısı ve PS5 dinlenme modundan açılırken 100 Mbps profili de çalışmış. Docker/IPv4 forwarding notu ve kalan testler [otomasyon kılavuzunda](AUTOMATION.tr.md). Bu rapor gerçek sürekli bitrate veya giriş gecikmesi ölçümü değildir.

## Projeyi destekle

☕ **Projeyi destekle:** Proje ve APK ücretsiz ve açık kaynak olarak kalacak. Geliştirme ve test çalışmalarının devamına destek olmak istersen buradan bana bir kahve ısmarlayabilirsin: [https://buymeacoffee.com/atameric](https://buymeacoffee.com/atameric) ❤️
