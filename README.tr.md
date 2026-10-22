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
3. `Start.command` ile İngilizce terminal sihirbazını aç. PS5 ve Portal IPv4 adreslerini gir, Mac ağ arayüzünü kontrol et ve bitrate profilini seç. Mevcut adresler otomatik doldurulur; sihirbaz `config.json` dosyasını yerel olarak kaydeder. IP adreslerini yönlendiricinin bağlı cihazlar listesinden bulabilirsin.
4. Cihazlar aynı yerel ağda olmalı. Konuk ağı/istemci izolasyonu olmamalı. PS5 için Ethernet tercih et.

## Kullanım

1. Portal'ın PS5 bağlantısını kes; PS5 açık kalsın.
2. `Start.command` aç. Parolayı yalnız Mac'in sudo istemine gir. Vurgulanan ön koşulları ve düzenlenebilir cihaz adreslerini kontrol et; ilk deneme için 65 Mbps seç. Tab veya yukarı/aşağı tuşları alanı, sağ/sol veya boşluk tuşu profili seçer. Yazarak seçili değeri değiştirebilirsin.
3. **WAIT** sırasında Portal bağlantısı kesik kalsın. Yeşil **READY / CONNECT NOW** mesajından sonra Portal'dan bağlan. Ekrandaki **02:00** ile başlayan **120 saniyelik geri sayım** bağlantı süresini gösterir.
4. Başlangıç paketi değiştiğinde hedefi doğrulamak için en fazla 15 saniye daha beklenir. Üç yüksek hedef bildirimi gelirse doğrudan ağ yolu hemen geri yüklenir.
5. **Ready to play**, hedef doğrulaması, yerel paket çıkışı doğrulaması ve hatasız geri yükleme gerektirir. Q/Esc ile çıkabilir, Enter ile yeni bir deneme başlatabilirsin. Deneme sırasında Q, Esc veya Ctrl-C ağın geri yüklenmesini başlatır. Kurtarma hatası varsa yeni deneme düğmesi devre dışı kalır; D ayrıntıları gösterir.

Terminalden açmak için: `sudo .venv/bin/python portal_tui.py`. Ağ veya yapılandırma değişikliği yapmadan önizleme: `.venv/bin/python portal_tui.py --demo`. En az 72 sütun ve 24 satırlık terminal gerekir; yeni bağımlılık gerekmez.

Hazırlık, bağlantıya hazır olma ve sonuç durumları farklı işaretler ve kısa animasyonlarla gösterilir. Hareketi kapatmak için `--no-animations` ekle; durum etiketleri ve vurgular korunur. Animasyonlar ağ aktarımını duraklatmaz.

Kalıcı cihaz değişikliği yapılmaz. Her yeni oturumda işlem gerekir. Normal ayara dönmek için bağlantıyı kapatıp başlatıcı olmadan yeniden bağlan.

65/100/200 seçimini aynı hareketli sahnede karşılaştır. Yüksek bitrate daha fazla ağ yükü oluşturabilir; daha düşük gecikme garantisi yok. Mevcut ekran 1080p kalır.

## Sonuçlar ve hatalar

- `NOT APPLIED`: yeni başlangıç paketi yakalanmadı, değişiklik yapılmadı.
- `UNCONFIRMED`: paket değişti ama yüksek hedef doğrulanmadı.
- `restoration_errors`: boş olmalı. Hata varsa [İngilizce kurtarma adımlarını](README.md#troubleshooting-and-recovery) uygula.

Sihirbazda 5 saniyelik hazırlıktan sonra tam 120 saniyelik bağlantı süresi ve ilk değiştirilen paketten sonra en fazla 15 saniyelik doğrulama süresi vardır. Ayrı kurtarma süreci 155 saniye sonra özgün ağ ayarlarını geri yüklemeyi dener. Eski `portal_active_probe.py` komutunun varsayılan 40 saniyelik aktarma ve 55 saniyelik kurtarma süreleri korunur. Başlangıç ve temizleme ek süre alabilir. Mac kapanırsa kurtarma çalışamaz.

Özel IP'ler, raporlar ve ham paket kayıtları yerel kalır. Ham kayıtları GitHub'a yükleme. Bu araç jailbreak değildir; Sony ile bağlantısı yoktur.


Linux kullanıcı raporu: [tissee](https://www.reddit.com/r/PlaystationPortal/comments/1wtyglf/comment/pd2k5ls/), EndeavourOS ve Ethernet bağlı Raspberry Pi OS / Pi 3B üzerinde başarı bildirdi. Pi yeniden başlatma, yeni Portal bağlantısı ve PS5 dinlenme modundan açılırken 100 Mbps profili de çalışmış. Docker/IPv4 forwarding notu ve kalan testler [otomasyon kılavuzunda](AUTOMATION.tr.md). Bu rapor gerçek sürekli bitrate veya giriş gecikmesi ölçümü değildir.

## Projeyi destekle

☕ **Projeyi destekle:** Proje ve APK ücretsiz ve açık kaynak olarak kalacak. Geliştirme ve test çalışmalarının devamına destek olmak istersen buradan bana bir kahve ısmarlayabilirsin: [https://buymeacoffee.com/atameric](https://buymeacoffee.com/atameric) ❤️
