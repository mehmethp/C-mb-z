def save_report(url, results_dict):
    from datetime import datetime

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"CIMBIZ_REPORT_{timestamp}.txt"
    content = []

    content.append("🕵️ Cımbız Güvenlik Açığı Tarama Raporu")
    content.append(f"Taranan URL: {url}")
    content.append(f"Tarih: {timestamp}")
    content.append("-" * 50 + "\n")

    for module_name, results in results_dict.items():
        content.append(f"🔍 {module_name}:")
        if results:
            for item in results:
                content.append(f"⚠️ {item}")
        else:
            content.append("✅ Açık bulunamadı.")
        content.append("-" * 40 + "\n")

    full_report = "\n".join(content)

    # Dosyaya kaydet
    with open(filename, "w", encoding="utf-8") as f:
        f.write(full_report)

    return filename, full_report  # filename: kaydedilen dosya adı, full_report: indirme için içerik
