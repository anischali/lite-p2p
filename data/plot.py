import matplotlib.pyplot as plt

# By ChatGPT
# Data with key sizes
cipher_labels = [
    "ChaCha20 (256 bits)", "AES-128-CTR (128 bits)", "AES-128-CBC (128 bits)", "AES-192-CBC (192 bits)", 
    "AES-192-CTR (192 bits)", "AES-256-CBC (256 bits)", "AES-128-ECB (128 bits)", "AES-192-ECB (192 bits)", 
    "AES-256-CTR (256 bits)", "AES-256-ECB (256 bits)", "ChaCha20-Poly1305 (256 bits)", 
    "id-aes128-GCM (128 bits)", "id-aes192-GCM (192 bits)", "id-aes256-GCM (256 bits)", 
    "CAMELLIA-128-ECB (128 bits)", "CAMELLIA-128-CTR (128 bits)", "CAMELLIA-192-ECB (192 bits)", 
    "ARIA-128-CBC (128 bits)", "CAMELLIA-256-ECB (256 bits)", "CAMELLIA-192-CTR (192 bits)", 
    "ARIA-128-CTR (128 bits)", "ARIA-128-ECB (128 bits)", "CAMELLIA-256-CTR (256 bits)", 
    "ARIA-128-GCM (128 bits)", "ARIA-192-CBC (192 bits)", "ARIA-192-ECB (192 bits)", 
    "CAMELLIA-128-CBC (128 bits)", "ARIA-192-CTR (192 bits)", "ARIA-256-ECB (256 bits)", 
    "ARIA-256-CTR (256 bits)", "ARIA-256-CBC (256 bits)", "ARIA-192-GCM (192 bits)", 
    "ARIA-256-GCM (256 bits)", "CAMELLIA-256-CBC (256 bits)", "CAMELLIA-192-CBC (192 bits)"
]

encryption_times = [
    800, 841, 738, 767, 867, 814, 739, 775, 935, 830, 1014, 1295, 1331, 1398,
    3117, 4102, 3752, 3868, 3705, 4152, 4140, 4004, 4180, 4195, 4348, 4504,
    4778, 4770, 5143, 5134, 5142, 5051, 5837, 5974, 6054
]
decryption_times = [
    817, 904, 1036, 1049, 979, 1074, 1151, 1186, 1030, 1218, 1044, 1454, 1508,
    1574, 3251, 3600, 3957, 4091, 4427, 4052, 4229, 4416, 4364, 4438, 4835,
    4703, 4929, 5085, 4947, 5153, 5178, 5420, 5463, 6229, 6354
]

# Plotting with key sizes in labels
plt.figure(figsize=(14, 8))
bar_width = 0.4
x = range(len(cipher_labels))

plt.bar(x, encryption_times, width=bar_width, label="Encryption Time", color="skyblue", align="center")
plt.bar([p + bar_width for p in x], decryption_times, width=bar_width, label="Decryption Time", color="orange", align="center")

plt.xlabel("Cipher", fontsize=12)
plt.ylabel("Time (ms)", fontsize=12)
plt.title("Encryption and Decryption Times for Various Ciphers (1000 Iterations) By ChatGPT", fontsize=14)
plt.xticks([p + bar_width / 2 for p in x], cipher_labels, rotation=90, fontsize=10)
plt.legend(fontsize=12)
plt.tight_layout()
plt.grid(axis='y', linestyle='--', alpha=0.7)

plt.show()
