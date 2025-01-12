def make_rc5_key_schedule(key, word, rounds):
    """Создание ключевого расписания."""
    u = word // 8  # Длина слова в байтах
    c = max(1, (len(key) + u - 1) // u)  # Количество слов в ключе (округление вверх)
    b = len(key)

    L = [0] * c
    for i in range(b - 1, -1, -1):
        L[i // u] = (L[i // u] << 8) + key[i]

    # Создать таблицу
    t = 2 * (rounds + 1)
    P = 0xB7E15163
    Q = 0x9E3779B9
    Schedule = [(P + i * Q) & (2**word - 1) for i in range(t)]

    # Перемешивание
    i = j = 0
    A = B = 0
    for k in range(3 * max(t, c)):
        A = Schedule[i] = (
            (Schedule[i] + A + B) << 3 | (Schedule[i] + A + B) >> (word - 3)
        ) & (2**word - 1)
        B = L[j] = (
            (L[j] + A + B) << ((A + B) % word)
            | (L[j] + A + B) >> (word - (A + B) % word)
        ) & (2**word - 1)
        i = (i + 1) % t
        j = (j + 1) % c

    return Schedule


def rc5_encrypt(block, Schedule, word, rounds):
    """Шифрование блока данных."""
    A, B = block
    A = (A + Schedule[0]) & (2**word - 1)
    B = (B + Schedule[1]) & (2**word - 1)

    for i in range(1, rounds + 1):
        A = ((A ^ B) << (B % word) | (A ^ B) >> (word - (B % word))) & (2**word - 1)
        A = (A + Schedule[2 * i]) & (2**word - 1)
        B = ((B ^ A) << (A % word) | (B ^ A) >> (word - (A % word))) & (2**word - 1)
        B = (B + Schedule[2 * i + 1]) & (2**word - 1)

    return A, B


def rc5_decrypt(block, Schedule, word, rounds):
    """Расшифрование блока данных."""
    A, B = block

    for i in range(rounds, 0, -1):
        B = (B - Schedule[2 * i + 1]) & (2**word - 1)
        B = ((B >> (A % word)) | (B << (word - (A % word)))) & (2**word - 1)
        B = B ^ A
        A = (A - Schedule[2 * i]) & (2**word - 1)
        A = ((A >> (B % word)) | (A << (word - (B % word)))) & (2**word - 1)
        A = A ^ B

    B = (B - Schedule[1]) & (2**word - 1)
    A = (A - Schedule[0]) & (2**word - 1)

    return A, B







def encrypt_text_rc5(text, Schedule, block_size, word=32, rounds=12):
    """Шифрование текста целиком."""

    def pad_text(data, block_size):
        """Дополнение текста до размера блока."""
        padding_len = block_size - (len(data) % block_size)
        return data + bytes([padding_len] * padding_len)
    text=text.encode()
    padded_text = pad_text(text, block_size)
    encrypted_blocks = []
    for i in range(0, len(padded_text), block_size):
        block = padded_text[i : i + block_size]
        A, B = int.from_bytes(block[: block_size // 2], "big"), int.from_bytes(
            block[block_size // 2 :], "big"
        )
        encrypted_A, encrypted_B = rc5_encrypt((A, B), Schedule, word, rounds)
        encrypted_blocks.append(
            encrypted_A.to_bytes(block_size // 2, "big")
            + encrypted_B.to_bytes(block_size // 2, "big")
        )
    return b"".join(encrypted_blocks)


def decrypt_text_rc5(encrypted_text, Schedule, block_size, word=32, rounds=12):
    """Расшифровка текста целиком."""
    decrypted_blocks = []
    for i in range(0, len(encrypted_text), block_size):
        block = encrypted_text[i : i + block_size]
        A, B = int.from_bytes(block[: block_size // 2], "big"), int.from_bytes(
            block[block_size // 2 :], "big"
        )
        decrypted_A, decrypted_B = rc5_decrypt((A, B), Schedule, word, rounds)
        decrypted_blocks.append(
            decrypted_A.to_bytes(block_size // 2, "big")
            + decrypted_B.to_bytes(block_size // 2, "big")
        )
    decrypted_text = b"".join(decrypted_blocks)
    return decrypted_text[: -decrypted_text[-1]].decode('utf-8')


# Параметры RC5

if __name__ =='__main__':
    word = 32  # Размер слова
    rounds = 12  # Количество раундов
    block_size = 8  # Размер блока в байтах (64 бита)
    key = b"SECRETKEY"
# Генерация ключевого расписания
    Schedule = make_rc5_key_schedule(key, word, rounds)

    # Исходный текст
    plaintext = "Example text"

    # Шифрование
    encrypted_text = encrypt_text_rc5(plaintext, Schedule, block_size, word, rounds)
    print(f"Зашифрованный текст: {encrypted_text}")

    # Расшифровка
    decrypted_text = decrypt_text_rc5(encrypted_text, Schedule, block_size, word, rounds)
    print(f"Расшифрованный текст: {decrypted_text}")
