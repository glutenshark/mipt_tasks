from crypt import *
import random 
test_word = 32  # Размер слова
test_rounds = 12  # Количество раундов
test_block_size = 8  # Размер блока в байтах (64 бита)
test_key = b"SECRETKEY"
test_Schedule = make_rc5_key_schedule(test_key, test_word, test_rounds)


# Выдает один и тот же шифр на 2 одинаковые строки
def case1():
    test_word1 = str(random.randint(1,1000))
    test_word2 = test_word1
    assert test_word1 == test_word2
    assert encrypt_text_rc5(test_word1,test_Schedule,block_size=test_block_size,word=test_word,rounds=test_rounds) == encrypt_text_rc5(test_word2,test_Schedule,block_size=test_block_size,word=test_word,rounds=test_rounds)


# Выдает 2 разных шифра при похожих словах
def case2():
    test_word1 = random.randint(1,1000)
    test_word2 = test_word1 + 1 
    test_word1=str(test_word1)
    test_word2=str(test_word2)
    assert test_word1 != test_word2
    assert encrypt_text_rc5(test_word1,test_Schedule,block_size=test_block_size,word=test_word,rounds=test_rounds) != encrypt_text_rc5(test_word2,test_Schedule,block_size=test_block_size,word=test_word,rounds=test_rounds)


# Расшифровка совпадает с исходным сообщением
def case3():
    test_word1 = str(random.randint(1,1000))
    encrypted_test_word = encrypt_text_rc5(test_word1,test_Schedule,block_size=test_block_size,word=test_word,rounds=test_rounds)
    decrypted_test_word = decrypt_text_rc5(encrypted_test_word, test_Schedule, test_block_size, test_word, test_rounds)
    assert test_word1 == decrypted_test_word

case1()
case2()
case3()
