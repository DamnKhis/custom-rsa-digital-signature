import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib
import random
import sys
import os

# ----------------------------------------------------------------------
# 1. Основные фукции
# ----------------------------------------------------------------------

sys.setrecursionlimit(2000)

# 1. КРИПТОГРАФИЧЕСКИЕ ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
def power(a: int, d: int, n: int) -> int:
    """Эффективное модульное возведение в степень: (a^d) mod n."""
    res = 1
    a = a % n
    while d > 0:
        if d & 1:
            res = (res * a) % n
        d = d >> 1
        a = (a * a) % n
    return res


def is_prime_miller_rabin(n: int, k: int = 40) -> bool:
    """Тест Миллера-Рабина для надежной проверки простоты."""
    if n <= 1 or n == 4: return False
    if n <= 3: return True
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = power(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = power(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_large_prime(bits: int) -> int:
    """Генерирует простое число заданной битовой длины, используя тест Миллера-Рабина."""
    min_val = 1 << (bits - 1)
    while True:
        p = random.randrange(min_val + 1, (1 << bits) - 1, 2)
        if is_prime_miller_rabin(p):
            return p


def gcd(a, b):
    """Нахождение НОД (Наибольшего Общего Делителя)."""
    while b:
        a, b = b, a % b
    return a


def modular_inverse(e, phi_n):
    """Вычисление модульного обратного (d)."""
    try:
        d = pow(e, -1, phi_n)
        return d
    except ValueError:
        return None


# 2. ГЕНЕРАЦИЯ ГАРАНТИРОВАННЫХ P И Q
def find_guaranteed_primes(length_in_bytes: int) -> tuple[int, int]:
    """Генерирует p и q, гарантируя n > 2^(length_in_bytes * 8)."""
    min_bit_length_n = (length_in_bytes * 8)
    target_bit_length_n = min_bit_length_n + 1
    buffer_bits = 8
    p_q_target_length = target_bit_length_n + buffer_bits
    bit_length_p = (p_q_target_length + 1) // 2
    bit_length_q = p_q_target_length // 2

    p = generate_large_prime(bit_length_p)
    q = generate_large_prime(bit_length_q)
    return p, q


# 3. ГЕНЕРАЦИЯ КЛЮЧЕЙ
def generate_keypair(p, q):
    """Генерирует публичный и приватный ключ RSA."""
    if not (is_prime_miller_rabin(p) and is_prime_miller_rabin(q)):
        raise ValueError('Оба числа p и q должны быть простыми.')
    if p == q:
        raise ValueError('Числа p и q не должны быть равны.')

    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = random.randrange(2, phi_n)
    while gcd(e, phi_n) != 1:
        e = random.randrange(2, phi_n)

    d = modular_inverse(e, phi_n)

    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key


# 4. ШИФРОВАНИЕ И РАСШИФРОВАНИЕ 
def encrypt(public_key, plaintext):
    """C = M^e mod n (Используется для ПРОВЕРКИ ПОДПИСИ)"""
    e, n = public_key
    ciphertext = pow(plaintext, e, n)
    return ciphertext


def decrypt(private_key, ciphertext):
    """M = C^d mod n (Используется для СОЗДАНИЯ ПОДПИСИ)"""
    d, n = private_key
    plaintext = pow(ciphertext, d, n)
    return plaintext


# ----------------------------------------------------------------------
# 2. Вспомогательные функции для работы с файлами и хэшами
# ----------------------------------------------------------------------

def hash_file_sha256(filepath):
    """Вычисляет SHA-256 хэш файла и возвращает его как целое число."""
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as file:
        while chunk := file.read(4096):
            hasher.update(chunk)
    # Возвращаем хэш в виде целого числа
    return int(hasher.hexdigest(), 16)


def int_to_hex_string(integer):
    """Преобразует большое целое число в шестнадцатеричную строку."""
    hex_string = f'{integer:x}'
    if len(hex_string) % 2 != 0:
        hex_string = '0' + hex_string
    return hex_string


def hex_string_to_int(hex_string):
    """Преобразует шестнадцатеричную строку в целое число."""
    return int(hex_string, 16)


# ----------------------------------------------------------------------
# 3. Класс GUI-приложения
# ----------------------------------------------------------------------

class RSA_Signature_App:
    def __init__(self, master):
        self.master = master
        master.title("Инструмент цифровой подписи RSA")

        self.public_key = None
        self.private_key = None
        self.file_path = None


        self.key_size_var = tk.StringVar(master, value="2048")
        self.keys_saved = False


        key_frame = tk.LabelFrame(master, text="1. Генерация и сохранение ключей")
        key_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        tk.Label(key_frame, text="Размер ключа (бит):").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        tk.Entry(key_frame, textvariable=self.key_size_var, width=10).grid(row=0, column=1, padx=5, pady=5, sticky="w")

        self.generate_btn = tk.Button(key_frame, text="Генерировать и сохранить ключи",
                                      command=self.generate_and_save_keys)
        self.generate_btn.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="ew")


        file_frame = tk.LabelFrame(master, text="2. Выбор файла для подписи/проверки")
        file_frame.grid(row=1, column=0, padx=10, pady=10, sticky="ew")

        self.file_label = tk.Label(file_frame, text="Файл не выбран.")
        self.file_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        tk.Button(file_frame, text="Выбрать файл", command=self.select_file).grid(row=0, column=1, padx=5, pady=5,
                                                                                  sticky="ew")

        sign_frame = tk.LabelFrame(master, text="3. Создание цифровой подписи")
        sign_frame.grid(row=2, column=0, padx=10, pady=10, sticky="ew")

        tk.Button(sign_frame, text="Создать подпись (.sig)", command=self.create_signature).grid(row=0, column=0,
                                                                                                 padx=5, pady=5,
                                                                                                 sticky="ew")

        verify_frame = tk.LabelFrame(master, text="4. Проверка цифровой подписи")
        verify_frame.grid(row=3, column=0, padx=10, pady=10, sticky="ew")

        tk.Button(verify_frame, text="Проверить подпись", command=self.verify_signature).grid(row=0, column=0, padx=5,
                                                                                              pady=5, sticky="ew")

    def generate_and_save_keys(self):
        """Генерирует ключи RSA и сохраняет их в файлы (private.key и public.key)."""
        try:
            bits = int(self.key_size_var.get())
            if bits < 512 or bits > 4096 or bits % 8 != 0:
                messagebox.showerror("Ошибка", "Размер ключа должен быть от 512 до 4096 бит и кратен 8.")
                return

            required_bytes = 32

            p, q = find_guaranteed_primes(required_bytes)

            self.public_key, self.private_key = generate_keypair(p, q)

            e, n = self.public_key
            d, n_d = self.private_key

            with open("public.key", "w") as f:
                f.write(f"e={e}\n")
                f.write(f"n={n}\n")

            with open("private.key", "w") as f:
                f.write(f"d={d}\n")
                f.write(f"n={n_d}\n")

            self.keys_saved = True
            messagebox.showinfo("Успех", "Ключи успешно сгенерированы и сохранены в public.key и private.key.")
            self.generate_btn.config(text="Ключи сгенерированы и сохранены", state=tk.DISABLED)

        except Exception as e:
            messagebox.showerror("Ошибка генерации", f"Произошла ошибка: {e}")

    def select_file(self):
        """Открывает диалог для выбора файла."""
        filepath = filedialog.askopenfilename(title="Выберите файл для подписи/проверки")
        if filepath:
            self.file_path = filepath
            self.file_label.config(text=f"Выбран: {os.path.basename(filepath)}")
        else:
            self.file_path = None
            self.file_label.config(text="Файл не выбран.")

    def create_signature(self):
        """Создает цифровую подпись для выбранного файла."""
        if not self.keys_saved or not self.private_key:
            messagebox.showwarning("Предупреждение", "Сначала сгенерируйте и сохраните ключи.")
            return
        if not self.file_path:
            messagebox.showwarning("Предупреждение", "Сначала выберите файл для подписи.")
            return

        try:
            data_hash_int = hash_file_sha256(self.file_path)

            signature_int = decrypt(self.private_key, data_hash_int)

            signature_hex = int_to_hex_string(signature_int)
            signature_filename = self.file_path + ".sig"

            with open(signature_filename, "w") as f:
                f.write(signature_hex)

            messagebox.showinfo("Успех", f"Подпись успешно создана и сохранена в:\n{signature_filename}")

        except Exception as e:
            messagebox.showerror("Ошибка подписи", f"Произошла ошибка: {e}")

    def verify_signature(self):
        """Проверяет подпись выбранного файла."""
        if not self.file_path:
            messagebox.showwarning("Предупреждение", "Сначала выберите файл для проверки.")
            return
        try:
            with open("public.key", "r") as f:
                lines = f.readlines()
                e = int(lines[0].strip().split('=')[1])
                n = int(lines[1].strip().split('=')[1])
                public_key = (e, n)
        except FileNotFoundError:
            messagebox.showerror("Ошибка", "Файл public.key не найден. Сначала сгенерируйте ключи.")
            return
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка чтения public.key: {e}")
            return

        signature_filename = self.file_path + ".sig"
        try:
            with open(signature_filename, "r") as f:
                signature_hex = f.read().strip()
                signature_int = hex_string_to_int(signature_hex)
        except FileNotFoundError:
            messagebox.showerror("Ошибка", f"Файл подписи {signature_filename} не найден.")
            return
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка чтения файла подписи: {e}")
            return

        try:
            original_data_hash_int = hash_file_sha256(self.file_path)
            check_hash_int = encrypt(public_key, signature_int)

            if check_hash_int == original_data_hash_int:
                messagebox.showinfo("Результат", "✅ Подпись действительна! Файл не был изменен.")
            else:
                messagebox.showwarning("Результат",
                                       "❌ Подпись недействительна! Файл был изменен или использован неверный ключ.")

        except Exception as e:
            messagebox.showerror("Ошибка проверки", f"Произошла ошибка: {e}")


# ----------------------------------------------------------------------
# 4. Запуск приложения 
# ----------------------------------------------------------------------
if __name__ == '__main__':
    root = tk.Tk()
    app = RSA_Signature_App(root)
    root.mainloop()