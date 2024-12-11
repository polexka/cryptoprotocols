import { Injectable } from '@angular/core';
import * as forge from 'node-forge';

@Injectable({
  providedIn: 'root',
})
export class CryptoService {
  // Генерация AES-ключа
  generateAESKey(): string {
    const key = forge.random.getBytesSync(32); // 256-битный AES-ключ
    return forge.util.encode64(key); // Возвращаем ключ в формате Base64
  }

  // Шифрование сообщения с использованием AES
  encryptAES(message: string, key: string): string {
    const aesKey = forge.util.decode64(key); // Декодируем AES-ключ из Base64
    const iv = forge.random.getBytesSync(16); // Генерируем IV (инициализационный вектор)
    const cipher = forge.cipher.createCipher('AES-CBC', aesKey); // Создаем AES-шифр
    cipher.start({ iv });
    cipher.update(forge.util.createBuffer(message, 'utf8'));
    cipher.finish();

    // Возвращаем IV и зашифрованное сообщение, закодированные в Base64
    return (
      forge.util.encode64(iv) +
      ':' +
      forge.util.encode64(cipher.output.getBytes())
    );
  }

  // Дешифрование сообщения с использованием AES
  decryptAES(encryptedMessage: string, key: string): string {
    const aesKey = forge.util.decode64(key); // Декодируем AES-ключ из Base64
    const [ivBase64, encryptedBase64] = encryptedMessage.split(':'); // Разделяем IV и данные
    const iv = forge.util.decode64(ivBase64); // Декодируем IV из Base64
    const encryptedBytes = forge.util.decode64(encryptedBase64); // Декодируем зашифрованные данные из Base64

    const decipher = forge.cipher.createDecipher('AES-CBC', aesKey); // Создаем AES-дешифратор
    decipher.start({ iv });
    decipher.update(forge.util.createBuffer(encryptedBytes));
    const success = decipher.finish();

    if (!success) {
      throw new Error('Failed to decrypt AES message');
    }

    return decipher.output.data; // Возвращаем расшифрованное сообщение
  }

  // Генерация пары RSA-ключей
  generateRSAKeys(): { publicKey: string; privateKey: string } {
    const { publicKey, privateKey } = forge.pki.rsa.generateKeyPair(2048);
    return {
      publicKey: forge.pki.publicKeyToPem(publicKey),
      privateKey: forge.pki.privateKeyToPem(privateKey),
    };
  }

  // Подпись сообщения с помощью RSA
  signMessage(message: string, privateKey: string): string {
    const privateKeyForge = forge.pki.privateKeyFromPem(privateKey);
    const md = forge.md.sha256.create();
    md.update(message, 'utf8');
    return forge.util.encode64(privateKeyForge.sign(md)); // Подпись в формате Base64
  }

  // Шифрование AES-ключа с использованием открытого ключа RSA
  encryptAESKeyWithRSA(aesKey: string, publicKey: string): string {
    const publicKeyForge = forge.pki.publicKeyFromPem(publicKey);
    const encryptedKey = publicKeyForge.encrypt(
      forge.util.decode64(aesKey),
      'RSA-OAEP'
    );
    return forge.util.encode64(encryptedKey); // Закодировать в Base64 перед отправкой
  }
}
