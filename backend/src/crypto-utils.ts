import crypto from "crypto";

/**
 * Генерация пары RSA-ключей
 */
export const generateRSAKeys = (): {
  publicKey: string;
  privateKey: string;
} => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  return { publicKey, privateKey };
};

/**
 * Шифрование сообщения с использованием AES
 */
export const encryptAES = (message: string, key: Buffer): string => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  let encrypted = cipher.update(message, "utf8", "hex");
  encrypted += cipher.final("hex");
  return iv.toString("hex") + encrypted;
};

/**
 * Дешифрование сообщения с использованием AES
 */
export const decryptAES = (encryptedMessage: string, key: Buffer): string => {
  const [ivBase64, encryptedBase64] = encryptedMessage.split(":"); // Разделяем IV и зашифрованное сообщение
  const iv = Buffer.from(ivBase64, "base64"); // Декодируем IV из Base64
  const encrypted = Buffer.from(encryptedBase64, "base64"); // Декодируем зашифрованное сообщение

  console.log(encryptedMessage);
  console.log(key, iv);

  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv); // Используем AES-256-CBC

  let decrypted = decipher.update(encrypted);
  decrypted = Buffer.concat([decrypted, decipher.final()]);

  return decrypted.toString("utf-8");
};

/**
 * Подписание сообщения с использованием RSA
 */
export const signMessage = (message: string, privateKey: string): string => {
  const sign = crypto.createSign("SHA256");
  sign.update(message);
  sign.end();
  return sign.sign(privateKey, "hex");
};

/**
 * Проверка подписи
 */
export const verifySignature = (
  message: string,
  signature: string,
  publicKey: string
): boolean => {
  const verify = crypto.createVerify("SHA256");
  verify.update(message);
  verify.end();
  return verify.verify(publicKey, Buffer.from(signature, "base64"));
};
