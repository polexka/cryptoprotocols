import express, { Request, Response } from "express";
import bodyParser from "body-parser";
import { generateRSAKeys, decryptAES, verifySignature } from "./crypto-utils";
import crypto from "crypto";

const app = express();
const cors = require('cors');

app.use(bodyParser.json());

app.use(cors({
  origin: 'http://localhost:4200',
  methods: ['GET', 'POST'],
}))
// RSA-ключи сервера
const serverKeys = generateRSAKeys();

// Маршрут: получение открытого ключа сервера
app.get("/rsa/public-key", (_req: Request, res: Response) => {
  console.log("---------------------- RSA REQUEST ----------------------");
  res.json({ publicKey: serverKeys.publicKey });
  console.log("Send RSA Public Key as response");
  
  console.log("---------------------- END REQUEST ----------------------");
});

// Маршрут: прием зашифрованного сообщения
app.post("/message", (req: express.Request, res: express.Response): any => {
  console.log("---------------------- GOT REQUEST ----------------------");

  const { encryptedMessage, encryptedAESKey, signature, clientPublicKey } =
    req.body;

  console.log("Succcesfully read Request body");

  if (!encryptedMessage || !encryptedAESKey || !signature || !clientPublicKey) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    // Дешифруем AES-ключ с помощью закрытого ключа сервера
    const aesKey = crypto.privateDecrypt(
      {
        key: serverKeys.privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, // Используем RSA-OAEP
      },
      Buffer.from(encryptedAESKey, "base64") // Используем Base64 для дешифровки
    );

    console.log("Succcesfully decrypted AES Key, AES length: ", aesKey.length);

    // Дешифруем сообщение с использованием AES-ключа
    const decryptedMessage = decryptAES(encryptedMessage, aesKey);

    console.log("Succcesfully decrypted message");

    // Проверяем подпись
    const isSignatureValid = verifySignature(
      encryptedMessage,
      signature,
      clientPublicKey
    );

    if (!isSignatureValid) {
      return res.status(400).json({ error: "Invalid signature" });
    }

    console.log("Succcesfully verified signature");

    res.json({ message: decryptedMessage });

    console.log("Send response");
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "Decryption or verification failed" });
  }

  console.log("---------------------- END REQUEST ----------------------");
});

// Запуск сервера
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
