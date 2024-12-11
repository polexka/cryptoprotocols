import { Component, inject } from '@angular/core';
import { CryptoService } from './crypto.service';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { catchError, delay, Observable, of, switchMap, tap } from 'rxjs';
import { FormsModule } from '@angular/forms';
import { JsonPipe } from '@angular/common';

type CryptResponse = { message: string };

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [FormsModule, JsonPipe],
  templateUrl: './app.component.html',
})
export class AppComponent {
  private readonly cryptoService = inject(CryptoService);
  private readonly http = inject(HttpClient);

  private readonly baseUrl = 'http://localhost:3000';

  public message = 'Hello, world!';
  public loading = false;
  public error = false;

  public loadingLog: string[] = [];

  public response: CryptResponse | null = null;

  send() {
    this.loading = true;
    this.loadingLog = [];
    this.loadingLog.push('Запрашиваю RSA Public Key');
    this.http
      .get<{ publicKey: string }>(`${this.baseUrl}/rsa/public-key`)
      .pipe(
        tap(({ publicKey }) => {
          this.loadingLog.push('Получен RSA Public Key:');
          this.loadingLog.push(publicKey);
        }),
        switchMap(({ publicKey }) => this.encryptMessage(publicKey)),
        catchError((err: HttpErrorResponse) => {
          this.loadingLog.push('Произошла ошибка! Попробуйте снова');
          this.loadingLog.push('Текст ошибки:', err.error);
          this.loading = false;
          return of();
        })
      )
      .subscribe((res) => {
        this.loading = false;
        this.response = res;
      });
  }

  encryptMessage(publicKey: string): Observable<CryptResponse> {
    this.loadingLog.push('Генерация ключа AES');
    // Генерация ключа AES
    const aesKey = this.cryptoService.generateAESKey();
    this.loadingLog.push('Успех');

    this.loadingLog.push('Шифрование сообщения с использованием AES');
    // Шифрование сообщения с использованием AES
    const encryptedMessage = this.cryptoService.encryptAES(
      this.message,
      aesKey
    );
    this.loadingLog.push('Успех');

    this.loadingLog.push('Шифрование AES-ключа с использованием RSA');
    // Шифрование AES-ключа с использованием RSA
    const encryptedAESKey = this.cryptoService.encryptAESKeyWithRSA(
      aesKey,
      publicKey
    );
    this.loadingLog.push('Успех');

    this.loadingLog.push('Подпись сообщения с использованием RSA');
    // Подпись сообщения с использованием RSA
    const rsaKeys = this.cryptoService.generateRSAKeys();
    const signature = this.cryptoService.signMessage(
      encryptedMessage,
      rsaKeys.privateKey
    );
    this.loadingLog.push('Успех');

    this.loadingLog.push('Отправка данных на сервер');
    // Отправка данных на сервер
    return this.http
      .post<CryptResponse>(`${this.baseUrl}/message`, {
        encryptedMessage: encryptedMessage,
        encryptedAESKey: encryptedAESKey,
        signature: signature,
        clientPublicKey: rsaKeys.publicKey,
      })
      .pipe(
        tap(() => {
          this.loadingLog.push('Жду ответ...');
        }),
        delay(4000)
      );
  }
}
