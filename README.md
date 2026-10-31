# CAPTCHA Guard — Backend

Backend API проекта CAPTCHA Guard на ASP.NET Core 8. Сервер получает CAPTCHA-токен от frontend, проверяет его через Cloudflare Turnstile Siteverify API и возвращает защищённое сообщение только после успешной валидации.

## Технологии

- C#
- .NET 8 / ASP.NET Core Minimal API
- `HttpClient` для обращения к Cloudflare Siteverify API
- Конфигурация через настройки ASP.NET Core и переменные окружения

## API

| Метод | Маршрут | Назначение |
|---|---|---|
| `GET` | `/api/health` | Проверка доступности сервера |
| `GET` | `/api/captcha/config` | Получение публичного site key и статуса конфигурации |
| `POST` | `/api/captcha/verify` | Серверная проверка Turnstile-токена |

При обработке `/api/captcha/verify` backend отправляет `secret` и `response` в Cloudflare Siteverify. При наличии IP клиента он также передаётся как `remoteip`. После ответа Cloudflare backend проверяет `success`, при настроенном значении — `hostname`, а также ожидаемое действие `reveal_secret`. При успешной проверке API возвращает защищённое сообщение.
