# ICAP Spring Boot Starter

Spring Boot **3.5.14** стартер с готовым клиентом для протокола
**ICAP (Internet Content Adaptation Protocol)** в соответствии с
[RFC 3507](https://www.rfc-editor.org/rfc/rfc3507).

ICAP чаще всего используется для передачи контента внешнему сервису адаптации —
**антивирусной проверки, DLP или фильтрации содержимого** (Symantec Protection
Engine, McAfee Web Gateway, Kaspersky Scan Engine, F-Secure, open-source
[c-icap](https://c-icap.sourceforge.net/) + ClamAV и т.д.).

Подключите стартер, задайте несколько свойств `icap.*` и внедрите `IcapClient`.

---

## Возможности

- Чистый Java-клиент ICAP/1.0 без внешних зависимостей, поверх TCP или TLS (ICAPS).
- Все три метода ICAP: **`OPTIONS`**, **`REQMOD`**, **`RESPMOD`**.
- Корректная генерация и разбор заголовка `Encapsulated`
  (`req-hdr` / `res-hdr` / `req-body` / `res-body` / `null-body`).
- Передача тела запроса и ответа в HTTP-кодировке **chunked**.
- Согласование **`Preview` / `100 Continue`**, включая оптимизацию `ieof`
  (раннее завершение, когда тело целиком умещается в превью).
- Поддержка **`Allow: 204`** («модификация не требуется»).
- Автоконфигурация Spring Boot с типобезопасными свойствами `icap.*` и
  метаданными для подсказок в IDE.
- Однострочный помощник `scan(byte[], filename)` для самого частого сценария
  «безопасен ли этот контент?».

---

## Требования

| | |
|---|---|
| Java | 17+ |
| Spring Boot | 3.5.x (собрано под 3.5.14) |

---

## Подключение

Maven:

```xml
<dependency>
    <groupId>io.github.icap</groupId>
    <artifactId>icap-spring-boot-starter</artifactId>
    <version>0.1.0</version>
</dependency>
```

Gradle:

```groovy
implementation 'io.github.icap:icap-spring-boot-starter:0.1.0'
```

Артефакт пока не опубликован, поэтому сначала соберите его локально:

```bash
mvn clean install
```

---

## Настройка

Все свойства расположены под префиксом `icap.*`:

```yaml
icap:
  enabled: true            # false — полностью отключить автоконфигурацию
  host: icap.internal.example.com
  port: 1344               # стандартный порт ICAP (IANA)
  service: avscan          # имя сервиса -> icap://host:1344/avscan (зависит от продукта)
  connect-timeout: 5s      # таймаут TCP-подключения (0 = бесконечно)
  read-timeout: 30s        # таймаут чтения из сокета (0 = бесконечно)
  allow-204: true          # разрешить серверу отвечать "204 No Content", если изменений нет
  tls: false               # true — использовать TLS (ICAPS)
  preview:
    enabled: true          # использовать механизм Preview при наличии тела
    size: 4096             # сколько начальных байт тела отправлять в превью
```

| Свойство | По умолчанию | Описание |
|---|---|---|
| `icap.enabled` | `true` | Включает/выключает автоконфигурацию. |
| `icap.host` | `localhost` | Хост ICAP-сервера. |
| `icap.port` | `1344` | Порт ICAP-сервера. |
| `icap.service` | `""` | Имя сервиса по умолчанию. |
| `icap.connect-timeout` | `5s` | Таймаут TCP-подключения. |
| `icap.read-timeout` | `30s` | Таймаут чтения из сокета. |
| `icap.allow-204` | `true` | Объявлять `Allow: 204`. |
| `icap.tls` | `false` | Использовать TLS (ICAPS). |
| `icap.preview.enabled` | `true` | Использовать механизм `Preview`. |
| `icap.preview.size` | `4096` | Размер превью в байтах. |

> Правильное имя `service` полностью зависит от вашего ICAP-продукта. Частые
> значения: `avscan`, `respmod`, `srv_clamav`, `virus_scan`. Если не знаете —
> узнайте через `OPTIONS` (см. ниже).

---

## Использование

### Проверка контента (самый частый сценарий)

Внедрите бин `IcapClient` (создаётся автоконфигурацией) и вызовите `scan(...)`:

```java
import io.github.icap.spring.boot.client.IcapClient;
import io.github.icap.spring.boot.model.IcapResponse;

@Service
public class UploadValidator {

    private final IcapClient icap;

    // Бин IcapClient предоставляется автоконфигурацией — просто внедряем его.
    public UploadValidator(IcapClient icap) {
        this.icap = icap;
    }

    public void validate(byte[] content, String filename) {
        IcapResponse response = icap.scan(content, filename);

        if (response.isBlockedOrInfected()) {
            String threat = response.getInfectionFound().orElse("нарушение политики");
            throw new IllegalStateException("Файл отклонён ICAP-сервером: " + threat);
        }
        // 204 No Content -> контент чистый / разрешён
    }
}
```

`scan(...)` отправляет `RESPMOD` с минимальным синтезированным HTTP-запросом и
HTTP-ответом, в которые «заворачиваются» ваши байты. Как интерпретировать результат:

| Метод результата | Значение |
|---|---|
| `response.isNoModificationsNeeded()` (204) | Сервер ничего не изменил — контент чистый / разрешён. |
| `response.isModified()` (200) | Сервер вернул заменяющее тело — обычно контент заблокирован/вылечен. |
| `response.getInfectionFound()` | Значение заголовка `X-Infection-Found` при обнаружении угрозы. |
| `response.getViolationsFound()` | Значение `X-Violations-Found` (нарушения политик DLP/AV). |
| `response.getEncapsulatedBody()` | Адаптированное/заменяющее тело (например, страница блокировки), если есть. |

### Загрузка через `MultipartFile` (типичный веб-сценарий)

```java
@RestController
@RequestMapping("/files")
public class UploadController {

    private final IcapClient icap;

    public UploadController(IcapClient icap) {
        this.icap = icap;
    }

    @PostMapping("/upload")
    public ResponseEntity<String> upload(@RequestParam("file") MultipartFile file) throws IOException {
        IcapResponse resp = icap.scan(file.getBytes(), file.getOriginalFilename());

        if (resp.isBlockedOrInfected()) {
            // 422 — содержимое не прошло проверку безопасности
            return ResponseEntity.unprocessableEntity()
                    .body("Файл отклонён: " + resp.getInfectionFound().orElse("обнаружена угроза"));
        }
        // ... здесь сохраняем файл, он признан безопасным
        return ResponseEntity.ok("Файл загружен");
    }
}
```

### Запрос возможностей сервиса (`OPTIONS`)

Полезно при настройке — узнать поддерживаемые методы и рекомендуемый размер превью:

```java
IcapResponse options = icap.options("avscan");
String methods = options.getHeaders().getFirst("Methods");   // например, "RESPMOD"
String preview = options.getHeaders().getFirst("Preview");   // предпочитаемый сервером размер превью
options.getIstag().ifPresent(tag -> log.info("ISTag={}", tag));
```

### Полный контроль через `RESPMOD` / `REQMOD`

Если нужно передать собственные HTTP-заголовки или дополнительные ICAP-заголовки,
соберите запрос вручную через билдер:

```java
import io.github.icap.spring.boot.model.*;

String httpReqHdr = "GET /file.dat HTTP/1.1\r\nHost: origin\r\n\r\n";
String httpResHdr = "HTTP/1.1 200 OK\r\nContent-Length: " + body.length + "\r\n\r\n";

IcapRequest request = IcapRequest.builder(IcapMethod.RESPMOD)
        .service("avscan")
        .httpRequestHeader(httpReqHdr)
        .httpResponseHeader(httpResHdr)
        .body(body)
        .header("X-Client-IP", "203.0.113.7")   // дополнительный ICAP-заголовок
        .build();

IcapResponse response = icap.respmod(request);
```

### Переопределение бина клиента

Объявите собственный бин `IcapClient` — автоконфигурация отступит
(`@ConditionalOnMissingBean`):

```java
@Bean
IcapClient icapClient() {
    return new DefaultIcapClient("icap-1", 1344, "avscan",
            3000, 15000, true, 8192, true, false);
}
```

---

## Как это работает (детали протокола)

Запрос `RESPMOD`, который клиент отправляет «на провод», выглядит так:

```
RESPMOD icap://host:1344/avscan ICAP/1.0
Host: host
Allow: 204
Preview: 4096
Encapsulated: req-hdr=0, res-hdr=44, res-body=109

GET /file.dat HTTP/1.1
Host: origin

HTTP/1.1 200 OK
Content-Length: 1234

<тело в HTTP-кодировке chunked, завершается чанком нулевой длины>
```

- Обязательный заголовок **`Encapsulated`** перечисляет каждую секцию и её
  **байтовое смещение** внутри инкапсулированной полезной нагрузки. Секции
  заголовков передаются как есть; секция тела — по частям (chunked).
- При включённом **Preview** сначала отправляются только первые `preview.size`
  байт, после чего клиент ждёт: сервер либо сразу возвращает вердикт (например,
  `204`/`200`), либо отвечает `100 Continue`, и тогда клиент досылает остаток.
  Если всё тело умещается в превью, клиент посылает признак `0; ieof`.
- На каждый обмен используется отдельное короткоживущее соединение.
  `DefaultIcapClient` неизменяемый и потокобезопасный, поэтому единственный бин
  можно безопасно использовать из всего приложения.

---

## Обработка ошибок

Все ошибки — непроверяемые (unchecked) и наследуются от `IcapException`:

| Исключение | Когда возникает |
|---|---|
| `IcapConnectionException` | Таймауты подключения/чтения, разрыв соединения, обрыв потока. |
| `IcapProtocolException` | Некорректная строка статуса, неверный `Encapsulated`, ошибки чанкования. |
| `IcapException` | Базовый тип — перехватывайте его, чтобы обработать всё сразу. |

```java
try {
    IcapResponse r = icap.scan(bytes, "f.bin");
} catch (IcapConnectionException e) {
    // проблема транспорта — можно повторить запрос либо применить политику fail-open/fail-closed
} catch (IcapException e) {
    // любая другая ошибка ICAP
}
```

---

## Тестирование

```bash
mvn test
```

Набор тестов включает встроенный (in-process) фейковый ICAP-сервер, который
проверяет `OPTIONS`, чистый ответ `204` и заражённый ответ `200` с заменяющим
телом, а также тесты контекста автоконфигурации.

Чтобы проверить на реальном сервере, поднимите open-source стек c-icap + ClamAV
(например, через Docker), укажите `icap.host`/`icap.service` на него и просканируйте
[тестовую строку EICAR](https://www.eicar.org/download-anti-malware-testfile/) —
она должна быть помечена как угроза.

---

## Структура проекта

```
src/main/java/io/github/icap/spring/boot/
├── autoconfigure/
│   ├── IcapAutoConfiguration.java   # регистрирует бин IcapClient
│   └── IcapProperties.java          # свойства конфигурации icap.*
├── client/
│   ├── IcapClient.java              # публичный API
│   └── DefaultIcapClient.java       # реализация RFC 3507 поверх сокета
├── exception/
│   ├── IcapException.java
│   ├── IcapConnectionException.java
│   └── IcapProtocolException.java
└── model/
    ├── IcapMethod.java              # OPTIONS / REQMOD / RESPMOD
    ├── IcapStatus.java              # константы статус-кодов + reason-фразы
    ├── IcapHeaders.java             # регистронезависимая упорядоченная мультикарта заголовков
    ├── IcapRequest.java             # неизменяемый запрос + билдер
    └── IcapResponse.java            # разобранный ответ + помощники для вердикта

src/main/resources/META-INF/
├── spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports
└── additional-spring-configuration-metadata.json
```

> **Замечание для продакшена:** канонический подход Spring Boot — разделять стартер
> на модуль `*-autoconfigure` и тонкий модуль `*-starter`, который только объявляет
> зависимости. Здесь оба модуля объединены для наглядности; разделение — это
> механический рефакторинг, если вы собираетесь публиковать стартер широко.

---

## Лицензия

Предоставляется «как есть», без гарантий. Адаптируйте под нужды вашей организации.
