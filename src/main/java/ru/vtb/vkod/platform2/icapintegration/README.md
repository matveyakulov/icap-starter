# Тестовый ICAP-сервер

Минимальный ICAP/1.0 (RFC 3507) **сервер** без внешних зависимостей для использования на стенде.
Позволяет тестировать ICAP-клиент (в том числе `DefaultIcapClient` из этого стартера или прокси Squid)
без настоящего антивирусного/DLP-шлюза.

> ICAP — это собственный TCP-протокол, а **не** HTTP, поэтому здесь обычный слушающий сокет, а не
> контроллер Spring MVC. ICAP-порт по умолчанию — **1344**.

## Что он делает

| Запрос             | Ответ |
|--------------------|-------|
| `OPTIONS`          | `200 OK` с `Methods`, `ISTag`, `Allow: 204`, `Preview` |
| `REQMOD`/`RESPMOD`, тело которого содержит сигнатуру [EICAR](https://www.eicar.org/) | `200 OK` + `X-Infection-Found` + страница-заглушка «заблокировано» |
| `REQMOD`/`RESPMOD` с чистым содержимым | `204 No Content` (если клиент прислал `Allow: 204`), иначе неизменённое эхо `200 OK` |

Корректно обрабатывает рукопожатие `Preview` / `100 Continue` и декодирует chunked-тело.

## Запуск standalone

```bash
mvn -o compile
# порт по умолчанию 1344:
java -cp target/classes ru.vtb.vkod.platform2.icapintegration.IcapTestServer
# или выбрать порт:
java -cp target/classes ru.vtb.vkod.platform2.icapintegration.IcapTestServer 13440
```

Быстрая проверка встроенным клиентом (направьте его на запущенный сервер):

```properties
icap.host=localhost
icap.port=1344
icap.default-service=test
```

## Встраивание в Spring Boot приложение

Сервер целиком находится в пакете `ru.vtb.vkod.platform2.icapintegration` и **не** затрагивает
публикуемый клиентский стартер (он не зарегистрирован в `AutoConfiguration.imports`). Подключается
явно — импортом `IcapTestServerConfiguration` в вашем стендовом приложении, после чего включается
через свойства:

```java
@Import(ru.vtb.vkod.platform2.icapintegration.IcapTestServerConfiguration.class)
@SpringBootApplication
public class StandApplication { }
```

```yaml
# application-stand.yml  (включайте только в стендовом профиле)
icap:
  test-server:
    enabled: true        # по умолчанию выключен
    port: 1344           # 0 = эфемерный порт
    check-passes: true   # true = проверка «чисто» (204); false = «заражено/блок» (200)
```

Зарегистрирован как бин `SmartLifecycle`, поэтому привязывает сокет при старте контекста и корректно
закрывается при завершении — вызывать `start()`/`stop()` вручную не нужно.

Внедрите бин, чтобы прочитать фактический порт или переключить вердикт в рантайме:

```java
@Autowired
IcapTestServer icapTestServer;

// например, сымитировать неуспешную проверку для одного теста, затем вернуть обратно:
icapTestServer.setCheckPasses(false);
int port = icapTestServer.getPort();
```

> `check-passes` — это переключатель, определяющий исход каждой проверки. Значение `false` заставляет
> сервер сообщать о заражении для любого содержимого (удобно, чтобы детерминированно проверить
> обработку «заблокировано»). Сигнатура EICAR всегда считается заражённой, независимо от флага.

### Встраивание вручную (например, в обычном интеграционном тесте)

```java
try (IcapTestServer server = new IcapTestServer(0)) { // 0 = эфемерный порт
    server.start();
    int port = server.getPort();
    // ... направьте клиент на localhost:port и проверьте IcapResponse ...
}
```

## Замечания и ограничения

- Предназначен только для тестирования — нестрогий парсинг, без аутентификации и продакшен-защиты.
- Один поток на соединение; цикл обработки поддерживает клиентов, переиспользующих соединение.
- Политика вердикта намеренно тривиальна (детектирование EICAR). При необходимости измените
  `decideVerdict` / `writeBlockedResponse` в `IcapTestServer` под нужное поведение стенда.
