# BlackHoleVPN

BlackHoleVPN — экспериментальный сервис защищённого доступа к интернету на Debian 13 с Xray-core и VLESS/REALITY. Проект развивается для небольшой установки до 100 пользователей на нескольких VPS; управление разрешениями и восстановлением сейчас реализовано **на одном узле**.

**Статус: прототип с проверенными транспортами и узловыми операциями, не готовый промышленный релиз.** Реальная передача данных подтверждена с внешнего Linux-клиента. Проверены изолированные systemd-перезапуски, сбои управляющего процесса и безопасное восстановление. Windows/iOS GUI, настоящий reboot/отказ питания и общий rollout нескольких VPS ещё не прошли приёмку. [Подробные результаты и ограничения](docs/validation-results.md).

## Что реализовано

| Возможность | Реализация и границы |
| --- | --- |
| Два транспорта | Основной XHTTP + REALITY (`stream-one`), резервный TCP + REALITY + Vision; отдельные порты. [Описание](docs/dual-transport.md) |
| Клиентские конфигурации | VLESS URI и полный JSON, опциональный FinalMask `tlshello`; четыре JSON-варианта испытаны настоящим Xray. [Экспорт](docs/client-json-export.md) |
| Управление устройствами | Отдельный UUID, активные записи и сохраняемые tombstone. Старый snapshot не возвращает отозванный UUID при сохранности актуального authority. [Реестр](docs/device-registry.md) |
| Надёжные изменения | Межпроцессная блокировка, проверка Xray, атомарная запись, приватные backup/restore и fsync. [Транзакции](docs/config-transactions.md) |
| Применение к службе | Явная policy, проверка привязки unit/процесса, HTTPS-пробы обоих транспортов, last-good и автоматический откат. [Apply](docs/health-checked-apply.md) |
| Восстановление узла | Pre-start guard до запуска Xray и отдельный supervisor; обработка гибели контроллера/supervisor/Xray без возврата отозванных UUID. Проверен boot-like target, не kernel reboot. [Systemd recovery](docs/automatic-recovery.md) |
| Подписки и измерения | Локальный прототип подписок и рекомендация маршрута по измерениям; нет готовой публичной HTTPS-подписки, общего отзыва на всех VPS и автоматического переключения в GUI. [Архитектура](docs/subscription-architecture.md), [адаптивность](adaptive/README.md) |

## Документация

- [Начало эксплуатации и ограничения](docs/operator-guide.md), [план промышленной подготовки](docs/production-roadmap.md).
- [Управление серверной конфигурацией](docs/server-alpha.md), [реестр устройств и миграция](docs/device-registry.md).
- [Apply/rollback](docs/health-checked-apply.md), [автовосстановление и systemd-шаблоны](docs/automatic-recovery.md).
- [Проверка Windows/iOS](docs/windows-ios-testing.md), [импорт JSON в Happ и v2rayN](docs/json-import-happ-v2rayn.md).
- [REALITY target и FinalMask](docs/finalmask-reality.md), [экспериментальный протокол](experiments/README.md).
- [Архитектура](docs/architecture.md), [безопасность и сообщения об уязвимостях](SECURITY.md), [участие в проекте](CONTRIBUTING.md).

## Проверка кода

Требуется Python 3 на Linux. Дополнительные Python-пакеты для тестов не нужны.

```sh
python3 -m unittest discover -s tests -v
# Опционально: настоящий доверенный Xray, включая валидацию экспорта/backup/restore.
BLACKHOLE_TEST_XRAY=/path/to/xray python3 -m unittest discover -s tests -v
```

По умолчанию настоящий Xray-тест пропускается. CI проверяет Python 3.11/3.13/3.14 и закреплённый Xray 26.10.21 с проверкой SHA256. Unit-mocks не заменяют отдельные испытания systemd/сети; выполненные реальные проверки перечислены в [отчёте](docs/validation-results.md).

## Перед развёртыванием

Используйте отдельную Debian 13 VM с SSH по ключу, консолью провайдера и возможностью восстановления. Самостоятельно установите доверенный Xray, выберите совместимый REALITY target и свободные порты. Универсального production-установщика нет. Systemd-шаблоны нужно адаптировать и испытать на новом узле; они не предназначены для слепой замены действующих служб.

Секреты, адреса узлов, UUID, профили, токены и резервные копии хранятся вне Git. Локальные копии содержат секреты и сами по себе не зашифрованы; для потери VPS нужны отдельные защищённые off-site-копии и проверка восстановления. Authority нельзя откатывать вместе с конфигурацией.

VLESS — прокси-протокол; системный VPN/TUN, DNS/IPv6 и kill switch зависят от клиента и ОС. REALITY и FinalMask не гарантируют обход DPI, незаметность или анонимность. Настройки Xray отключают его access/error/DNS-логи в генерируемом JSON, но не подтверждают отсутствие журналов ОС, systemd и хостинга.

## Лицензия и источники

Проект распространяется по [MIT](LICENSE); внешние компоненты — по собственным лицензиям.

- [Xray VLESS](https://xtls.github.io/en/config/inbounds/vless.html)
- [Xray REALITY](https://xtls.github.io/en/config/transports/reality.html)
- [Xray FinalMask](https://xtls.github.io/en/config/transports/finalmask.html)
- [Debian 13](https://www.debian.org/releases/trixie/)
