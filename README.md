# omni-tls-starter #

Модуль omni-tls-starter обеспечивает своевременное предупреждение об истечении срока действия сертификатов.

### Принцип работы ###

Стартер переопределяет провайдера безопасности, с помощью которого предоставляет свои реализации TrustManager и KeyManager.

### Настроечные ключи

| Ключ                                    | Значение по умолчанию | Описание                                                                                                                    |
|-----------------------------------------|:---------------------:|-----------------------------------------------------------------------------------------------------------------------------|
| omni-tls.certificate.info-level-days    |          90           | Пороговое значение срока действия сертификата в днях, при пересечении которого будет выведено предупреждение уровня INFO    |
| omni-tls.certificate.warning-level-days |          30           | Пороговое значение срока действия сертификата в днях, при пересечении которого будет выведено предупреждение уровня WARNING |
| omni-tls.certificate.error-level-days   |           7           | Пороговое значение срока действия сертификата в днях, при пересечении которого будет выведено предупреждение уровня ERROR   |
| omni-tls.certificate.mode               |     ALLOW_EXPIRED     | Отключить выбрасывание исключений при обнаружении проблем с сертификатами, только логировать соответствующую информацию     |

Пример:
```yaml
omni-tls:
  certificate:
    info-level-days: 150
    warning-level-days: 70
    error-level-days: 2
```
