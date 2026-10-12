# Руководство

Установите выпущенную зависимость report-contract перед wheel. Явный --format neutral-json-v1 обязателен. Выходные файлы не должны существовать. Коды: 0 pass/неприменимость, 1 отказ, 2 неполные свидетельства без отказов, 3 неверный вход/выход. Другой формат — usage-ошибка argparse (2), а не оценка покрытия. Проверка автономна, DNS и подключения не выполняются.

```bash
python -m pip install -r requirements-bootstrap.txt
python -m pip install .
network-audit examples/safe.synthetic.json --format neutral-json-v1 --observed-at 2026-10-12T00:00:00Z --output report.json
opsec-report validate report.json
opsec-report html report.json --output report.html
```

[Index](index.md)
