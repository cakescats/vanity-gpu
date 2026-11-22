# Сборка vanity-gpu

[English](BUILD.md) | **Русский**

vanity-gpu работает в Linux x86-64 с видеокартой NVIDIA. Получить программу можно двумя способами:

1. Скачать готовую сборку из релизов, её собирает GitHub Actions (любая NVIDIA начиная с RTX 20xx).
2. Собрать самому: несколько минут для одного типа видеокарты, и программа будет оптимизирована под ваш процессор.

## 1. Готовая сборка

Скачайте `vanity-gpu-<версия>-linux-x86_64.tar.gz` со страницы Releases, проверьте контрольную сумму и запустите самотест:

```bash
sha256sum -c vanity-gpu-*-linux-x86_64.tar.gz.sha256
tar xzf vanity-gpu-*-linux-x86_64.tar.gz
cd vanity-gpu-*-linux-x86_64
./vanity-gpu selftest
```

В сборке есть код для compute capability 7.5, 8.0, 8.6, 8.9, 9.0 и 12.0 (RTX 20xx, A100, RTX 30xx, RTX 40xx, H100, RTX 50xx). Архив весит ~240 МБ. Рантайм CUDA вшит в программу, поэтому CUDA toolkit не нужен, достаточно драйвера NVIDIA (рекомендуется 570 или новее). Сборка сделана на Ubuntu 24.04 и требует glibc 2.39 или новее (Ubuntu 24.04+, Debian 13+, Fedora 40+). На более старой системе соберите из исходников.

Для `--cpu` в готовой сборке используется переносимый код: на тестовой машине `--cpu max` добавляет к EVM 2% вместо 6% с `-march=native`. Если пользуетесь `--cpu`, соберите из исходников.

## 2. Сборка из исходников

### Что нужно

| | версия | примечание |
|---|---|---|
| драйвер NVIDIA | любой, поддерживающий ваш CUDA toolkit | `nvidia-smi` показывает максимальную поддерживаемую версию CUDA |
| CUDA toolkit | 12.4 или новее (проверено: 12.4, 13.5) | нужны только `nvcc` и рантайм |
| компилятор C++ | g++ 11–13 для CUDA 12.x; для CUDA 13 новее | CMake сам берёт `g++-13`, если он установлен |
| CMake | 3.20 или новее | |
| Python 3 + `cryptography` | по желанию | только для `tests/crosscheck.py` |

В Ubuntu:

```bash
sudo apt install build-essential g++-13 cmake git
# CUDA: либо пакет Ubuntu (может быть старее)...
sudo apt install nvidia-cuda-toolkit
# ...либо репозиторий NVIDIA (в адресе — ваша версия Ubuntu):
wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/cuda-keyring_1.1-1_all.deb
sudo dpkg -i cuda-keyring_1.1-1_all.deb && sudo apt update
sudo apt install cuda-toolkit-12-8
```

### Сборка

```bash
git clone https://github.com/<you>/vanity-gpu.git
cd vanity-gpu
cmake -S . -B build -DCMAKE_CUDA_ARCHITECTURES=86
cmake --build build -j
./build/vanity-gpu selftest
```

В `CMAKE_CUDA_ARCHITECTURES` укажите compute capability своей видеокарты без точки (по умолчанию 86):

| видеокарта | значение |
|---|---|
| RTX 20xx, GTX 16xx | 75 |
| A100 | 80 |
| RTX 30xx, A10, A40 | 86 |
| RTX 40xx, L4, L40 | 89 |
| H100 | 90 |
| RTX 50xx (нужна CUDA 12.8+) | 120 |

Узнать значение можно командой `nvidia-smi --query-gpu=compute_cap --format=csv`. Можно перечислить несколько значений (`"86;89"`), тогда одна программа будет работать на разных картах, но каждое значение добавляет несколько минут сборки.

Если `nvcc` нет в `PATH` или установлено несколько версий CUDA, укажите нужную: `-DCMAKE_CUDA_COMPILER=/usr/local/cuda-12.8/bin/nvcc`. После смены CUDA или компилятора сначала удалите `build/`.

### Параметры

| параметр | по умолчанию | что делает |
|---|---|---|
| `CMAKE_CUDA_ARCHITECTURES` | `86` | под какие видеокарты собирать |
| `VG_NATIVE_CPU` | `ON` | собирать обработчики `--cpu` с `-march=native` (AVX-512 / AVX2 этого процессора). Выключите (`OFF`), если программу будут запускать на других машинах |
| `VG_VERSION` | версия проекта | что печатает `--version` |
| `CMAKE_CUDA_HOST_COMPILER` | `g++-13`, если найден | компилятор для `nvcc` |

### Проверка сборки

```bash
./build/vanity-gpu selftest                        # эталонные векторы, GPU против CPU, частота находок (~1-2 мин)
python3 -I tests/crosscheck.py build/vanity-gpu 40 # независимая сверка через Python-пакет cryptography
tests/bench.sh build/vanity-gpu 8                  # скорость всех режимов поиска
```

`selftest` должен закончиться строкой `all tests passed`. Если это не так, ключами из такой сборки пользоваться нельзя.

### Частые проблемы

- **`unsupported GNU version! gcc versions later than 13 are not supported`**: CUDA 12.x с gcc 14/15. Установите `g++-13` и удалите `build/` или передайте `-DCMAKE_CUDA_HOST_COMPILER=/usr/bin/g++-13`.
- **`no kernel image is available for execution on the device`**: программа собрана под другую видеокарту. Пересоберите со своим `CMAKE_CUDA_ARCHITECTURES`.
- **`CUDA driver version is insufficient for CUDA runtime version`**: CUDA toolkit новее драйвера. Обновите драйвер или возьмите более старый toolkit.
- **Solana/TON медленнее, чем ожидалось**: если свободной видеопамяти меньше ~5.5 ГБ, используется малая таблица на 50 МБ (примерно на 25% медленнее). Закройте другие программы, занимающие видеокарту.

## 3. Сборка на GitHub (Actions)

В репозитории есть `.github/workflows/build.yml`. Он запускается при каждом push в `main`, на pull request, вручную (Actions → build → Run workflow) и на тегах `v*`.

Что он делает:

1. Ставит `nvcc` и рантайм CUDA 12.8 из репозитория NVIDIA на `ubuntu-24.04` (без драйвера и без видеокарты).
2. Собирает под все архитектуры из таблицы выше с `VG_NATIVE_CPU=OFF`.
3. Запускает `vanity-gpu --version`. На серверах GitHub нет видеокарт, поэтому `selftest` там не запустить.
4. Упаковывает программу, README, LICENSE, `examples/` и `docs/` в `vanity-gpu-<версия>-linux-x86_64.tar.gz` с файлом `.sha256` и прикрепляет их к запуску (Actions → запуск → Artifacts).
5. На теге `v*` дополнительно создаёт релиз на GitHub с этими файлами.

Выпустить релиз:

```bash
git tag v1.0.0
git push origin v1.0.0
```

Сборка идёт около 30 минут (шесть архитектур; локально на 16 ядрах — 29 минут). Программа весит ~240 МБ: в ней машинный код для шести поколений видеокарт. Потом скачайте архив на машину с видеокартой NVIDIA и запустите `./vanity-gpu selftest`, прежде чем объявлять релиз.

Чтобы поменять версию CUDA или список видеокарт, отредактируйте `CUDA_PKG`, `CUDA_HOME` и `CUDA_ARCHS` в начале workflow. Для compute capability 12.0 (RTX 50xx) нужна CUDA 12.8 или новее.
