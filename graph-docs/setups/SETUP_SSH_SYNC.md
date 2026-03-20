# Настройка SSH-синхронизации между машинами (Phase 4)

## Топология

- **Машина 1** (главная, Ethernet) — стратегия A (`corpus_p4a`)
- **Машина 2** (вторая, WSL) — стратегия B (`corpus_p4b`)

Связь: **SSH по локальной сети**. GitHub не используется — corpus состоит из
сотен бинарных файлов, rsync по LAN быстрее и не создаёт нагрузки на git.

---

## Генерация SSH-ключа (машина 2)

```bash
ls ~/.ssh/id_ed25519 2>/dev/null || ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519
cat ~/.ssh/id_ed25519.pub
```

Скопировать вывод → добавить на машине 1:

```bash
echo "<публичный ключ>" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

---

## Проверка

```bash
ssh a1oleg@172.21.121.84 "echo OK"
```

---

## Переменные окружения (прописать в ~/.bashrc или tmux-команде)

```bash
export MACHINE1=a1oleg@172.21.121.84
export MACHINE2=user@<IP_машины2>   # заполнить когда известен IP машины 2
```

---

## Corpus sync — раз в час (машина 2 → получает с машины 1)

```bash
REPO=~/tonGraph
MACHINE1=a1oleg@172.21.121.84

rsync -az $MACHINE1:$REPO/simulation/corpus_p4a/ \
         $REPO/simulation/corpus_p4a_remote/

$REPO/build-fuzz2/test/consensus/fuzz_pool -merge=1 \
  $REPO/simulation/corpus_p4b_merged/ \
  $REPO/simulation/corpus_p4b/ \
  $REPO/simulation/corpus_p4a_remote/

mv $REPO/simulation/corpus_p4b_merged/* \
   $REPO/simulation/corpus_p4b/
```

---

## Примечания

- Ethernet надёжнее Wi-Fi, но для раз-в-час rsync оба варианта приемлемы
- Файлы corpus атомарны (libFuzzer только создаёт новые, не изменяет старые) →
  rsync идемпотентен, прерывание безопасно
- При потере связи машина продолжает фаззить независимо; после восстановления —
  см. раздел «Если машина 2 отвалилась» в [FUZZING_PHASE4.md](../FUZZING_PHASE4.md)
