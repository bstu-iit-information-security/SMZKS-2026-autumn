#!/usr/bin/python3
from bcc import BPF
import time
from datetime import datetime

bpf_text = """
#include <uapi/linux/ptrace.h>
#define MS_RDONLY 1

struct data_t {
    u32 pid;
    u32 uid;
    u64 flags;

    char comm[256];
    char source[256];
    char target[256];
    char fstype[64];
};

BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(data_heap, struct data_t, 1);
/*
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();

    bpf_probe_read_user_str(
        &data.comm,
        sizeof(data.comm),
        args->filename
    );

    events.perf_submit(args, &data, sizeof(data));

    return 0;
}*/

// Перехват системного вызова mount
TRACEPOINT_PROBE(syscalls, sys_enter_mount) {
    u32 zero = 0;

    struct data_t *data = data_heap.lookup(&zero);

    if (!data) {
        return 0;
    }

    // Очистка структуры
    __builtin_memset(data, 0, sizeof(*data));

    data->flags = args->flags;

    // ФИЛЬТРАЦИЯ АНОМАЛИЙ В ЯДРЕ
    // Если установлен MS_RDONLY, событие игнорируется
    if (data->flags & MS_RDONLY) {
        return 0;
    }

    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid();

    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    // Получение аргументов системного вызова
    bpf_probe_read_user_str(
        &data->source,
        sizeof(data->source),
        args->dev_name
    );

    bpf_probe_read_user_str(
        &data->target,
        sizeof(data->target),
        args->dir_name
    );

    bpf_probe_read_user_str(
        &data->fstype,
        sizeof(data->fstype),
        args->type
    );

    // Отправка только аномальных событий
    events.perf_submit(args, data, sizeof(*data));

    return 0;
}
"""

b = BPF(text=bpf_text)

print("[*] Мониторинг запущен. Ожидание вызовов execve... (Нажмите Ctrl+C для выхода)")

#def print_event(cpu, data, size):
#    event = b["events"].event(data)

#    pid = event.pid
#    uid = event.uid
#    comm = event.comm.decode('utf-8', 'replace')

#    print(f"Перехват! PID: {pid}, UID: {uid}, "
#          f"Процесс: {comm}")

def print_event(cpu, data, size):
    event = b["events"].event(data)

    pid = event.pid
    uid = event.uid

    comm = event.comm.decode('utf-8', 'replace').rstrip('\x00')
    source = event.source.decode('utf-8', 'replace').rstrip('\x00')
    target = event.target.decode('utf-8', 'replace').rstrip('\x00')
    fstype = event.fstype.decode('utf-8', 'replace').rstrip('\x00')

    flags = event.flags

    print("\n[!] ОБНАРУЖЕНА АНОМАЛИЯ!")
    print(f"PID: {pid}")
    print(f"UID: {uid}")
    print(f"Процесс: {comm}")
    print(f"Источник: {source}")
    print(f"Целевой каталог: {target}")
    print(f"Тип файловой системы: {fstype}")
    print(f"Флаги монтирования: {flags}")
    print("Причина: монтирование без MS_RDONLY")

    # Получение текущей временной метки
    timestamp = datetime.now().astimezone().isoformat(
        timespec="seconds"
    )

    # Формирование записи журнала
    log_entry = (
        f"[{timestamp}] "
        f"PID: {pid} | "
        f"UID: {uid} | "
        f"Процесс: {comm} | "
        f"Источник: {source} | "
        f"Целевой каталог: {target} | "
        f"Тип файловой системы: {fstype} | "
        f"Флаги: {flags} | "
        f"Причина: монтирование без MS_RDONLY\n"
    )

    # Запись события в файл аудита
    with open("security_audit.log", "a", encoding="utf-8") as log:
        log.write(log_entry)

    print("[+] Событие записано в security_audit.log")

b["events"].open_perf_buffer(print_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\n[*] Завершение работы монитора.")
        exit()