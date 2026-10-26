#!/usr/bin/python3
from bcc import BPF
import time

# ==============================================================================
# 1. Kernel Space - код на C
# ==============================================================================
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Структура для передачи данных из ядра в User Space
struct data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
};

// Объявление кольцевого буфера (Perf Ring Buffer) с именем 'events'
BPF_PERF_OUTPUT(events);

// Функция, которая прикрепляется к системному вызову execve (kprobe)
int syscall__execve(struct pt_regs *ctx) {
    struct data_t data = {};

    // ЗАДАНИЕ 1. ВАШ КОД ЗДЕСЬ:
    // 1. Извлеките PID (используйте макрос bpf_get_current_pid_tgid() >> 32)
    // 2. Извлеките UID (используйте макрос bpf_get_current_uid_gid())
    // 3. Извлеките имя процесса (используйте bpf_get_current_comm(&data.comm, sizeof(data.comm)))

    // 4. Отправьте структуру data в пространство пользователя:
    // events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# ==============================================================================
# 2. Инициализация eBPF
# ==============================================================================
# Компилируем C-код и загружаем его в виртуальную машину eBPF в ядре
b = BPF(text=bpf_text)

# Прикрепление C-функцию к системному вызову execve.
# BCC использует get_syscall_fnname() для автоматического определения
# правильного префикса ядра (например, __x64_sys_execve)
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")

print("[*] Мониторинг запущен. Ожидание вызовов execve... (Нажмите Ctrl+C для выхода)")


# ==============================================================================
# 3. User Space - обработка событий в Python
# ==============================================================================
def print_event(cpu, data, size):
    # Конвертируем сырые байты из ядра в структуру Python
    event = b["events"].event(data)

    # Задания 1 и 3. ВАШ КОД ЗДЕСЬ:
    # 1. Выведите в консоль event.pid, event.uid и event.comm.decode('utf-8', 'replace')
    # 2. (для Задания 3): Добавьте логику записи этих данных в файл security_audit.log

    # Пример вывода (замените на свой):
    print(f"Перехват! PID: {event.pid}")


# Подписываем функцию print_event на события из кольцевого буфера 'events'
b["events"].open_perf_buffer(print_event)

# Бесконечный цикл опроса буфера
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\n[*] Завершение работы монитора.")
        exit()