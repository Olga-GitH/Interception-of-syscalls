# Interception-of-syscalls
Interception of system calls in Linux OS

# Алгоритм перехвата системного вызова:
1. Сохранить указатель на оригинальный (исходный) вызов для возможности его восстановления - *original_sys_write и *original_sys_read
2. Создать функцию, реализующую новый системный вызов - hooked_sys_write и hooked_sys_read
3. Произвести замену вызовов в регистрах для следующей инструкции в исполняемом коде (regs->ip), т.е настроить соответствующий указатель на новый системный вызов
4. По окончании работы восстановить оригинальный системный вызов, используя ранее сохраненный указатель.

# Kprobes
Используемая технология - kprobes. Kprobes позволяет динамически подключаться к любой программе ядра и без сбоев собирать информацию об отладке и производительности. Вы можете перехватывать практически любой адрес кода ядра, указывая программу-обработчик, которая будет вызываться при достижении точки останова.

Документация: https://www.kernel.org/doc/Documentation/kprobes.txt

# Для выполнения программы:
1. Компилируем модуль: make
2. Загружаем модуль: sudo insmod syscall_hook.ko
3. Выгружает модуль: sudo rmmod syscall_hook
4. Проверка логов: sudo dmesg

# Примеры выводимых логов:
![alt text](https://github.com/Olga-GitH/Interception-of-syscalls/blob/main/examples/5b39be16-c7be-4997-b7b7-d80d5ae8a644.jpg)
![alt text](https://github.com/Olga-GitH/Interception-of-syscalls/blob/main/examples/8f47f1d0-2955-49f3-a5f3-9c569b0d65f0.jpg)
