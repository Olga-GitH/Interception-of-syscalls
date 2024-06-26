# Module-interception for hacking

Данный раздел посвящен не только перехвату систеных вызовов, но и замене их на собственно написанные функции с целью изменения поведение процесса записи/чтения  - hooked_sys_write и hooked_sys_read. В целом, логика внутри данных функций может быть любая - в распроряжении программиста имеется те же параметры, что и у оригинальных системных вызовов. В данном примере это:
- fd - файловый дескриптор, полученный с помощью open()
- buf - буффер данных для чтения/записи
- count - количество необходимых байтов для чтения/записи

# Задача

1. Сломать ввод/вывод для пользователя, оставив возможность прочитать/записать только первый символ.
2. На кажом этапе обработки провести логирование действий для мониторинга, в том числе выводить в логи путь к файлу, с которым работает пользователь.

# Тонкости

Ввиду того, что ksys_read и ksys_write являются функциями ядра Linux и используются системной для собственных действий чтения/записи, было принято решение ограничить сферу действия подмены оригинальной функции на "испорченную" только внутри рабочего каталога "kernel_module". Применение данной подмены везде повлекло бы в лучшем случае зависание, в худшем - сбой системы. Данный момент обработан следующей проверкой в пред-обработчике, который предшествует вызову функции:
````
// path to the file using our function
char *path_ = get_file_path_from_fd(regs->di);

if (path_) {
  if (strstr(path_, "root/kernel_module")) {...}}
````
# В случае прохождения данной проверки, произойдет следующий сценарий:
1. Сохранение указателя на оригинальный вызов для возможности восстановления из структуры struct kprobe *p. 
````
original_sys_write = (void *)p->addr;
````
2. Реализация логики "испорченной" функции hooked_sys_write
````
static asmlinkage hooked_sys_write(insigned int fd, const char __user *buf, size_t count)
{
  printk(KERN_INFO "Hooked write called\n");
  // was "count", now "1"
  return original_sys_write(fd, buf, 1);
}
````
4. Подмена вызова, путем изменения регистров:
````
regs->ip = (unsigned long)hooked_sys_write;
````
4. Сохранение изменений
````
return 1;
````
Иначе return 0. Это приведет к вызову оригинальной функции + post_handler.
# Результаты запуска
Если попробовать вызвать исполняемый файл try_read, осуществляющий чтение текстового содержимого "Hello!" (результат работы при еще не загруженном модуле представлен в разделе Tracing) после сборки модуля и загрузки в ядро, получаем ожидаемый результат:
````
make syscall_hook.c
insmod syscall_hook.ko
./try_read
````
![alt text](https://github.com/Olga-GitH/Interception-of-syscalls/blob/main/examples/IMG_8060.jpeg)

Так, в следующей строке терминала после вызова ./try read пропечаталась первая буква слова - "H". 
Выгрузим модуль и посмотрим логи:
````
rmmod syscall_hook.ko
dmesg
````
![alt text](https://github.com/Olga-GitH/Interception-of-syscalls/blob/main/examples/IMG_8061.jpeg)
![alt text](https://github.com/Olga-GitH/Interception-of-syscalls/blob/main/examples/IMG_8062.jpeg)

Таким образом, перехват произошел успешно (поставленные задачи выполнены). Чтение/запись взломаны, вся требуемая информация выводится в логах, не затрагивая внутренню работу ядра.
