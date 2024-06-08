# Tracing
Tracing for tracking system calls

# 
Выяснить, какие системные вызовы задействуются при работе приложения, позволяет трассировка. Осуществив трассировку, можно определить, какой именно системный вызов следует перехватить, чтобы взять под контроль приложение. В качестве примера воспользуемся файлом try_read.cpp, который просто открывает файл file2.txt, считывает из него данные в буфер, выводит содержимое в консоль и закрывает файл. При этом опреации open, read и close выполняются ядром по запросу задачи. Чтобы выяснить, какие системные вызовы для этого исполняются, выполним следующий алгоритм:
1. Поместим в одну папку приведенные в данном разделе файлы try_read.cpp и file2.txt
2. Скопмилируем исходный файл try_read.cpp и создадим исполняемый файл с именем try_read комнадой терминала
````
g++ -g -o try_read try_read.cpp
````
3. Проверяем работоспособность исполняемого файла:
````
./try_read
````
![alt text](https://github.com/Olga-GitH/Interception-of-syscalls/blob/main/examples/IMG_8058_.PNG)

4. Осуществляем трассировку:
````
ltrace -S ./try_read
````
5. Видим результат, в данной работе нас будут интересовать ksys_read и ksys_write:

![alt width = "322" text](https://github.com/Olga-GitH/Interception-of-syscalls/blob/main/examples/IMG_8059_.PNG)

Подробнее о функциях ввода-вывода:
- https://elixir.bootlin.com/linux/latest/source/fs/read_write.c

О перехвате системных вызовов (для старых версий):
- https://www.opennet.ru/base/dev/intercept_lnx.txt.html
