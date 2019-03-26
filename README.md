# LocalVPN
A packet interceptor for Android built on top of VpnService

License: Apache v2.0

Early alpha, will eat your cat!

Приложение работает нестабильно, пакеты могут теряться. Часто возникают ошибки, при приеме-передаче пакетов.
В ветке testing-and-debug содержится много комментариев к коду, а также добавлено логирование, поможет при поиске причины ошибок.

Сценарий работы:
1. Приложение запускается на устройстве (или эмуляторе)
2. Включается vpn (нужно дать разрешение приложению на обработку трафика)
3. Теперь весь трафик смартфона идет через это приложение.

Какие ошибки наблюдаются:
После запуска приложения, интернет некоторое время работает нормально. Но в какой-то момент возникает
ошибка, после которой интернет соединение пропадает - ни один сайт не грузится. Если смотреть трафик в wireshark,
сайт просто начинает слать reset пакеты на любой запрос (но не всегда, это одна из ошибок).

Одна ошибка была найдена, она была связана с используванием пула буферов (ByteBufferPool.java) в двух паралельных потоках,
что приводит к некорректным пакетам. Одно из решений - удаление пула буферов, однако это приводит
к очень частому запуску сборщика мусора.

По вопросам связанным с работой кода приложения можно обращаться к https://vk.com/azaabi


Ошибки логируются, поэтому их легко увидеть, однако выяснить причину может быть непросто.

Примеры ошибок из логов.
Ошибка при отправке данных в сеть через сокет:
E/TCPOutput: Network write error: 178.154.131.216:443:40482
    java.net.SocketException: sendto failed: EPIPE (Broken pipe)
        at libcore.io.IoBridge.maybeThrowAfterSendto(IoBridge.java:546)
        at libcore.io.IoBridge.sendto(IoBridge.java:529)
        at java.nio.SocketChannelImpl.writeImpl(SocketChannelImpl.java:406)
        at java.nio.SocketChannelImpl.write(SocketChannelImpl.java:364)
        at xyz.hexene.localvpn.TCPOutput.processACK(TCPOutput.java:218)
        at xyz.hexene.localvpn.TCPOutput.run(TCPOutput.java:107)
        at java.util.concurrent.Executors$RunnableAdapter.call(Executors.java:422)
        at java.util.concurrent.FutureTask.run(FutureTask.java:237)
        at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1112)
        at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:587)
        at java.lang.Thread.run(Thread.java:818)
     Caused by: android.system.ErrnoException: sendto failed: EPIPE (Broken pipe)
        at libcore.io.Posix.sendtoBytes(Native Method)
        at libcore.io.Posix.sendto(Posix.java:169)
        at libcore.io.BlockGuardOs.sendto(BlockGuardOs.java:270)
        at libcore.io.IoBridge.sendto(IoBridge.java:527)

Ошибка при чтении данных из сети:
E/TCPInput: Network read error: 173.194.113.153:443:44037
    java.net.SocketException: recvfrom failed: ECONNRESET (Connection reset by peer)
        at libcore.io.IoBridge.maybeThrowAfterRecvfrom(IoBridge.java:592)
        at libcore.io.IoBridge.recvfrom(IoBridge.java:568)
        at java.nio.SocketChannelImpl.readImpl(SocketChannelImpl.java:342)
        at java.nio.SocketChannelImpl.read(SocketChannelImpl.java:304)
        at xyz.hexene.localvpn.TCPInput.processInput(TCPInput.java:120)
        at xyz.hexene.localvpn.TCPInput.run(TCPInput.java:71)
        at java.util.concurrent.Executors$RunnableAdapter.call(Executors.java:422)
        at java.util.concurrent.FutureTask.run(FutureTask.java:237)
        at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1112)
        at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:587)
        at java.lang.Thread.run(Thread.java:818)
     Caused by: android.system.ErrnoException: recvfrom failed: ECONNRESET (Connection reset by peer)
        at libcore.io.Posix.recvfromBytes(Native Method)
        at libcore.io.Posix.recvfrom(Posix.java:154)
        at libcore.io.BlockGuardOs.recvfrom(BlockGuardOs.java:245)
        at libcore.io.IoBridge.recvfrom(IoBridge.java:565)
        at java.nio.SocketChannelImpl.readImpl(SocketChannelImpl.java:342) 
        at java.nio.SocketChannelImpl.read(SocketChannelImpl.java:304) 
        at xyz.hexene.localvpn.TCPInput.processInput(TCPInput.java:120) 
        at xyz.hexene.localvpn.TCPInput.run(TCPInput.java:71) 
        at java.util.concurrent.Executors$RunnableAdapter.call(Executors.java:422) 
        at java.util.concurrent.FutureTask.run(FutureTask.java:237) 
        at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1112) 
        at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:587) 
        at java.lang.Thread.run(Thread.java:818) 
