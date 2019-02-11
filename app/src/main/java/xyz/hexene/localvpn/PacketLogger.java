package xyz.hexene.localvpn;

import android.app.Application;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.util.Log;
import android.util.SparseArray;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/*
Алгоритм связывания пакета с приложением:
 1. Из пакета мы знаем ip:port и протокол
 2. Зная ip:port - находим подходящее соединее в файле соединений (TCP или UDP):
      /proc/net/tcp, /proc/net/udp
      В этом файле хранится uid приложения, которое это соединение открыло.
 3. Зная uid, находим приложение из списка установленных приложений. Информацию можно хранить в виде мапы:
      uid -> метаданные приложения (в том числе имя, иконка и т.д.)
*/
public class PacketLogger extends Application {

    private static final String TAG = PacketLogger.class.getName();

    private static SparseArray<String> installedAppsNames;

    @Override
    public void onCreate() {
        super.onCreate();

        //get a list of installed apps.
        installedAppsNames = initializeInstalledApps();
    }

    private SparseArray<String> initializeInstalledApps() {
        SparseArray<String> uidToNameMap = new SparseArray<>();
        PackageManager packageManager = getApplicationContext().getPackageManager();
        List<ApplicationInfo> packages = packageManager.getInstalledApplications(PackageManager.GET_META_DATA);

        for (ApplicationInfo applicationInfo : packages) {
            String appName = packageManager.getApplicationLabel(applicationInfo).toString();
            uidToNameMap.put(applicationInfo.uid, appName);
        }
        return uidToNameMap;
    }

    public static void logPacket(Packet packet) {
        Packet.IP4Header.TransportProtocol protocol = packet.ip4Header.protocol;
        List<ParsedProcEntry> connections;
        if (protocol == Packet.IP4Header.TransportProtocol.TCP) {
            // может быть можно кэшировать соединения, чтобы не читать из файла для каждого пакета
            connections = ParsedProcEntry.parse("/proc/net/tcp");
            connections.addAll(ParsedProcEntry.parse("/proc/net/tcp6"));
        } else if (protocol == Packet.IP4Header.TransportProtocol.UDP) {
            connections = ParsedProcEntry.parse("/proc/net/udp");
        } else {
            connections = Collections.emptyList();
        }

        // Приложение отправляет пакет, но в списке коннесшенов его нет. Все время uid == 0
        // У приложения Simple TCP Test uid == 10059.
        // Во-вторых, логер нужно поставить в другом месте, здесь логируется не все пакеты.
        for (ParsedProcEntry p : connections) {
            if (packet.ip4Header.sourceAddress.equals(p.getLocalAddress()) && packet.tcpHeader.sourcePort == p.getPort()) {
                Log.d(TAG, getAppName(p.getUid()) + ": " + packet.toString());

                // FIXME Временно добавил логирование сырых байтов, для сравнения с wireshark
//                StringBuilder sb = new StringBuilder();
//                for (byte b : Arrays.copyOf(packet.backingBuffer.array(), packet.backingBuffer.limit())) {
//                    sb.append(String.format("%02X ", b));
//                }
//                Log.i(TAG, "INPUT: " + sb.toString());
            }
        }
    }

    private static String getAppName(int uid) {
        return installedAppsNames.get(uid);
    }

}
