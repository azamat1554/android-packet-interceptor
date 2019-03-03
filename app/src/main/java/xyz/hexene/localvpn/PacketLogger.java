package xyz.hexene.localvpn;

import android.app.Application;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.support.annotation.NonNull;
import android.util.Log;
import android.util.SparseArray;

import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import com.google.firebase.firestore.DocumentReference;
import com.google.firebase.firestore.FieldValue;
import com.google.firebase.firestore.FirebaseFirestore;
import com.google.firebase.firestore.WriteBatch;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

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
    private static FirebaseFirestore db;
    private static AtomicInteger counter = new AtomicInteger(0);
    private static WriteBatch batch;


    @Override
    public void onCreate() {
        super.onCreate();

        // get a list of installed apps.
        installedAppsNames = initializeInstalledApps();
        // create db
        db = FirebaseFirestore.getInstance();
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

    public synchronized static void logPacket(Packet packet) {
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
            Packet.IP4Header ip4Header = packet.ip4Header;
            Packet.TCPHeader tcpHeader = packet.tcpHeader;
            Packet.UDPHeader udpHeader = packet.udpHeader;
            //TODO Некоторые пакеты соответствуют приложению 'Local VPN' что страно. Стоил либо их фильтровать здесь, либо они вообще не должны сюда попадаться.
            if (ip4Header.sourceAddress.equals(p.getLocalAddress()) && tcpHeader.sourcePort == p.getPort() && getAppName(p.getUid()) != null) {
                Map<String, Object> packetData = new HashMap<>();
                packetData.put("app_name", getAppName(p.getUid()));
                packetData.put("source_ip", ip4Header.sourceAddress.getHostAddress());
                packetData.put("destination_ip", ip4Header.destinationAddress.getHostAddress());
                packetData.put("protocol", protocol.name());
                if (protocol == Packet.IP4Header.TransportProtocol.TCP) {
                    packetData.put("source_port", tcpHeader.sourcePort);
                    packetData.put("destination_port", tcpHeader.destinationPort);
                    packetData.put("payload_length", ip4Header.totalLength - (ip4Header.headerLength + tcpHeader.headerLength));
                } else if (protocol == Packet.IP4Header.TransportProtocol.UDP) {
                    packetData.put("source_port", udpHeader.sourcePort);
                    packetData.put("destination_port", udpHeader.destinationPort);
                    packetData.put("payload_length", udpHeader.length - Packet.UDP_HEADER_SIZE);
                }
                packetData.put("timestamp", FieldValue.serverTimestamp());

                persist(packetData);


                // FIXME Временно добавил логирование сырых байтов, для сравнения с wireshark
//                StringBuilder sb = new StringBuilder();
//                for (byte b : Arrays.copyOf(packet.backingBuffer.array(), packet.backingBuffer.limit())) {
//                    sb.append(String.format("%02X ", b));
//                }
//                Log.i(TAG, "INPUT: " + sb.toString());
            }
        }
    }

    private static void persist(Map<String, Object> packetData) {
        WriteBatch batch = getBatch();
        batch.set(createDoc(), packetData);
        if (counter.incrementAndGet() == 100) {
            flush();
            counter.set(0);
        }
    }

    public static void flush() {
        if (counter.intValue() > 0) {
            getBatch().commit().addOnCompleteListener(
                    new OnCompleteListener<Void>() {
                        @Override
                        public void onComplete(@NonNull Task<Void> task) {
                            Log.d(TAG, "onComplete: Complete");
                        }
                    });
        }
    }

    private static WriteBatch getBatch() {
        if (counter.intValue() == 0)
            batch = db.batch();
        return batch;
    }

    private static DocumentReference createDoc() {
        return db.collection("packets").document();
    }

    private static String getAppName(int uid) {
        return installedAppsNames.get(uid);
    }

}
