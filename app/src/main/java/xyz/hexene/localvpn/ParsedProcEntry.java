package xyz.hexene.localvpn;

import android.util.Log;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class ParsedProcEntry {
    private final InetAddress localAddress;
    private final int port;
    private final String state;
    private final int uid;

    private ParsedProcEntry(InetAddress addr, int port, String state, int uid) {
        this.localAddress = addr;
        this.port = port;
        this.state = state;
        this.uid = uid;
    }

    public static List<ParsedProcEntry> parse(String procFilePath) {
        List<ParsedProcEntry> retval = new ArrayList<>();
        /*
         * Sample output of "cat /proc/net/tcp" on emulator:
         *
         * sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  ...
         * 0: 0100007F:13AD 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0   ...
         * 1: 00000000:15B3 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0   ...
         * 2: 0F02000A:15B3 0202000A:CE8A 01 00000000:00000000 00:00000000 00000000     0   ...
         *
         */
        Scanner scanner = null;
        try {
            File procFile = new File(procFilePath);
            scanner = new Scanner(procFile);
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine().trim();
                // Skip column headers
                if (line.startsWith("sl")) {
                    continue;
                }
                String[] fields = line.split("\\s+");
                final int expectedNumColumns = 12;
                if (fields.length < expectedNumColumns) {
                    throw new ProcEntryException(procFilePath + " should have at least " + expectedNumColumns
                            + " columns of output " + fields);
                }

                String state = fields[3];
                int uid = Integer.parseInt(fields[7]);
                InetAddress localIp = addrToInet(fields[1].split(":")[0]);
                int localPort = Integer.parseInt(fields[1].split(":")[1], 16);
                retval.add(new ParsedProcEntry(localIp, localPort, state, uid));
            }
        } catch (IOException e) {
            Log.e(ParsedProcEntry.class.getName(), "Error while parse file: " + procFilePath, e);
        } finally {
            if (scanner != null) {
                scanner.close();
            }
        }
        return retval;
    }

    /**
     * Convert a string stored in little endian format to an IP address.
     */
    private static InetAddress addrToInet(String s) throws UnknownHostException {
        int len = s.length();
        if (len != 8 && len != 32) {
            throw new IllegalArgumentException(len + "");
        }
        byte[] retval = new byte[len / 2];
        for (int i = 0; i < len / 2; i += 4) {
            retval[i] = (byte) ((Character.digit(s.charAt(2 * i + 6), 16) << 4)
                    + Character.digit(s.charAt(2 * i + 7), 16));
            retval[i + 1] = (byte) ((Character.digit(s.charAt(2 * i + 4), 16) << 4)
                    + Character.digit(s.charAt(2 * i + 5), 16));
            retval[i + 2] = (byte) ((Character.digit(s.charAt(2 * i + 2), 16) << 4)
                    + Character.digit(s.charAt(2 * i + 3), 16));
            retval[i + 3] = (byte) ((Character.digit(s.charAt(2 * i), 16) << 4)
                    + Character.digit(s.charAt(2 * i + 1), 16));
        }
        return InetAddress.getByAddress(retval);
    }

    @Override
    public String toString() {
        return "ParsedProcEntry{" +
                "localAddress=" + localAddress +
                ", port=" + port +
                ", state='" + state + '\'' +
                ", uid=" + uid +
                '}';
    }

    public InetAddress getLocalAddress() {
        return localAddress;
    }

    public int getPort() {
        return port;
    }

    public String getState() {
        return state;
    }

    public int getUid() {
        return uid;
    }

    private static class ProcEntryException extends RuntimeException {
        public ProcEntryException(String message) {
            super(message);
        }
    }
}
