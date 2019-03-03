/*
 ** Copyright 2015, Mohamed Naufal
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */

package xyz.hexene.localvpn;

import android.util.Log;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.Random;
import java.util.concurrent.ConcurrentLinkedQueue;

import xyz.hexene.localvpn.Packet.TCPHeader;
import xyz.hexene.localvpn.TCB.TCBStatus;

/**
 * В этом классе выполянется отправка исходящих пакетов в сеть, и обработка ответов о статусе соедидения и получении пакетов.
 * В конечном счете на основании ответа из сети формируется пакет, который помещяется в очередь пакетов,
 * которые будут напрявлены в приложение.
 * <p>
 * Отправляет ответы в сеть.
 */
public class TCPOutput implements Runnable {
    private static final String TAG = TCPOutput.class.getSimpleName();

    private LocalVPNService vpnService;
    private ConcurrentLinkedQueue<Packet> inputQueue;
    private ConcurrentLinkedQueue<ByteBuffer> outputQueue;
    private Selector selector;

    private Random random = new Random();

    /**
     * @param inputQueue
     * @param outputQueue
     * @param selector
     * @param vpnService
     */
    public TCPOutput(ConcurrentLinkedQueue<Packet> inputQueue, ConcurrentLinkedQueue<ByteBuffer> outputQueue,
                     Selector selector, LocalVPNService vpnService) {
        this.inputQueue = inputQueue; // deviceToNetworkTCPQueue - сюда записываются пакеты прочитанные из канала - исходящий tcp траффик
        this.outputQueue = outputQueue; // networkToDeviceQueue - входящий трафик из интернета
        this.selector = selector;
        this.vpnService = vpnService;
    }

    @Override
    public void run() {
        Log.i(TAG, "Started");
        try {

            Thread currentThread = Thread.currentThread();
            while (true) {
                Packet currentPacket;
                // TODO: Block when not connected
                do {
                    currentPacket = inputQueue.poll();
//                    Log.d(TAG, "Get packet from queue");
                    if (currentPacket != null)
                        break;
                    Thread.sleep(10);
                } while (!currentThread.isInterrupted());

                if (currentThread.isInterrupted())
                    break;

                ByteBuffer payloadBuffer = currentPacket.backingBuffer; // Этот будеф откуда сюда попадает.
                currentPacket.backingBuffer = null; // Почему обнуляется буфер? Может чтобы переиспользовать.
                ByteBuffer responseBuffer = ByteBufferPool.acquire(); // просто создает буфер или переиспользует закэшированный

                InetAddress destinationAddress = currentPacket.ip4Header.destinationAddress;

                TCPHeader tcpHeader = currentPacket.tcpHeader;
                int destinationPort = tcpHeader.destinationPort;
                int sourcePort = tcpHeader.sourcePort;

                String ipAndPort = destinationAddress.getHostAddress() + ":" +
                        destinationPort + ":" + sourcePort;


//                Log.d(TAG, notEqualTag + String.format("run: destIp:destPort:srcPort = %s; seq = %d; payloadLength = %d; next expected seq: %d",
//                        ipAndPort, currentPacket.tcpHeader.sequenceNumber, payloadLength, nextExpectedSequence)
//                );

                TCB tcb = TCB.getTCB(ipAndPort); // кэш соединений
                if (tcb == null) {
                    Log.d(TAG, "run: tcb == null");

                    initializeConnection(ipAndPort, destinationAddress, destinationPort,
                            currentPacket, tcpHeader, responseBuffer);
                } else if (tcpHeader.isSYN()) {
                    Log.d(TAG, "run: tcp is SYN");

                    processDuplicateSYN(tcb, tcpHeader, responseBuffer);
                } else if (tcpHeader.isRST()) {
                    Log.d(TAG, "run: tcp is RST");

                    closeCleanly(tcb, responseBuffer);
                } else if (tcpHeader.isFIN()) {
                    Log.d(TAG, "run: tcp is FIN");

                    processFIN(tcb, tcpHeader, responseBuffer);
                } else if (tcpHeader.isACK()) {
                    Log.d(TAG, "run: tcp is ACK");

                    processACK(tcb, tcpHeader, payloadBuffer, responseBuffer);
                }

                // XXX: cleanup later
                if (responseBuffer.position() == 0) {
                    Log.d(TAG, "run: clean empty buffer");

                    ByteBufferPool.release(responseBuffer);
                }
                ByteBufferPool.release(payloadBuffer);
            }
        } catch (
                InterruptedException e) {
            Log.i(TAG, "Stopping");
        } catch (
                IOException e) {
            Log.e(TAG, e.toString(), e);
        } finally {
            TCB.closeAll();
        }
    }

    private void initializeConnection(String ipAndPort, InetAddress destinationAddress, int destinationPort,
                                      Packet currentPacket, TCPHeader tcpHeader, ByteBuffer responseBuffer)
            throws IOException {
        currentPacket.swapSourceAndDestination(); // Такое ощущение, что эта перестановка влияет только на поля пакета, а буфер не меняется.
        if (tcpHeader.isSYN()) {
            SocketChannel outputChannel = SocketChannel.open();
            outputChannel.configureBlocking(false);
            // Чтобы исключить сокет из под VPN.
            // В противном случае, обработанные пакеты снова будут перехватываться, и так по кругу.
            vpnService.protect(outputChannel.socket());

            TCB tcb = new TCB(ipAndPort, random.nextInt(Short.MAX_VALUE + 1), tcpHeader.sequenceNumber, tcpHeader.sequenceNumber + 1,
                    tcpHeader.acknowledgementNumber, outputChannel, currentPacket);


            TCB.putTCB(ipAndPort, tcb);
            Log.d(TAG, "initializeConnection: Create TCB");

            try {
                outputChannel.connect(new InetSocketAddress(destinationAddress, destinationPort)); // здесь отправляется начальный SYN, я полагаю
                Log.d(TAG, "initializeConnection: open connection");

                if (outputChannel.finishConnect()) {
                    Log.d(TAG, "initializeConnection: finish connection");

                    tcb.status = TCBStatus.SYN_RECEIVED;
                    // TODO: Set MSS for receiving larger packets from the device
                    currentPacket.updateTCPBuffer(responseBuffer, (byte) (TCPHeader.SYN | TCPHeader.ACK),
                            tcb.getMySequenceNum(), tcb.myAcknowledgementNum, 0);
                    tcb.addMySequenceNum(1); // SYN counts as a byte
                } else {
                    tcb.status = TCBStatus.SYN_SENT;
                    Log.d(TAG, "initializeConnection: sent TCP, but not finished connection");

                    selector.wakeup();
                    tcb.selectionKey = outputChannel.register(selector, SelectionKey.OP_CONNECT, tcb);
                    return;
                }
            } catch (IOException e) {
                Log.e(TAG, "Connection error: " + ipAndPort, e);
                currentPacket.updateTCPBuffer(responseBuffer, (byte) TCPHeader.RST, 0, tcb.myAcknowledgementNum, 0);
                TCB.closeTCB(tcb);
            }
        } else {
            Log.d(TAG, "initializeConnection: reset packet");

            currentPacket.updateTCPBuffer(responseBuffer, (byte) TCPHeader.RST,
                    0, tcpHeader.sequenceNumber + 1, 0);
        }
        outputQueue.offer(responseBuffer);
        Log.d(TAG, "initializeConnection: add buffer to queue");

    }

    private void processDuplicateSYN(TCB tcb, TCPHeader tcpHeader, ByteBuffer responseBuffer) {
        synchronized (tcb) {
            if (tcb.status == TCBStatus.SYN_SENT) {
                Log.d(TAG, "processDuplicateSYN: in synchronized block");

                tcb.myAcknowledgementNum = tcpHeader.sequenceNumber + 1;
                return;
            }
        }
        sendRST(tcb, 1, responseBuffer);
    }

    private void processFIN(TCB tcb, TCPHeader tcpHeader, ByteBuffer responseBuffer) {
        synchronized (tcb) {
            Packet referencePacket = tcb.referencePacket;
            tcb.myAcknowledgementNum = tcpHeader.sequenceNumber + 1;
            tcb.theirAcknowledgementNum = tcpHeader.acknowledgementNumber;

            if (tcb.waitingForNetworkData) {
                tcb.status = TCBStatus.CLOSE_WAIT;
                Log.d(TAG, "processFIN: set CLOSE_WAIT status");

                referencePacket.updateTCPBuffer(responseBuffer, (byte) TCPHeader.ACK,
                        tcb.getMySequenceNum(), tcb.myAcknowledgementNum, 0);
            } else {
                tcb.status = TCBStatus.LAST_ACK;
                Log.d(TAG, "processFIN: set LAST_ACK status");

                referencePacket.updateTCPBuffer(responseBuffer, (byte) (TCPHeader.FIN | TCPHeader.ACK),
                        tcb.getMySequenceNum(), tcb.myAcknowledgementNum, 0);
                tcb.addMySequenceNum(1); // FIN counts as a byte
            }
        }
        outputQueue.offer(responseBuffer);
    }

    private void processACK(TCB tcb, TCPHeader tcpHeader, ByteBuffer payloadBuffer, ByteBuffer responseBuffer) throws IOException {
        int payloadSize = payloadBuffer.limit() - payloadBuffer.position();

        synchronized (tcb) {
            SocketChannel outputChannel = tcb.channel;
            if (tcb.status == TCBStatus.SYN_RECEIVED) {
                tcb.status = TCBStatus.ESTABLISHED;
                Log.d(TAG, "processACK: status ESTABLISHED, before selector wakeup");


                selector.wakeup();
                tcb.selectionKey = outputChannel.register(selector, SelectionKey.OP_READ, tcb);
                tcb.waitingForNetworkData = true;
            } else if (tcb.status == TCBStatus.LAST_ACK) {
                closeCleanly(tcb, responseBuffer);
                return;
            }

            if (payloadSize == 0) {
                Log.d(TAG, "processACK: empty ACK");

                return; // Empty ACK, ignore
            }

            if (!tcb.waitingForNetworkData) {
                Log.d(TAG, "processACK: waitingForNetworkData == false");

                selector.wakeup();
                tcb.selectionKey.interestOps(SelectionKey.OP_READ);
                tcb.waitingForNetworkData = true;
            }

            // Forward to remote server
            try {
                while (payloadBuffer.hasRemaining()) {
                    Log.d(TAG, "processACK: send buffer to network. buffer position: " + payloadBuffer.position());

                    //TODO Данные пишутся с 40 позиции. Откуда берутся первые 40 байт? Они не нужны, ведь сокет сам реализует TCP/IP.

                    outputChannel.write(payloadBuffer); // отправляет данные в сеть
                }
            } catch (IOException e) {
                Log.e(TAG, "Network write error: " + tcb.ipAndPort, e);
                sendRST(tcb, payloadSize, responseBuffer);
                return;
            }

            // TODO: We don't expect out-of-order packets, but verify
//            if (tcb.myAcknowledgementNum != tcpHeader.sequenceNumber || tcb.getMySequenceNum() != tcpHeader.acknowledgementNumber) {
//                Log.d(TAG, "ORDER IS BROKEN.\n"
//                        + "destIp:destPort:srcPort = " + tcb.ipAndPort
//                        + String.format("FROM APP -> seq: %d, ack %d \n", tcpHeader.sequenceNumber, tcpHeader.acknowledgementNumber)
//                        + String.format("FROM SERVER -> seq: %d, ack %d", tcb.getMySequenceNum(), tcb.myAcknowledgementNum));
//            }


            // Ошибка то ли при отправке пакета приложению, то ли при приеме из сети.
            tcb.myAcknowledgementNum = tcpHeader.sequenceNumber + payloadSize;
            tcb.theirAcknowledgementNum = tcpHeader.acknowledgementNumber;
            Packet referencePacket = tcb.referencePacket;
            Log.d(TAG, "processACK: end of method");

            referencePacket.updateTCPBuffer(responseBuffer, (byte) TCPHeader.ACK, tcb.getMySequenceNum(), tcb.myAcknowledgementNum, 0);
        }
        outputQueue.offer(responseBuffer);
    }

    private void sendRST(TCB tcb, int prevPayloadSize, ByteBuffer buffer) {
        tcb.referencePacket.updateTCPBuffer(buffer, (byte) TCPHeader.RST, 0, tcb.myAcknowledgementNum + prevPayloadSize, 0);
        Log.d(TAG, "sendRST: add buffer");

        outputQueue.offer(buffer);
        TCB.closeTCB(tcb);
    }

    private void closeCleanly(TCB tcb, ByteBuffer buffer) {
        ByteBufferPool.release(buffer);
        TCB.closeTCB(tcb);
    }
}
