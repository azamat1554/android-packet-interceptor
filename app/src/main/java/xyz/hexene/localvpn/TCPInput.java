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
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;

import xyz.hexene.localvpn.TCB.TCBStatus;

/**
 * Этот класс выполняет то же что и TCPOutput, только что-то вроде отложенной
 * обработки, если ответ не пришел сразу, тогда нужно подождать ответа от сервера.
 * Может поэтому он называется TCPInput, - типа в ожидании ввода.
 *
 */
public class TCPInput implements Runnable {
    private static final String TAG = TCPInput.class.getSimpleName();
    private static final int HEADER_SIZE = Packet.IP4_HEADER_SIZE + Packet.TCP_HEADER_SIZE;

    private ConcurrentLinkedQueue<ByteBuffer> outputQueue;
    private Selector selector;

    public TCPInput(ConcurrentLinkedQueue<ByteBuffer> outputQueue, Selector selector) {
        this.outputQueue = outputQueue; // входящий траффик
        this.selector = selector;
    }

    @Override
    public void run() {
        try {
            Log.d(TAG, "Started");
            while (!Thread.interrupted()) {
                int readyChannels = selector.select();


                if (readyChannels == 0) {
                    Thread.sleep(10);
                    continue;
                }
                Log.d(TAG, "run: readyChannels == " + readyChannels);


                Set<SelectionKey> keys = selector.selectedKeys();
                Iterator<SelectionKey> keyIterator = keys.iterator();

                while (keyIterator.hasNext() && !Thread.interrupted()) {
                    SelectionKey key = keyIterator.next();
                    if (key.isValid()) {
                        if (key.isConnectable()) {
                            Log.d(TAG, "run: key is connectable");

                            processConnect(key, keyIterator);
                        } else if (key.isReadable()) {
                            Log.d(TAG, "run: key is readable");

                            processInput(key, keyIterator);
                        }
                    }
                }
            }
        } catch (InterruptedException e) {
            Log.i(TAG, "Stopping");
        } catch (IOException e) {
            Log.w(TAG, e.toString(), e);
        }
    }

    private void processConnect(SelectionKey key, Iterator<SelectionKey> keyIterator) {
        TCB tcb = (TCB) key.attachment();
        Packet referencePacket = tcb.referencePacket;
        try {
            if (tcb.channel.finishConnect()) {
                Log.d(TAG, "processConnect: finish connect");

                keyIterator.remove(); // мне кажется, если возможно, лучше вынести наружу метода, будет очевиднее
                tcb.status = TCBStatus.SYN_RECEIVED;

                // TODO: Set MSS for receiving larger packets from the device
                ByteBuffer responseBuffer = ByteBufferPool.acquire();
                referencePacket.updateTCPBuffer(responseBuffer, (byte) (Packet.TCPHeader.SYN | Packet.TCPHeader.ACK),
                        tcb.getMySequenceNum(), tcb.myAcknowledgementNum, 0);

                outputQueue.offer(responseBuffer);

                tcb.addMySequenceNum(1); // SYN counts as a byte
                key.interestOps(SelectionKey.OP_READ);
            }
        } catch (IOException e) {
            Log.e(TAG, "Connection error: " + tcb.ipAndPort, e);
            ByteBuffer responseBuffer = ByteBufferPool.acquire();
            referencePacket.updateTCPBuffer(responseBuffer, (byte) Packet.TCPHeader.RST, 0, tcb.myAcknowledgementNum, 0);
            outputQueue.offer(responseBuffer);
            TCB.closeTCB(tcb);
        }
    }

    private void processInput(SelectionKey key, Iterator<SelectionKey> keyIterator) {
        keyIterator.remove();
        ByteBuffer receiveBuffer = ByteBufferPool.acquire();
        // Leave space for the header
        // заголовок пакета, который будет отправлен в приложение мы формируем сами,
        // и он всегда равен 40 байтов.
        receiveBuffer.position(HEADER_SIZE);

        TCB tcb = (TCB) key.attachment();
        synchronized (tcb) {
            Packet referencePacket = tcb.referencePacket;
            SocketChannel inputChannel = (SocketChannel) key.channel();
            int readBytes;
            try {
                Log.d(TAG, "processInput: try to read input traffic from channel");
                // Записывает в буфер только данные, заголовок уже заполнен
                readBytes = inputChannel.read(receiveBuffer);
            } catch (IOException e) {
                Log.e(TAG, "Network read error: " + tcb.ipAndPort, e);
                referencePacket.updateTCPBuffer(receiveBuffer, (byte) Packet.TCPHeader.RST, 0, tcb.myAcknowledgementNum, 0);
                outputQueue.offer(receiveBuffer);
                TCB.closeTCB(tcb);
                return;
            }

            if (readBytes == -1) {
                // End of stream, stop waiting until we push more data
                key.interestOps(0);
                tcb.waitingForNetworkData = false;

                if (tcb.status != TCBStatus.CLOSE_WAIT) {
                    Log.d(TAG, "processInput: status != CLOSE_WAIT");

                    ByteBufferPool.release(receiveBuffer);
                    return;
                }

                tcb.status = TCBStatus.LAST_ACK;
                Log.d(TAG, "processInput: set LAST_ACK");

                referencePacket.updateTCPBuffer(receiveBuffer, (byte) Packet.TCPHeader.FIN, tcb.getMySequenceNum(), tcb.myAcknowledgementNum, 0);
                tcb.addMySequenceNum(1); // FIN counts as a byte
            } else {
                //FIXME XXX: We should ideally be splitting segments by MTU/MSS, but this seems to work without
                Log.d(TAG, "processInput: buffer has data");

                referencePacket.updateTCPBuffer(receiveBuffer, (byte) (Packet.TCPHeader.PSH | Packet.TCPHeader.ACK),
                        tcb.getMySequenceNum(), tcb.myAcknowledgementNum, readBytes);
                tcb.addMySequenceNum(readBytes); // Next sequence number
                receiveBuffer.position(HEADER_SIZE + readBytes); // устанавливает позицию в конец пакета, чтобы потом сделать flip.
            }
        }
        outputQueue.offer(receiveBuffer);
    }
}
