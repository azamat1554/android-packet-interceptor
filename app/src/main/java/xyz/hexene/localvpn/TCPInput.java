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

public class TCPInput implements Runnable
{
    private static final String TAG = TCPInput.class.getSimpleName();
    private static final int HEADER_SIZE = Packet.IP4_HEADER_SIZE + Packet.TCP_HEADER_SIZE;

    private ConcurrentLinkedQueue<ByteBuffer> outputQueue;
    private Selector selector;

    public TCPInput(ConcurrentLinkedQueue<ByteBuffer> outputQueue, Selector selector)
    {
        this.outputQueue = outputQueue;
        this.selector = selector;
    }

    @Override
    public void run()
    {
        try
        {
            Log.d(TAG, "Started");
            while (!Thread.interrupted())
            {
                int readyChannels = selector.select();

                if (readyChannels == 0) {
                    Thread.sleep(10);
                    continue;
                }

                Set<SelectionKey> keys = selector.selectedKeys();
                Iterator<SelectionKey> keyIterator = keys.iterator();

                while (keyIterator.hasNext() && !Thread.interrupted())
                {
                    SelectionKey key = keyIterator.next();
                    if (key.isValid() && key.isReadable())
                    {
                        keyIterator.remove();
                        ByteBuffer receiveBuffer = ByteBufferPool.acquire();
                        // Leave space for the header
                        receiveBuffer.position(HEADER_SIZE);

                        TCB tcb = (TCB) key.attachment();
                        synchronized (tcb)
                        {
                            Packet referencePacket = tcb.referencePacket;
                            SocketChannel inputChannel = (SocketChannel) key.channel();
                            int readBytes;
                            try
                            {
                                readBytes = inputChannel.read(receiveBuffer);
                            }
                            catch (IOException e)
                            {
                                Log.e(TAG, "Network read error: " + tcb.ipAndPort);
                                referencePacket.updateTCPBuffer(receiveBuffer, (byte) Packet.TCPHeader.RST, 0, tcb.myAcknowledgementNum, 0);
                                outputQueue.offer(receiveBuffer);
                                TCB.closeTCB(tcb);
                                continue;
                            }

                            if (readBytes == -1)
                            {
                                // End of stream, stop waiting until we push more data
                                key.interestOps(0);
                                tcb.waitingForNetworkData = false;

                                if (tcb.status != TCBStatus.CLOSE_WAIT)
                                {
                                    ByteBufferPool.release(receiveBuffer);
                                    continue;
                                }

                                tcb.status = TCBStatus.LAST_ACK;
                                referencePacket.updateTCPBuffer(receiveBuffer, (byte) Packet.TCPHeader.FIN, tcb.mySequenceNum, tcb.myAcknowledgementNum, 0);
                                tcb.mySequenceNum++; // FIN counts as a byte
                            }
                            else
                            {
                                // XXX: We should ideally be splitting segments by MTU/MSS, but this seems to work without
                                referencePacket.updateTCPBuffer(receiveBuffer, (byte) (Packet.TCPHeader.PSH | Packet.TCPHeader.ACK),
                                        tcb.mySequenceNum, tcb.myAcknowledgementNum, readBytes);
                                tcb.mySequenceNum += readBytes; // Next sequence number
                                receiveBuffer.position(HEADER_SIZE + readBytes);
                            }
                        }
                        outputQueue.offer(receiveBuffer);
                    }
                }
            }
        }
        catch (InterruptedException e)
        {
            Log.i(TAG, "Stopping");
        }
        catch (IOException e)
        {
            Log.w(TAG, e.toString(), e);
        }
    }
}