using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace Hazel.Udp.FewerThreads
{
    /// <summary>
    ///     Listens for new UDP connections and creates UdpConnections for them.
    /// </summary>
    /// <inheritdoc />
    public class ThreadLimitedUdpConnectionListener : NetworkConnectionListener
    {
        private struct SendMessageInfo
        {
            public SmartBuffer Span;
            public IPEndPoint Recipient;
        }

        private struct ReceiveMessageInfo
        {
            public MessageReader Message;
            public IPEndPoint Sender;
            public ConnectionId ConnectionId;
        }

        private const int SendReceiveBufferSize = 1024 * 1024;

        private Socket socket;
        protected ILogger Logger;

        private Thread reliablePacketThread;
        private Thread receiveThread;
        private Thread sendThread;
        private HazelThreadPool processThreads;

        public bool ReceiveThreadRunning => this.receiveThread.ThreadState == ThreadState.Running;

        public struct ConnectionId : IEquatable<ConnectionId>
        {
            public IPEndPoint EndPoint;
            public int Serial;

            public static ConnectionId Create(IPEndPoint endPoint, int serial)
            {
                return new ConnectionId
                {
                    EndPoint = endPoint,
                    Serial = serial,
                };
            }

            public bool Equals(ConnectionId other)
            {
                return this.Serial == other.Serial
                    && this.EndPoint.Equals(other.EndPoint)
                    ;
            }

            public override bool Equals(object obj)
            {
                if (obj is ConnectionId)
                {
                    return this.Equals((ConnectionId)obj);
                }

                return false;
            }

            public override int GetHashCode()
            {
                ///NOTE(mendsley): We're only hashing the endpoint
                /// here, as the common case will have one
                /// connection per address+port tuple.
                return this.EndPoint.GetHashCode();
            }
        }

        protected ConcurrentDictionary<ConnectionId, ThreadLimitedUdpServerConnection> allConnections = new ConcurrentDictionary<ConnectionId, ThreadLimitedUdpServerConnection>();

        private BlockingCollection<ReceiveMessageInfo> receiveQueue;
        private BlockingCollection<SendMessageInfo> sendQueue = new BlockingCollection<SendMessageInfo>();

        public int MaxAge
        {
            get
            {
                var now = DateTime.UtcNow;
                TimeSpan max = new TimeSpan();
                foreach (var con in allConnections.Values)
                {
                    var val = now - con.CreationTime;
                    if (val > max) max = val;
                }

                return (int)max.TotalSeconds;
            }
        }

        public override double AveragePing => this.allConnections.Values.Sum(c => c.AveragePingMs) / this.allConnections.Count;
        public override int ConnectionCount { get { return this.allConnections.Count; } }
        public override int SendQueueLength { get { return this.sendQueue.Count; } }
        public override int ReceiveQueueLength { get { return this.receiveQueue.Count; } }

        private bool isActive;

        public ThreadLimitedUdpConnectionListener(int numWorkers, IPEndPoint endPoint, ILogger logger, IPMode ipMode = IPMode.IPv4)
        {
            this.Logger = logger;
            this.EndPoint = endPoint;
            this.IPMode = ipMode;

            this.receiveQueue = new BlockingCollection<ReceiveMessageInfo>(10000);

            this.socket = UdpConnection.CreateSocket(this.IPMode);
            this.socket.ExclusiveAddressUse = true;
            this.socket.Blocking = false;

            this.socket.ReceiveBufferSize = SendReceiveBufferSize;
            this.socket.SendBufferSize = SendReceiveBufferSize;

            this.reliablePacketThread = new Thread(ManageReliablePackets);
            this.sendThread = new Thread(SendLoop);
            this.receiveThread = new Thread(ReceiveLoop);
            this.processThreads = new HazelThreadPool(numWorkers, ProcessingLoop);
        }

        ~ThreadLimitedUdpConnectionListener()
        {
            this.Dispose(false);
        }

        // This is just for booting people after they've been connected a certain amount of time...
        public void DisconnectOldConnections(TimeSpan maxAge, MessageWriter disconnectMessage)
        {
            var now = DateTime.UtcNow;
            foreach (var conn in this.allConnections.Values)
            {
                if (now - conn.CreationTime > maxAge)
                {
                    conn.Disconnect("Stale Connection", disconnectMessage);
                }
            }
        }

        private void ManageReliablePackets()
        {
            while (this.isActive)
            {
                foreach (var kvp in this.allConnections)
                {
                    var sock = kvp.Value;
                    sock.ManageReliablePackets();
                }

                Thread.Sleep(100);
            }
        }

        public override void Start()
        {
            try
            {
                socket.Bind(EndPoint);
            }
            catch (SocketException e)
            {
                throw new HazelException("Could not start listening as a SocketException occurred", e);
            }

            this.isActive = true;
            this.reliablePacketThread.Start();
            this.sendThread.Start();
            this.receiveThread.Start();
            this.processThreads.Start();
        }

        private void ReceiveLoop()
        {
            while (this.isActive)
            {
                if (this.socket.Poll(1000, SelectMode.SelectRead))
                {
                    if (!isActive) break;

                    EndPoint remoteEP = new IPEndPoint(this.EndPoint.Address, this.EndPoint.Port);
                    var message = MessageReader.GetSized(this.ReceiveBufferSize);
                    try
                    {
                        message.Length = socket.ReceiveFrom(message.Buffer, 0, message.Buffer.Length, SocketFlags.None, ref remoteEP);
                    }
                    catch (SocketException sx)
                    {
                        message.Recycle();
                        if (sx.SocketErrorCode == SocketError.NotConnected)
                        {
                            this.InvokeInternalError(HazelInternalErrors.ConnectionDisconnected);
                            return;
                        }

                        this.Logger.WriteError("Socket Ex in ReceiveLoop: " + sx.Message);
                        continue;
                    }
                    catch (Exception ex)
                    {
                        message.Recycle();
                        this.Logger.WriteError("Stopped due to: " + ex.Message);
                        return;
                    }

                    ConnectionId connectionId = ConnectionId.Create((IPEndPoint)remoteEP, 0);
                    this.ProcessIncomingMessageFromOtherThread(message, (IPEndPoint)remoteEP, connectionId);
                }
            }
        }

        private void ProcessingLoop()
        {
            foreach (ReceiveMessageInfo msg in this.receiveQueue.GetConsumingEnumerable())
            {
                try
                {
                    this.ReadCallback(msg.Message, msg.Sender, msg.ConnectionId);
                }
                catch
                {

                }
            }
        }

        protected void ProcessIncomingMessageFromOtherThread(MessageReader message, IPEndPoint remoteEndPoint, ConnectionId connectionId)
        {
            var info = new ReceiveMessageInfo() { Message = message, Sender = remoteEndPoint, ConnectionId = connectionId };
            if (!this.receiveQueue.TryAdd(info))
            {
                this.Statistics.AddReceiveThreadBlocking();
                this.receiveQueue.Add(info);
            }
        }

        private void SendLoop()
        {
            foreach (SendMessageInfo msg in this.sendQueue.GetConsumingEnumerable())
            {
                try
                {
                    using var buffer = msg.Span;
                    if (this.socket.Poll(Timeout.Infinite, SelectMode.SelectWrite))
                    {
                        this.socket.SendTo((byte[])buffer, 0, buffer.Length, SocketFlags.None, msg.Recipient);
                        this.Statistics.AddBytesSent(buffer.Length);
                    }
                    else
                    {
                        this.Logger.WriteError("Socket is no longer able to send");
                        break;
                    }
                }
                catch (Exception e)
                {
                    this.Logger.WriteError("Error in loop while sending: " + e.Message);
                    Thread.Sleep(1);
                }
            }
        }

        protected virtual void ReadCallback(MessageReader message, IPEndPoint remoteEndPoint, ConnectionId connectionId)
        {
            int bytesReceived = message.Length;
            bool aware = true;
            bool isHello = message.Buffer[0] == (byte)UdpSendOption.Hello;

            // If we're aware of this connection use the one already
            // If this is a new client then connect with them!
            ThreadLimitedUdpServerConnection connection;
            if (!this.allConnections.TryGetValue(connectionId, out connection))
            {
                lock (this.allConnections)
                {
                    if (!this.allConnections.TryGetValue(connectionId, out connection))
                    {
                        // Check for malformed connection attempts
                        if (!isHello)
                        {
                            message.Recycle();
                            return;
                        }

                        if (AcceptConnection != null)
                        {
                            if (!AcceptConnection(remoteEndPoint, message.Buffer, out byte[] response))
                            {
                                message.Recycle();
                                if (response != null)
                                {
                                    using SmartBuffer buffer = this.bufferPool.GetObject();
                                    buffer.CopyFrom(response);
                                    SendDataRaw(buffer, remoteEndPoint);
                                }

                                return;
                            }
                        }

                        aware = false;
                        connection = new ThreadLimitedUdpServerConnection(this, connectionId, remoteEndPoint, this.IPMode, this.Logger);
                        if (!this.allConnections.TryAdd(connectionId, connection))
                        {
                            throw new HazelException("Failed to add a connection. This should never happen.");
                        }
                    }
                }
            }

            // If it's a new connection invoke the NewConnection event.
            // This needs to happen before handling the message because in localhost scenarios, the ACK and
            // subsequent messages can happen before the NewConnection event sets up OnDataRecieved handlers
            if (!aware)
            {
                // Skip header and hello byte;
                message.Offset = 4;
                message.Length = bytesReceived - 4;
                message.Position = 0;
                try
                {
                    this.InvokeNewConnection(message, connection);
                }
                catch (Exception e)
                {
                    this.Logger.WriteError("NewConnection handler threw: " + e);
                }
            }

            // Inform the connection of the buffer (new connections need to send an ack back to client)
            connection.HandleReceive(message, bytesReceived);
        }

        internal void SendDataRaw(SmartBuffer response, IPEndPoint remoteEndPoint)
        {
            QueueRawData(response, remoteEndPoint);
        }

        protected virtual void QueueRawData(SmartBuffer span, IPEndPoint remoteEndPoint)
        {
            span.AddUsage();
            this.sendQueue.TryAdd(new SendMessageInfo() { Span = span, Recipient = remoteEndPoint });
        }

        /// <summary>
        ///     Removes a virtual connection from the list.
        /// </summary>
        /// <param name="endPoint">Connection key of the virtual connection.</param>
        internal bool RemoveConnectionTo(ConnectionId connectionId)
        {
            return this.allConnections.TryRemove(connectionId, out _);
        }

        /// <summary>
        ///  This is after all messages could be sent. Clean up anything extra.
        /// </summary>
        internal virtual void RemovePeerRecord(ConnectionId connectionId)
        {
        }

        protected override void Dispose(bool disposing)
        {
            foreach (var kvp in this.allConnections)
            {
                kvp.Value.Dispose();
            }

            bool wasActive = this.isActive;
            this.isActive = false;

            // Flush outgoing packets
            this.sendQueue?.CompleteAdding();
            this.receiveQueue?.CompleteAdding();

            if (wasActive)
            {
                this.sendThread.Join();
                this.reliablePacketThread.Join();
                this.receiveThread.Join();
                this.processThreads.Join();
            }

            try { this.socket.Shutdown(SocketShutdown.Both); } catch { }
            try { this.socket.Close(); } catch { }
            try { this.socket.Dispose(); } catch { }

            this.receiveQueue?.Dispose();
            this.receiveQueue = null;
            this.sendQueue?.Dispose();
            this.sendQueue = null;

            base.Dispose(disposing);
        }
    }
}
