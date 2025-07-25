using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;


namespace Hazel.Udp
{
    /// <summary>
    ///     Represents a client's connection to a server that uses the UDP protocol.
    /// </summary>
    /// <inheritdoc/>
    public class UdpClientConnection : UdpConnection
    {
        /// <summary>
        /// The max size Hazel attempts to read from the network.
        /// Defaults to 8096.
        /// </summary>
        /// <remarks>
        /// 8096 is 5 times the standard modern MTU of 1500, so it's already too large imo.
        /// If Hazel ever implements fragmented packets, then we might consider a larger value since combining 5 
        /// packets into 1 reader would be realistic and would cause reallocations. That said, Hazel is not meant
        /// for transferring large contiguous blocks of data, so... please don't?
        /// </remarks>
        public int ReceiveBufferSize = 8096;

        /// <summary>
        ///     The socket we're connected via.
        /// </summary>
        protected Socket socket;

        /// <summary>
        ///     Reset event that is triggered when the connection is marked Connected.
        /// </summary>
        private ManualResetEvent connectWaitLock = new ManualResetEvent(false);

        protected Timer reliablePacketTimer;

#if DEBUG
        public event Action<byte[], int> DataSentRaw;
        public event Action<byte[], int> DataReceivedRaw;
#endif

        /// <summary>
        ///     Creates a new UdpClientConnection.
        /// </summary>
        /// <param name="remoteEndPoint">A <see cref="NetworkEndPoint"/> to connect to.</param>
        public UdpClientConnection(ILogger logger, IPEndPoint remoteEndPoint, IPMode ipMode = IPMode.IPv4)
            : base(logger)
        {
            this.EndPoint = remoteEndPoint;
            this.IPMode = ipMode;

            this.socket = CreateSocket(ipMode);

            reliablePacketTimer = new Timer(ManageReliablePacketsInternal, null, 100, Timeout.Infinite);
            this.InitializeKeepAliveTimer();
        }

        ~UdpClientConnection()
        {
            this.Dispose(false);
        }

        private void ManageReliablePacketsInternal(object state)
        {
            ManageReliablePackets();
            try
            {
                reliablePacketTimer.Change(100, Timeout.Infinite);
            }
            catch { }
        }

        /// <summary>
        /// Virtual method that can be overridden by subclasses to extend reliable packet management
        /// </summary>
        protected new virtual void ManageReliablePackets()
        {
            base.ManageReliablePackets();
        }

        /// <inheritdoc />
        protected override void WriteBytesToConnection(SmartBuffer bytes, int length)
        {
#if DEBUG
            if (TestLagMs > 0)
            {
                ThreadPool.QueueUserWorkItem(a => { Thread.Sleep(this.TestLagMs); WriteBytesToConnectionReal(bytes, length); });
            }
            else
#endif
            {
                WriteBytesToConnectionReal(bytes, length);
            }
        }

        private void WriteBytesToConnectionReal(SmartBuffer bytes, int length)
        {
#if DEBUG
            DataSentRaw?.Invoke((byte[])bytes, length);
#endif

            try
            {
                this.Statistics.LogPacketSend(length);
                bytes.AddUsage();
                socket.BeginSendTo(
                    (byte[])bytes,
                    0,
                    length,
                    SocketFlags.None,
                    EndPoint,
                    HandleSendTo,
                    bytes);
            }
            catch (NullReferenceException) { }
            catch (ObjectDisposedException)
            {
                // Already disposed and disconnected...
            }
            catch (SocketException ex)
            {
                DisconnectInternal(HazelInternalErrors.SocketExceptionSend, "Could not send data as a SocketException occurred: " + ex.Message);
            }
        }

        private void HandleSendTo(IAsyncResult result)
        {
            try
            {
                socket.EndSendTo(result);
            }
            catch (NullReferenceException) { }
            catch (ObjectDisposedException)
            {
                // Already disposed and disconnected...
            }
            catch (SocketException ex)
            {
                DisconnectInternal(HazelInternalErrors.SocketExceptionSend, "Could not send data as a SocketException occurred: " + ex.Message);
            }
            finally
            {
                ((SmartBuffer)result.AsyncState).Recycle();
            }
        }

        /// <inheritdoc />
        public override void Connect(byte[] bytes = null, int timeout = 5000)
        {
            this.ConnectAsync(bytes);

            //Wait till hello packet is acknowledged and the state is set to Connected
            bool timedOut = !WaitOnConnect(timeout);

            //If we timed out raise an exception
            if (timedOut)
            {
                Dispose();
                throw new HazelException("Connection attempt timed out.");
            }
        }

        /// <inheritdoc />
        public override void ConnectAsync(byte[] bytes = null)
        {
            this.State = ConnectionState.Connecting;

            try
            {
                if (IPMode == IPMode.IPv4)
                    socket.Bind(new IPEndPoint(IPAddress.Any, 0));
                else
                    socket.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));
            }
            catch (SocketException e)
            {
                this.State = ConnectionState.NotConnected;
                throw new HazelException("A SocketException occurred while binding to the port.", e);
            }

            try
            {
                StartListeningForData();
            }
            catch (ObjectDisposedException)
            {
                // If the socket's been disposed then we can just end there but make sure we're in NotConnected state.
                // If we end up here I'm really lost...
                this.State = ConnectionState.NotConnected;
                return;
            }
            catch (SocketException e)
            {
                Dispose();
                throw new HazelException("A SocketException occurred while initiating a receive operation.", e);
            }

            // Write bytes to the server to tell it hi (and to punch a hole in our NAT, if present)
            // When acknowledged set the state to connected
            SendHello(bytes, () =>
            {
                this.State = ConnectionState.Connected;
                this.InitializeKeepAliveTimer();
            });
        }

        /// <summary>
        ///     Instructs the listener to begin listening.
        /// </summary>
        protected void StartListeningForData()
        {
#if DEBUG
            if (this.TestLagMs > 0)
            {
                Thread.Sleep(this.TestLagMs);
            }
#endif

            var msg = MessageReader.GetSized(this.ReceiveBufferSize);
            try
            {
                socket.BeginReceive(msg.Buffer, 0, msg.Buffer.Length, SocketFlags.None, ReadCallback, msg);
            }
            catch
            {
                msg.Recycle();
                this.Dispose();
            }
        }

        protected override void SetState(ConnectionState state)
        {
            try
            {
                // If the server disconnects you during the hello
                // you can go straight from Connecting to NotConnected.
                if (state == ConnectionState.Connected
                    || state == ConnectionState.NotConnected)
                {
                    connectWaitLock.Set();
                }
                else
                {
                    connectWaitLock.Reset();
                }
            }
            catch (ObjectDisposedException)
            {
            }
        }

        /// <summary>
        ///     Blocks until the Connection is connected.
        /// </summary>
        /// <param name="timeout">The number of milliseconds to wait before timing out.</param>
        public bool WaitOnConnect(int timeout)
        {
            return connectWaitLock.WaitOne(timeout);
        }

        /// <summary>
        ///     Called when data has been received by the socket.
        /// </summary>
        /// <param name="result">The asyncronous operation's result.</param>
        void ReadCallback(IAsyncResult result)
        {
            var msg = (MessageReader)result.AsyncState;

            try
            {
                msg.Length = socket.EndReceive(result);
            }
            catch (SocketException e)
            {
                msg.Recycle();
                DisconnectInternal(HazelInternalErrors.SocketExceptionReceive, "Socket exception while reading data: " + e.Message);
                return;
            }
            catch (Exception)
            {
                msg.Recycle();
                return;
            }

            //Exit if no bytes read, we've failed.
            if (msg.Length == 0)
            {
                msg.Recycle();
                DisconnectInternal(HazelInternalErrors.ReceivedZeroBytes, "Received 0 bytes");
                return;
            }

            //Begin receiving again
            try
            {
                StartListeningForData();
            }
            catch (SocketException e)
            {
                DisconnectInternal(HazelInternalErrors.SocketExceptionReceive, "Socket exception during receive: " + e.Message);
            }
            catch (ObjectDisposedException)
            {
                //If the socket's been disposed then we can just end there.
                return;
            }

#if DEBUG
            if (this.TestDropRate > 0)
            {
                if ((this.testDropCount++ % this.TestDropRate) == 0)
                {
                    return;
                }
            }

            DataReceivedRaw?.Invoke(msg.Buffer, msg.Length);
#endif
            HandleReceive(msg, msg.Length);
        }

        /// <summary>
        ///     Sends a disconnect message to the end point.
        ///     You may include optional disconnect data. The SendOption must be unreliable.
        /// </summary>
        protected override bool SendDisconnect(MessageWriter data = null)
        {
            lock (this)
            {
                if (this._state == ConnectionState.NotConnected) return false;
                this.State = ConnectionState.NotConnected; // Use the property so we release the state lock
            }

            var bytes = EmptyDisconnectBytes;
            if (data != null && data.Length > 0)
            {
                if (data.SendOption != SendOption.None) throw new ArgumentException("Disconnect messages can only be unreliable.");

                bytes = data.ToByteArray(true);
                bytes[0] = (byte)UdpSendOption.Disconnect;
            }

            try
            {
                socket.SendTo(
                    bytes,
                    0,
                    bytes.Length,
                    SocketFlags.None,
                    EndPoint);
            }
            catch { }

            return true;
        }

        /// <inheritdoc />
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                SendDisconnect();
            }

            try { this.socket.Shutdown(SocketShutdown.Both); } catch { }
            try { this.socket.Close(); } catch { }
            try { this.socket.Dispose(); } catch { }

            this.reliablePacketTimer.Dispose();
            this.connectWaitLock.Dispose();

            base.Dispose(disposing);
        }
    }
}