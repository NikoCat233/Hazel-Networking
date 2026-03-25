using System;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace Hazel.Udp
{
    /// <summary>
    /// Represents a client's connection to a server that uses the UDP protocol via a SOCKS5 proxy.
    /// </summary>
    /// <inheritdoc/>
    public class Socks5ClientConnection : UdpClientConnection
    {
        /// <summary>
        /// The TCP socket for the SOCKS5 control connection.
        /// </summary>
        private Socket socks5TcpSocket;

        /// <summary>
        /// The SOCKS5 proxy server endpoint.
        /// </summary>
        private readonly IPEndPoint socks5EndPoint;

        /// <summary>
        /// The UDP relay endpoint provided by the SOCKS5 server.
        /// </summary>
        private IPEndPoint socks5UdpRelayEndPoint;

        /// <summary>
        /// A buffer for monitoring the SOCKS5 TCP connection.
        /// </summary>
        private readonly byte[] socks5MonitorBuffer = new byte[1];

        /// <summary>
        /// Creates a new Socks5ClientConnection.
        /// </summary>
        /// <param name="logger">The logger to use.</param>
        /// <param name="remoteEndPoint">The ultimate destination endpoint.</param>
        /// <param name="socks5EndPoint">The endpoint of the SOCKS5 proxy server.</param>
        /// <param name="ipMode">The IP mode to use.</param>
        public Socks5ClientConnection(ILogger logger, IPEndPoint remoteEndPoint, IPEndPoint socks5EndPoint, IPMode ipMode = IPMode.IPv4)
            : base(logger, remoteEndPoint, ipMode)
        {
            this.socks5EndPoint = socks5EndPoint;
        }

        /// <inheritdoc />
        public override void ConnectAsync(byte[] bytes = null)
        {
            this.State = ConnectionState.Connecting;

            try
            {
                // Step 1: Establish TCP connection with SOCKS5 proxy
                this.socks5TcpSocket = new Socket(this.socks5EndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                this.socks5TcpSocket.Connect(this.socks5EndPoint);

                // Step 2: SOCKS5 handshake for UDP association
                PerformSocks5UdpHandshake();

                // Step 2.5: Start monitoring the SOCKS5 TCP control connection
                MonitorSocks5TcpConnection();

                // Step 3: Create and bind the local UDP socket
                this.socket = new Socket(this.IPMode == IPMode.IPv4 ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
                if (IPMode == IPMode.IPv4)
                    socket.Bind(new IPEndPoint(IPAddress.Any, 0));
                else
                    socket.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));

                // Step 4: Start listening for data on the UDP socket
                StartListeningForData();

                // Step 5: Send Hazel's hello packet to the server via the SOCKS5 UDP relay
                SendHello(bytes, () =>
                {
                    this.State = ConnectionState.Connected;
                    this.InitializeKeepAliveTimer();
                });
            }
            catch (Exception e)
            {
                this.logger?.WriteError($"SOCKS5 connection failed: {e.Message}");
                DisconnectInternal(HazelInternalErrors.ConnectionDisconnected, e.Message);
                throw new HazelException("Failed to connect via SOCKS5 proxy.", e);
            }
        }

        /// <summary>
        /// Monitors the SOCKS5 TCP control connection for disconnection using an asynchronous read.
        /// </summary>
        private void MonitorSocks5TcpConnection()
        {
            try
            {
                this.socks5TcpSocket.BeginReceive(
                    this.socks5MonitorBuffer,
                    0,
                    this.socks5MonitorBuffer.Length,
                    SocketFlags.None,
                    Socks5TcpConnectionMonitorCallback,
                    null);
            }
            catch (Exception e)
            {
                if (this.State == ConnectionState.Connected)
                {
                    DisconnectInternal(HazelInternalErrors.ConnectionDisconnected, $"SOCKS5 TCP control connection failed: {e.Message}");
                }
            }
        }

        /// <summary>
        /// Callback for the SOCKS5 TCP connection monitor.
        /// </summary>
        private void Socks5TcpConnectionMonitorCallback(IAsyncResult ar)
        {
            try
            {
                int bytesReceived = this.socks5TcpSocket.EndReceive(ar);

                // If 0 bytes are received, the connection has been gracefully closed by the proxy.
                if (bytesReceived == 0)
                {
                    if (this.State == ConnectionState.Connected)
                    {
                        DisconnectInternal(HazelInternalErrors.ConnectionDisconnected, "SOCKS5 TCP control connection was closed.");
                    }
                    return;
                }

                // The SOCKS5 control channel should not be sending any more data.
                // If it does, it's unexpected. We'll log it and close the connection.
                this.logger.WriteWarning("Received unexpected data on SOCKS5 TCP control channel. Closing connection.");
                DisconnectInternal(HazelInternalErrors.ConnectionDisconnected, "Unexpected data on SOCKS5 TCP control channel.");
            }
            catch (ObjectDisposedException)
            {
                // Socket has been closed, which is expected during disconnection.
                return;
            }
            catch (Exception e)
            {
                // Any other exception indicates a problem with the connection.
                if (this.State == ConnectionState.Connected)
                {
                    DisconnectInternal(HazelInternalErrors.ConnectionDisconnected, $"SOCKS5 TCP control connection failed: {e.Message}");
                }
            }
        }

        /// <summary>
        /// Performs the SOCKS5 handshake to request UDP association.
        /// </summary>
        private void PerformSocks5UdpHandshake()
        {
            // Greeting
            this.socks5TcpSocket.Send(new byte[] { 0x05, 0x01, 0x00 }); // Version 5, 1 auth method, No-Auth

            // Server Choice
            byte[] serverChoice = new byte[2];
            ReceiveAll(serverChoice, 2);
            if (serverChoice[0] != 0x05 || serverChoice[1] != 0x00)
                throw new HazelException("SOCKS5 server does not support No-Authentication.");

            // UDP Associate Request
            byte[] udpRequest = { 0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }; // VER, CMD_UDP, RSV, ATYP_IPV4, 0.0.0.0:0
            this.socks5TcpSocket.Send(udpRequest);

            // Server Reply
            byte[] serverReply = new byte[10]; // Minimum size for IPv4
            ReceiveAll(serverReply, 10);

            if (serverReply[0] != 0x05 || serverReply[1] != 0x00)
                throw new HazelException($"SOCKS5 server returned an error: {serverReply[1]}");

            if (serverReply[3] != 0x01) // ATYP must be IPv4 for now
                throw new HazelException($"SOCKS5 server returned an unsupported address type: {serverReply[3]}");

            byte[] addressBytes = new byte[4];
            Array.Copy(serverReply, 4, addressBytes, 0, 4);
            ushort port = (ushort)((serverReply[8] << 8) | serverReply[9]);

            this.socks5UdpRelayEndPoint = new IPEndPoint(new IPAddress(addressBytes), port);
        }

        /// <summary>
        /// Receives a specific number of bytes from the TCP socket.
        /// </summary>
        private void ReceiveAll(byte[] buffer, int size)
        {
            int totalReceived = 0;
            while (totalReceived < size)
            {
                int received;
                try
                {
                    received = this.socks5TcpSocket.Receive(buffer, totalReceived, size - totalReceived, SocketFlags.None);
                }
                catch (SocketException e)
                {
                    throw new HazelException("SOCKS5 TCP connection failed during receive.", e);
                }

                if (received == 0) throw new EndOfStreamException("SOCKS5 TCP connection was closed prematurely.");
                totalReceived += received;
            }
        }

        /// <inheritdoc />
        protected override void WriteBytesToConnection(SmartBuffer smartBuffer, int length)
        {
            if (this.socks5UdpRelayEndPoint == null)
            {
                this.logger.WriteError("SOCKS5 UDP relay endpoint is not available.");
                return;
            }

            // All UDP packets must be wrapped in a SOCKS5 UDP request header
            // and sent to the SOCKS5 UDP relay endpoint.
            using (var fullPacket = this.bufferPool.GetObject())
            {
                byte[] header;
                byte[] destAddrBytes = this.EndPoint.Address.GetAddressBytes();
                ushort destPort = (ushort)this.EndPoint.Port;

                if (this.EndPoint.Address.AddressFamily == AddressFamily.InterNetwork)
                {
                    header = new byte[10];
                    header[3] = 0x01; // ATYP: IPv4
                    Buffer.BlockCopy(destAddrBytes, 0, header, 4, 4);
                    header[8] = (byte)(destPort >> 8);
                    header[9] = (byte)destPort;
                }
                else // Assuming IPv6
                {
                    header = new byte[22];
                    header[3] = 0x04; // ATYP: IPv6
                    Buffer.BlockCopy(destAddrBytes, 0, header, 4, 16);
                    header[20] = (byte)(destPort >> 8);
                    header[21] = (byte)destPort;
                }
                // RSV and FRAG are already 0x00 from array initialization

                // Combine header and data into the pooled buffer
                Buffer.BlockCopy(header, 0, (byte[])fullPacket, 0, header.Length);
                Buffer.BlockCopy((byte[])smartBuffer, 0, (byte[])fullPacket, header.Length, length);
                int totalLength = header.Length + length;

                try
                {
                    this.Statistics.LogPacketSend(totalLength);
                    fullPacket.AddUsage();
                    this.socket.BeginSendTo(
                        (byte[])fullPacket,
                        0,
                        totalLength,
                        SocketFlags.None,
                        this.socks5UdpRelayEndPoint,
                        (iar) =>
                        {
                            try
                            {
                                this.socket?.EndSendTo(iar);
                            }
                            catch (ObjectDisposedException) { }
                            catch (SocketException ex)
                            {
                                DisconnectInternal(HazelInternalErrors.SocketExceptionSend, "Could not send data as a SocketException occurred: " + ex.Message);
                            }
                            finally
                            {
                                ((SmartBuffer)iar.AsyncState).Recycle();
                            }
                        },
                        fullPacket);
                }
                catch (ObjectDisposedException) { fullPacket.Recycle(); }
                catch (SocketException ex)
                {
                    fullPacket.Recycle();
                    DisconnectInternal(HazelInternalErrors.SocketExceptionSend, "Could not send data as a SocketException occurred: " + ex.Message);
                }
            }
        }

        /// <inheritdoc />
        protected internal override void HandleReceive(MessageReader message, int bytesReceived)
        {
            // We need to parse the SOCKS5 UDP response header to get to the actual data.
            // RSV(2), FRAG(1), ATYP(1) = 4 bytes
            if (bytesReceived < 4)
            {
                message.Recycle();
                return;
            }

            message.Position = 3; // Skip RSV and FRAG
            byte atyp = message.ReadByte();

            int addrLen;
            IPAddress originalSenderIp;
            ushort originalSenderPort;

            try
            {
                switch (atyp)
                {
                    case 0x01: // IPv4
                        addrLen = 4;
                        if (bytesReceived < 4 + addrLen + 2) { message.Recycle(); return; }
                        originalSenderIp = new IPAddress(message.ReadBytes(addrLen));
                        originalSenderPort = message.ReadUInt16();
                        break;
                    case 0x04: // IPv6
                        addrLen = 16;
                        if (bytesReceived < 4 + addrLen + 2) { message.Recycle(); return; }
                        originalSenderIp = new IPAddress(message.ReadBytes(addrLen));
                        originalSenderPort = message.ReadUInt16();
                        break;
                    default: // Unsupported address type
                        message.Recycle();
                        return;
                }
            }
            catch
            {
                // Malformed packet
                message.Recycle();
                return;
            }

            // Ensure the packet is from the endpoint we are connected to
            if (!this.EndPoint.Address.Equals(originalSenderIp) || this.EndPoint.Port != originalSenderPort)
            {
                message.Recycle();
                return;
            }

            // Header size = 4 (initial) + addrLen + 2 (port)
            int headerSize = 4 + addrLen + 2;
            int dataOffset = headerSize;
            int dataLength = bytesReceived - dataOffset;

            // Create a new reader for the actual payload.
            MessageReader payloadReader = MessageReader.GetSized(dataLength);
            Buffer.BlockCopy(message.Buffer, dataOffset, payloadReader.Buffer, 0, dataLength);
            payloadReader.Length = dataLength;

            // Recycle the original message that contained the SOCKS5 header.
            message.Recycle();

            // Let the base class handle the Hazel protocol message.
            base.HandleReceive(payloadReader, dataLength);
        }

        /// <inheritdoc />
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                // Close the SOCKS5 TCP control socket
                try { this.socks5TcpSocket?.Shutdown(SocketShutdown.Both); } catch { }
                try { this.socks5TcpSocket?.Close(); } catch { }
                try { this.socks5TcpSocket?.Dispose(); } catch { }
            }

            base.Dispose(disposing);
        }
    }
}