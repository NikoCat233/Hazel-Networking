﻿using Hazel.UPnP;
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Hazel.Udp
{
    public class UdpBroadcaster : IDisposable
    {
        private SocketBroadcast[] socketBroadcasts;
        private byte[] data;
        private Action<string> logger;

        ///
        public UdpBroadcaster(int port, Action<string> logger = null)
        {
            this.logger = logger;

            var addresses = NetUtility.GetAddressesFromNetworkInterfaces(AddressFamily.InterNetwork);
            this.socketBroadcasts = new SocketBroadcast[addresses.Count > 0 ? addresses.Count : 1];

            int count = 0;
            foreach (var addressInformation in addresses)
            {
                Socket socket = CreateSocket(new IPEndPoint(addressInformation.Address, 0));
                IPAddress broadcast = NetUtility.GetBroadcastAddress(addressInformation);

                this.socketBroadcasts[count] = new SocketBroadcast(socket, new IPEndPoint(broadcast, port));
                count++;
            }
            if (count == 0)
            {
                Socket socket = CreateSocket(new IPEndPoint(IPAddress.Any, 0));

                this.socketBroadcasts[0] = new SocketBroadcast(socket, new IPEndPoint(IPAddress.Broadcast, port));
            }
        }

        private static Socket CreateSocket(IPEndPoint endPoint)
        {
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.EnableBroadcast = true;
            socket.MulticastLoopback = false;
            socket.Bind(endPoint);

            return socket;
        }

        ///
        public void SetData(string data)
        {
            int len = UTF8Encoding.UTF8.GetByteCount(data);
            this.data = new byte[len + 2];
            this.data[0] = 4;
            this.data[1] = 2;

            UTF8Encoding.UTF8.GetBytes(data, 0, data.Length, this.data, 2);
        }

        ///
        public void Broadcast()
        {
            if (this.data == null)
            {
                return;
            }

            foreach (SocketBroadcast socketBroadcast in this.socketBroadcasts)
            {
                try
                {
                    Socket socket = socketBroadcast.Socket;
                    socket.BeginSendTo(data, 0, data.Length, SocketFlags.None, socketBroadcast.Broadcast, this.FinishSendTo, socket);
                }
                catch (Exception e)
                {
                    this.logger?.Invoke("BroadcastListener: " + e);
                }
            }
        }

        private void FinishSendTo(IAsyncResult evt)
        {
            try
            {
                Socket socket = (Socket)evt.AsyncState;
                socket.EndSendTo(evt);
            }
            catch (Exception e)
            {
                this.logger?.Invoke("BroadcastListener: " + e);
            }
        }

        ///
        public void Dispose()
        {
            if (this.socketBroadcasts != null)
            {
                foreach (SocketBroadcast socketBroadcast in this.socketBroadcasts)
                {
                    Socket socket = socketBroadcast.Socket;
                    if (socket != null)
                    {
                        try { socket.Shutdown(SocketShutdown.Both); } catch { }
                        try { socket.Close(); } catch { }
                        try { socket.Dispose(); } catch { }
                    }
                }
                Array.Clear(this.socketBroadcasts, 0, this.socketBroadcasts.Length);
            }
        }

        private struct SocketBroadcast
        {
            public Socket Socket;
            public IPEndPoint Broadcast;

            public SocketBroadcast(Socket socket, IPEndPoint broadcast)
            {
                Socket = socket;
                Broadcast = broadcast;
            }
        }
    }
}