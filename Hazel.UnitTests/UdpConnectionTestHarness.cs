﻿using Hazel.Udp;
using System;
using System.Collections.Generic;

namespace Hazel.UnitTests
{
    internal class UdpConnectionTestHarness : UdpConnection
    {
        public List<MessageReader> BytesSent = new List<MessageReader>();

        public UdpConnectionTestHarness() : base(new TestLogger())
        {
        }

        public ushort ReliableReceiveLast => this.reliableReceiveLast;


        public override void Connect(byte[] bytes = null, int timeout = 5000)
        {
            this.State = ConnectionState.Connected;
        }

        public override void ConnectAsync(byte[] bytes = null)
        {
            this.State = ConnectionState.Connected;
        }

        protected override bool SendDisconnect(MessageWriter writer)
        {
            lock (this)
            {
                if (this.State != ConnectionState.Connected)
                {
                    return false;
                }

                this.State = ConnectionState.NotConnected;
            }

            return true;
        }

        protected override void WriteBytesToConnection(SmartBuffer bytes, int length)
        {
            var buffer = new byte[bytes.Length];
            Buffer.BlockCopy((byte[])bytes, 0, buffer, 0, bytes.Length);

            this.BytesSent.Add(MessageReader.Get(buffer));
        }

        public void Test_Receive(MessageWriter msg)
        {
            byte[] buffer = new byte[msg.Length];
            Buffer.BlockCopy(msg.Buffer, 0, buffer, 0, msg.Length);

            var data = MessageReader.Get(buffer);
            this.HandleReceive(data, data.Length);
        }
    }
}
