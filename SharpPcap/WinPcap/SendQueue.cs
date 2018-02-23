/*
This file is part of SharpPcap.

SharpPcap is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

SharpPcap is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with SharpPcap.  If not, see <http://www.gnu.org/licenses/>.
*/
/* 
 * Copyright 2005 Tamir Gal <tamir@tamirgal.com>
 * Copyright 2008-2009 Chris Morgan <chmorgan@gmail.com>
 * Copyright 2008-2009 Phillip Lemon <lucidcomms@gmail.com>
 */

using System;
using System.Runtime.InteropServices;
using SharpPcap.LibPcap;

namespace SharpPcap.WinPcap
{
    /// <summary>
    /// Interface to the WinPcap send queue extension methods
    /// </summary>
    public class SendQueue
    {
        readonly IntPtr m_queue = IntPtr.Zero;

        /// <summary>
        /// Creates and allocates a new SendQueue
        /// </summary>
        /// <param name="memSize">
        /// The maximun amount of memory (in bytes) 
        /// to allocate for the queue</param>
        public SendQueue(Int32 memSize)
        {
            // ensure that we are running under winpcap
            WinPcapDevice.ThrowIfNotWinPcap();

            this.m_queue = SafeNativeMethods.pcap_sendqueue_alloc( memSize );
            if(this.m_queue==IntPtr.Zero)
                throw new PcapException("Error creating PcapSendQueue");
        }

        /// <summary>
        /// Add a packet to this send queue. The PcapHeader defines the packet length.
        /// </summary>
        /// <param name="packet">The packet bytes to add</param>
        /// <param name="pcapHdr">The pcap header of the packet</param>
        /// <returns>True if success, else false</returns>
        internal Boolean AddInternal( Byte[] packet, PcapHeader pcapHdr )
        {
            if(this.m_queue==IntPtr.Zero)
            {
                throw new PcapException("Can't add packet, this queue is disposed");
            }

            // the header defines the size to send
            if(pcapHdr.CaptureLength > packet.Length)
            {
                var error = String.Format("pcapHdr.CaptureLength of {0} > packet.Length {1}",
                                          pcapHdr.CaptureLength, packet.Length);
                throw new InvalidOperationException(error);
            }

            //Marshal packet
            IntPtr pktPtr;
            pktPtr = Marshal.AllocHGlobal(packet.Length);
            Marshal.Copy(packet, 0, pktPtr, packet.Length);

            //Marshal header
            IntPtr hdrPtr = pcapHdr.MarshalToIntPtr();

            Int32 res = SafeNativeMethods.pcap_sendqueue_queue(this.m_queue, hdrPtr, pktPtr);

            Marshal.FreeHGlobal(pktPtr);
            Marshal.FreeHGlobal(hdrPtr);    
    
            return (res!=-1);
        }

        /// <summary>
        /// Add a packet to this send queue. 
        /// </summary>
        /// <param name="packet">The packet bytes to add</param>
        /// <param name="pcapHdr">The pcap header of the packet</param>
        /// <returns>True if success, else false</returns>
        internal Boolean Add( Byte[] packet, PcapHeader pcapHdr )
        {
            return this.AddInternal( packet, pcapHdr);
        }

        /// <summary>
        /// Add a packet to this send queue. 
        /// </summary>
        /// <param name="packet">The packet bytes to add</param>
        /// <returns>True if success, else false</returns>
        public Boolean Add( Byte[] packet )
        {
            PcapHeader hdr = new PcapHeader();
            hdr.CaptureLength = (UInt32)packet.Length;
            return this.AddInternal( packet, hdr );
        }

        /// <summary>
        /// Add a packet to this send queue. 
        /// </summary>
        /// <param name="packet">The packet to add</param>
        /// <returns>True if success, else false</returns>
        public Boolean Add( RawCapture packet )
        {
            var data = packet.Data;
            var timeval = packet.Timeval;
            var header = new PcapHeader((UInt32)timeval.Seconds, (UInt32)timeval.MicroSeconds,
                                        (UInt32)data.Length, (UInt32)data.Length);
            return this.AddInternal(data, header);
        }

        /// <summary>
        /// Add a packet to this send queue.
        /// </summary>
        /// <param name="packet">The packet to add</param>
        /// <param name="seconds">The 'seconds' part of the packet's timestamp</param>
        /// <param name="microseconds">The 'microseconds' part of the packet's timestamp</param>
        /// <returns>True if success, else false</returns>
        public Boolean Add( Byte[] packet, Int32 seconds, Int32 microseconds )
        {
            var header = new PcapHeader((UInt32)seconds, (UInt32)microseconds,
                                        (UInt32)packet.Length, (UInt32)packet.Length);
            
            return this.Add( packet, header );
        }

        /// <summary>
        /// Send a queue of raw packets to the network. 
        /// </summary>
        /// <param name="device">
        /// The device on which to send the queue
        /// A <see cref="PcapDevice"/>
        /// </param>
        /// <param name="transmitMode">
        /// A <see cref="SendQueueTransmitModes"/>
        /// </param>
        /// <returns>
        /// A <see cref="System.Int32"/>
        /// </returns>
        public Int32 Transmit( WinPcapDevice device, SendQueueTransmitModes transmitMode)
        {
            if(!device.Opened)
                throw new DeviceNotReadyException("Can't transmit queue, the pcap device is closed");

            if(this.m_queue==IntPtr.Zero)
            {
                throw new PcapException("Can't transmit queue, this queue is disposed");
            }

            Int32 sync = (transmitMode == SendQueueTransmitModes.Synchronized) ? 1 : 0;
            return SafeNativeMethods.pcap_sendqueue_transmit(device.PcapHandle, this.m_queue, sync);
        }

        /// <summary>
        /// Destroy the send queue. 
        /// </summary>
        public void Dispose()
        {
            if(this.m_queue!=IntPtr.Zero)
            {
                SafeNativeMethods.pcap_sendqueue_destroy(this.m_queue );
            }
        }

        /// <summary>
        /// The current length in bytes of this queue
        /// </summary>
        public Int32 CurrentLength
        {
            get
            {
                if(this.m_queue==IntPtr.Zero)
                {
                    throw new PcapException("Can't perform operation, this queue is disposed");
                }
                PcapUnmanagedStructures.pcap_send_queue q =
                    (PcapUnmanagedStructures.pcap_send_queue)Marshal.PtrToStructure
                    (this.m_queue, typeof(PcapUnmanagedStructures.pcap_send_queue));
                return (Int32)q.len;
            }
        }
    }
}
