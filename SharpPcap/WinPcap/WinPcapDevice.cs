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
 * Copyright 2010-2011 Chris Morgan <chmorgan@gmail.com>
 */

using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Threading;
using SharpPcap.LibPcap;

namespace SharpPcap.WinPcap
{
    /// <summary>
    /// WinPcap device
    /// </summary>
    public class WinPcapDevice : LibPcapLiveDevice
    {
        private CaptureMode    m_pcapMode          = CaptureMode.Packets;

        /// <summary>
        /// Constructs a new PcapDevice based on a 'pcapIf' struct
        /// </summary>
        /// <param name="pcapIf">A 'pcapIf' struct representing
        /// the pcap device</param>
        internal WinPcapDevice( PcapInterface pcapIf ) : base(pcapIf)
        {}

        /// <summary>
        /// Fires whenever a new pcap statistics is available for this Pcap Device.<br/>
        /// For network captured packets this event is invoked only when working in "PcapMode.Statistics" mode.
        /// </summary>
        public event StatisticsModeEventHandler OnPcapStatistics;

        /// <summary>
        /// Starts the capturing process via a background thread
        /// OnPacketArrival() will be called for each captured packet
        ///
        /// NOTE: Winpcap devices can capture packets or statistics updates
        ///       so only if both a packet handler AND a statistics handler
        ///       are defined will an exception be thrown
        /// </summary>
        public override void StartCapture()
        {
            if (!this.Started)
            {
                if (!this.Opened)
                    throw new DeviceNotReadyException("Can't start capture, the pcap device is not opened.");

                if ((this.IsOnPacketArrivalNull == true) && (this.OnPcapStatistics == null))
                    throw new DeviceNotReadyException("No delegates assigned to OnPacketArrival or OnPcapStatistics, no where for captured packets to go.");

                this.shouldCaptureThreadStop = false;
                this.captureThread = new Thread(new ThreadStart(this.CaptureThread));
                this.captureThread.Start();
            }
        }

        /// <summary>
        /// Open the device
        /// </summary>
        public override void Open()
        {
            base.Open();
        }

        /// <summary>
        /// Open
        /// </summary>
        /// <param name="flags">
        /// A <see cref="OpenFlags"/>
        /// </param>
        /// <param name="readTimeoutMilliseconds">
        /// A <see cref="System.Int32"/>
        /// </param>
        /// <param name="remoteAuthentication">
        /// A <see cref="RemoteAuthentication"/>
        /// </param>
        public void Open(OpenFlags flags,
                         Int32 readTimeoutMilliseconds,
                         RemoteAuthentication remoteAuthentication)
        {
            if(!this.Opened)
            {
                var errbuf = new StringBuilder( Pcap.PCAP_ERRBUF_SIZE ); //will hold errors

                IntPtr rmAuthPointer;
                if (remoteAuthentication == null)
                    rmAuthPointer = IntPtr.Zero;
                else
                    rmAuthPointer = remoteAuthentication.GetUnmanaged();

                this.PcapHandle = SafeNativeMethods.pcap_open(this.Name,
                                                         Pcap.MAX_PACKET_SIZE,   // portion of the packet to capture.
                                                         (Int32)flags,
                                                         readTimeoutMilliseconds,
                                                         rmAuthPointer,
                                                         errbuf);

                if(rmAuthPointer != IntPtr.Zero)
                    Marshal.FreeHGlobal(rmAuthPointer);

                if (this.PcapHandle == IntPtr.Zero)
                {
                    String err = "Unable to open the adapter ("+ this.Name+"). "+errbuf.ToString();
                    throw new PcapException( err );
                }
            }
        }

        /// <value>
        /// WinPcap specific property
        /// </value>
        public virtual CaptureMode Mode
        {
            get
            {
                return this.m_pcapMode;
            }

            set
            {
                ThrowIfNotWinPcap();
                this.ThrowIfNotOpen("Mode");

                this.m_pcapMode = value;
                Int32 result = SafeNativeMethods.pcap_setmode(this.PcapHandle , (Int32) this.m_pcapMode);
                if (result < 0)
                    throw new PcapException("Error setting PcapDevice mode. : " + this.LastError);
            }
        }

        /// <summary>
        /// Open a device with specific flags
        /// WinPcap extension - Use of this method will exclude your application
        ///                     from working on Linux or Mac
        /// </summary>
        public virtual void Open(OpenFlags flags, Int32 read_timeout)
        {
            ThrowIfNotWinPcap();

            if(!this.Opened)
            {
                var errbuf = new StringBuilder(Pcap.PCAP_ERRBUF_SIZE);

                this.PcapHandle = SafeNativeMethods.pcap_open
                    (this.Name,                   // name of the device
                        Pcap.MAX_PACKET_SIZE,   // portion of the packet to capture.
                                                // MAX_PACKET_SIZE (65536) grants that the whole packet will be captured on all the MACs.
                        (Int16)flags,           // one or more flags
                        (Int16)read_timeout,    // read timeout
                        IntPtr.Zero,            // no authentication right now
                        errbuf );               // error buffer

                if (this.PcapHandle == IntPtr.Zero)
                {
                    String err = "Unable to open the adapter ("+ this.Name+"). "+errbuf.ToString();
                    throw new PcapException( err );
                }
            }
        }

        /// <summary>
        /// Close the device
        /// </summary>
        public override void Close()
        {
            if (this.OnPcapStatistics != null)
            {
                foreach(StatisticsModeEventHandler pse in this.OnPcapStatistics.GetInvocationList())
                {
                    this.OnPcapStatistics -= pse;
                }
            }

            // call the base method
            base.Close();
        }

        /// <summary>
        /// Notify the OnPacketArrival delegates about a newly captured packet
        /// </summary>
        /// <param name="p">
        /// A <see cref="RawCapture"/>
        /// </param>
        override protected void SendPacketArrivalEvent(RawCapture p)
        {
            if(this.Mode == CaptureMode.Packets)
            {
                base.SendPacketArrivalEvent(p);
            }
            else if(this.Mode == CaptureMode.Statistics)
            {
                var handler = this.OnPcapStatistics;
                if(handler != null)
                {
                    //Invoke the pcap statistics event
                    handler(this, new StatisticsModeEventArgs(p, this));
                }
            }
        }

        /// <summary>
        /// Sends all packets in a 'PcapSendQueue' out this pcap device
        /// </summary>
        /// <param name="q">
        /// A <see cref="SendQueue"/>
        /// </param>
        /// <param name="transmitMode">
        /// A <see cref="SendQueueTransmitModes"/>
        /// </param>
        /// <returns>
        /// A <see cref="System.Int32"/>
        /// </returns>
        public Int32 SendQueue( SendQueue q, SendQueueTransmitModes transmitMode )
        {
            return q.Transmit( this, transmitMode);
        }

        /// <value>
        /// Set the kernel value buffer size in bytes
        /// WinPcap extension
        /// </value>
        public virtual UInt32 KernelBufferSize
        {
            set
            {
                ThrowIfNotWinPcap();
                this.ThrowIfNotOpen("Can't set kernel buffer size, the device is not opened");

                Int32 retval = SafeNativeMethods.pcap_setbuff(this.m_pcapAdapterHandle,
                                                                    (Int32)value);
                if(retval != 0)
                {
                    throw new InvalidOperationException("pcap_setbuff() failed");
                }
            }

            get
            {
                throw new NotImplementedException();
            }
        }

        /// <value>
        /// Set the minumum amount of data (in bytes) received by the kernel in a single call. 
        /// WinPcap extension
        /// </value>
        public Int32 MinToCopy
        {
            set
            {
                ThrowIfNotWinPcap();
                this.ThrowIfNotOpen("Can't set MinToCopy size, the device is not opened");

                Int32 retval = SafeNativeMethods.pcap_setmintocopy(this.m_pcapAdapterHandle,
                                                                 value);
                if (retval != 0)
                {
                    throw new InvalidOperationException("pcap_setmintocopy() failed");
                }
            }
        }

        /// <summary>
        /// Helper method for ensuring we are running in winpcap. Throws
        /// a PcapWinPcapRequiredException() if not on a windows platform
        /// </summary>
        internal static void ThrowIfNotWinPcap()
        {
            if((Environment.OSVersion.Platform != PlatformID.Win32NT) &&
               (Environment.OSVersion.Platform != PlatformID.Win32Windows))
            {
                throw new WinPcapRequiredException("only supported in winpcap");
            }
        }
    }
}

