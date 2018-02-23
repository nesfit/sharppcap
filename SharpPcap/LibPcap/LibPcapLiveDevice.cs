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
 * Copyright 2008-2010 Phillip Lemon <lucidcomms@gmail.com>
 */

using System;
using System.Text;
using System.Collections.ObjectModel;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Collections.Generic;

namespace SharpPcap.LibPcap
{
    /// <summary>
    /// Capture live packets from a network device
    /// </summary>
    public class LibPcapLiveDevice : PcapDevice
    {
        /// <summary>
        /// Constructs a new PcapDevice based on a 'pcapIf' struct
        /// </summary>
        /// <param name="pcapIf">A 'pcapIf' struct representing
        /// the pcap device</param>
        internal LibPcapLiveDevice( PcapInterface pcapIf )
        {
            this.m_pcapIf = pcapIf;

            // go through the network interfaces and attempt to populate the mac address, 
            // friendly name etc of this device
            NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface adapter in nics)
            {
                // if the name and id match then we have found the NetworkInterface
                // that matches the PcapDevice
                if (this.Name.EndsWith(adapter.Id))
                {
                    var ipProperties = adapter.GetIPProperties();
                    Int32 gatewayAddressCount = ipProperties.GatewayAddresses.Count;
                    if (gatewayAddressCount != 0)
                    {
                        List<System.Net.IPAddress> gatewayAddresses = new List<System.Net.IPAddress>();
                        foreach(GatewayIPAddressInformation gatewayInfo in ipProperties.GatewayAddresses) {
                            gatewayAddresses.Add(gatewayInfo.Address);
                        }

                        this.Interface.GatewayAddresses = gatewayAddresses;
                    }

                    this.Interface.MacAddress = adapter.GetPhysicalAddress();
                    this.Interface.FriendlyName = adapter.Name;
                }
            }
        }

        /// <summary>
        /// Default contructor for subclasses
        /// </summary>
        protected LibPcapLiveDevice()
        {
        }

        /// <summary>
        /// PcapDevice finalizer.  Ensure PcapDevices are stopped and closed before exit.
        /// </summary>
        ~LibPcapLiveDevice()
        {
            this.Close();
        }

        /// <summary>
        /// Gets the pcap name of this network device
        /// </summary>
        public override String Name
        {
            get { return this.m_pcapIf.Name; }
        }

        /// <summary>
        /// Addresses that represent this device
        /// </summary>
        public virtual ReadOnlyCollection<PcapAddress> Addresses
        {
            get { return new ReadOnlyCollection<PcapAddress>(this.m_pcapIf.Addresses); }
        }

        /// <summary>
        /// Gets the pcap description of this device
        /// </summary>
        public override String Description
        {
            get { return this.m_pcapIf.Description; }
        }

        /// <summary>
        /// Interface flags, see pcap_findalldevs() man page for more info
        /// </summary>
        public virtual UInt32 Flags
        {
            get { return this.m_pcapIf.Flags; }
        }

        /// <summary>
        /// True if device is a loopback interface, false if not
        /// </summary>
        public virtual Boolean Loopback
        {
            get { return (this.Flags & Pcap.PCAP_IF_LOOPBACK)==1; }
        }

        /// <summary>
        /// Open the device with default values of: promiscuous_mode = false, read_timeout = 1000
        /// To start capturing call the 'StartCapture' function
        /// </summary>
        public override void Open()
        {
            this.Open(DeviceMode.Normal);
        }

        /// <summary>
        /// Open the device. To start capturing call the 'StartCapture' function
        /// </summary>
        /// <param name="mode">
        /// A <see cref="DeviceMode"/>
        /// </param>
        public override void Open(DeviceMode mode)
        {
            const Int32 readTimeoutMilliseconds = 1000;
            this.Open(mode, readTimeoutMilliseconds);
        }

        /// <summary>
        /// Open the device. To start capturing call the 'StartCapture' function
        /// </summary>
        /// <param name="mode">
        /// A <see cref="DeviceMode"/>
        /// </param>
        /// <param name="read_timeout">
        /// A <see cref="System.Int32"/>
        /// </param>
        public override void Open(DeviceMode mode, Int32 read_timeout)
        {
            const MonitorMode monitorMode = MonitorMode.Inactive;
            this.Open(mode, read_timeout, monitorMode);
        }

        /// <summary>
        /// Open the device. To start capturing call the 'StartCapture' function
        /// </summary>
        /// <param name="mode">
        /// A <see cref="DeviceMode"/>
        /// </param>
        /// <param name="read_timeout">
        /// A <see cref="System.Int32"/>
        /// </param>
        /// <param name="monitor_mode">
        /// A <see cref="MonitorMode"/>
        /// </param>
        public override void Open(DeviceMode mode, Int32 read_timeout, MonitorMode monitor_mode)
        {
            if ( !this.Opened )
            {
                StringBuilder errbuf = new StringBuilder( Pcap.PCAP_ERRBUF_SIZE ); //will hold errors

                // set the StopCaptureTimeout value to twice the read timeout to ensure that
                // we wait long enough before considering the capture thread to be stuck when stopping
                // a background capture via StopCapture()
                //
                // NOTE: Doesn't affect Mono if unix poll is available, doesn't affect Linux because
                //       Linux devices have no timeout, they always block. Only affects Windows devices.
                this.StopCaptureTimeout = new TimeSpan(0, 0, 0, 0, read_timeout * 2);

                this.PcapHandle = LibPcapSafeNativeMethods.pcap_create(this.Name, // name of the device
                    errbuf); // error buffer                

                if (this.PcapHandle == IntPtr.Zero)
                {
                    String err = "Unable to open the adapter ("+ this.Name+"). "+errbuf.ToString();
                    throw new PcapException( err );
                }

                LibPcapSafeNativeMethods.pcap_set_snaplen(this.PcapHandle, Pcap.MAX_PACKET_SIZE);
                if (monitor_mode == MonitorMode.Active)
                {
                    try
                    {
                        LibPcapSafeNativeMethods.pcap_set_rfmon(this.PcapHandle, (Int32)monitor_mode);
                    }
                    catch (EntryPointNotFoundException)
                    {
                        throw new PcapException("This implementation of libpcap does not support monitor mode.");
                    }
                }
                
                LibPcapSafeNativeMethods.pcap_set_promisc(this.PcapHandle, (Int32)mode);
                LibPcapSafeNativeMethods.pcap_set_timeout(this.PcapHandle, read_timeout);

                var activationResult = LibPcapSafeNativeMethods.pcap_activate(this.PcapHandle);
                if (activationResult < 0)
                {                    
                    String err = "Unable to activate the adapter (" + this.Name + "). Return code: " + activationResult.ToString();
                    throw new PcapException(err);
                }

                this.Active = true;
            }
        }

        private const Int32 disableBlocking = 0;
        private const Int32 enableBlocking = 1;

        /// <summary>
        /// Set/Get Non-Blocking Mode. returns allways false for savefiles.
        /// </summary>
        public Boolean NonBlockingMode
        {
            get
            {
                var errbuf = new StringBuilder(Pcap.PCAP_ERRBUF_SIZE); //will hold errors
                Int32 ret = LibPcapSafeNativeMethods.pcap_getnonblock(this.PcapHandle, errbuf);

                // Errorbuf is only filled when ret = -1
                if (ret == -1)
                {
                    String err = "Unable to set get blocking" + errbuf.ToString();
                    throw new PcapException(err);
                }

                if(ret == enableBlocking)
                    return true;
                return false;
            }
            set 
            {
                var errbuf = new StringBuilder(Pcap.PCAP_ERRBUF_SIZE); //will hold errors

                Int32 block = disableBlocking;
                if (value)
                    block = enableBlocking;

                Int32 ret = LibPcapSafeNativeMethods.pcap_setnonblock(this.PcapHandle, block, errbuf);

                // Errorbuf is only filled when ret = -1
                if (ret == -1)
                {
                    String err = "Unable to set non blocking" + errbuf.ToString();
                    throw new PcapException(err);
                }
            }
        }

        /// <summary>
        /// Sends a raw packet throgh this device
        /// </summary>
        /// <param name="p">The packet bytes to send</param>
        /// <param name="size">The number of bytes to send</param>
        public override void SendPacket(Byte[] p, Int32 size)
        {
            this.ThrowIfNotOpen("Can't send packet, the device is closed");

            if (size > p.Length)
            {
                throw new ArgumentException("Invalid packetSize value: "+size+
                "\nArgument size is larger than the total size of the packet.");
            }

            if (p.Length > Pcap.MAX_PACKET_SIZE) 
            {
                throw new ArgumentException("Packet length can't be larger than "+Pcap.MAX_PACKET_SIZE);
            }

            IntPtr p_packet = IntPtr.Zero;          
            p_packet = Marshal.AllocHGlobal( size );
            Marshal.Copy(p, 0, p_packet, size);     

            Int32 res = LibPcapSafeNativeMethods.pcap_sendpacket(this.PcapHandle, p_packet, size);
            Marshal.FreeHGlobal(p_packet);
            if(res < 0)
            {
                throw new PcapException("Can't send packet: " + this.LastError);
            }
        }

        /// <summary>
        /// Retrieves pcap statistics
        /// </summary>
        /// <returns>
        /// A <see cref="PcapStatistics"/>
        /// </returns>
        public override ICaptureStatistics Statistics
        {
            get
            {
                // can only call PcapStatistics on an open device
                this.ThrowIfNotOpen("device not open");

                return new PcapStatistics(this.m_pcapAdapterHandle);
            }
        }
    }
}
