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
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Net.NetworkInformation;
using PacketDotNet;

namespace SharpPcap.AirPcap
{
    /// <summary>
    /// AirPcap device
    /// </summary>
    public class AirPcapDevice : WinPcap.WinPcapDevice
    {
        /// <summary>
        /// See ThrowIfNotOpen(string ExceptionString)
        /// </summary>
        protected void ThrowIfNotOpen()
        {
            this.ThrowIfNotOpen("");
        }

        /// <summary>
        /// Handle to the device
        /// </summary>
        internal IntPtr AirPcapDeviceHandle { get; set; }

        internal AirPcapDevice(WinPcap.WinPcapDevice dev) : base(dev.Interface)
        {
        }

        /// <summary>
        /// Retrieve the last error string for a given pcap_t* device
        /// </summary>
        /// <param name="AirPcapDeviceHandle">
        /// A <see cref="IntPtr"/>
        /// </param>
        /// <returns>
        /// A <see cref="System.String"/>
        /// </returns>
        new internal static String GetLastError(IntPtr AirPcapDeviceHandle)
        {
            IntPtr err_ptr = AirPcapSafeNativeMethods.AirpcapGetLastError(AirPcapDeviceHandle);
            return Marshal.PtrToStringAnsi(err_ptr);
        }

        /// <summary>
        /// The last pcap error associated with this pcap device
        /// </summary>
        public override String LastError
        {
            get { return GetLastError(this.AirPcapDeviceHandle); }
        }

        /// <summary>
        /// Open a device
        /// </summary>
        public override void Open()
        {
            // open the base adapter, the WinPcapDevice
            base.Open();

            // reteieve the airpcap device given the winpcap handle
            this.AirPcapDeviceHandle = WinPcap.SafeNativeMethods.pcap_get_airpcap_handle(this.PcapHandle);
        }

        /// <summary>
        /// Open the device. To start capturing call the 'StartCapture' function
        /// </summary>
        /// <param name="mode">
        /// A <see cref="DeviceMode"/>
        /// </param>
        public override void Open(DeviceMode mode)
        {
            base.Open(mode);

            // reteieve the airpcap device given the winpcap handle
            this.AirPcapDeviceHandle = WinPcap.SafeNativeMethods.pcap_get_airpcap_handle(this.PcapHandle);
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
            base.Open(mode, read_timeout);

            // reteieve the airpcap device given the winpcap handle
            this.AirPcapDeviceHandle = WinPcap.SafeNativeMethods.pcap_get_airpcap_handle(this.PcapHandle);
        }

        /// <summary>
        /// Opens an Airpcap device with optional WinPcap.OpenFlags
        /// </summary>
        /// <param name="flags">
        /// A <see cref="WinPcap.OpenFlags"/>
        /// </param>
        /// <param name="read_timeout">
        /// A <see cref="System.Int32"/>
        /// </param>
        public override void Open(WinPcap.OpenFlags flags, Int32 read_timeout)
        {
            base.Open(flags, read_timeout);

            // reteieve the airpcap device given the winpcap handle
            this.AirPcapDeviceHandle = WinPcap.SafeNativeMethods.pcap_get_airpcap_handle(this.PcapHandle);
        }

        /// <summary>
        /// Close a device
        /// </summary>
        public override void Close()
        {
            if (!this.Opened)
                return;

            base.Close();
            this.AirPcapDeviceHandle = IntPtr.Zero;
        }

        /// <summary>
        /// Device capabilities, whether the device can transmit, its id, model name etc
        /// </summary>
        public AirPcapDeviceCapabilities Capabilities
        {
            get
            {
                this.ThrowIfNotOpen();

                IntPtr capablitiesPointer;
                if(!AirPcapSafeNativeMethods.AirpcapGetDeviceCapabilities(this.AirPcapDeviceHandle, out capablitiesPointer))
                {
                    throw new InvalidOperationException("error retrieving device capabilities");
                }

                return new AirPcapDeviceCapabilities(capablitiesPointer);
            }
        }

        /// <summary>
        /// Adapter channel
        /// </summary>
        public UInt32 Channel
        {
            get
            {
                this.ThrowIfNotOpen();
                UInt32 channel;
                if (!AirPcapSafeNativeMethods.AirpcapGetDeviceChannel(this.AirPcapDeviceHandle, out channel))
                {
                    throw new InvalidOperationException("Failed to retrieve channel");
                }
                return channel;
            }

            set
            {
                this.ThrowIfNotOpen();
                if (!AirPcapSafeNativeMethods.AirpcapSetDeviceChannel(this.AirPcapDeviceHandle, value))
                {
                    throw new InvalidOperationException("Failed to set channel");
                }
            }
        }

        /// <summary>
        /// Adapter frequency
        /// </summary>
        public UInt32 Frequency
        {
            get
            {
                this.ThrowIfNotOpen();
                AirPcapUnmanagedStructures.AirpcapChannelInfo channelInfo;
                if (!AirPcapSafeNativeMethods.AirpcapGetDeviceChannelEx(this.AirPcapDeviceHandle, out channelInfo))
                {
                    throw new InvalidOperationException("Failed to retrieve frequency");
                }
                return channelInfo.Frequency;
            }

            set
            {
                this.ThrowIfNotOpen();
                AirPcapUnmanagedStructures.AirpcapChannelInfo channelInfo = new AirPcapUnmanagedStructures.AirpcapChannelInfo();
                channelInfo.Frequency = value;
                if (!AirPcapSafeNativeMethods.AirpcapSetDeviceChannelEx(this.AirPcapDeviceHandle, channelInfo))
                {
                    throw new InvalidOperationException("Failed to set frequency");
                }
            }
        }

        /// <summary>
        /// Channel information
        /// </summary>
        public AirPcapChannelInfo ChannelInfo
        {
            get
            {
                this.ThrowIfNotOpen();

                AirPcapUnmanagedStructures.AirpcapChannelInfo channelInfo;
                if(!AirPcapSafeNativeMethods.AirpcapGetDeviceChannelEx(this.AirPcapDeviceHandle, out channelInfo))
                {
                    throw new InvalidOperationException("Failed to get channel ex");
                }

                return new AirPcapChannelInfo(channelInfo);
            }

            set
            {
                this.ThrowIfNotOpen();

                var channelInfo = value.UnmanagedInfo;
                if (!AirPcapSafeNativeMethods.AirpcapSetDeviceChannelEx(this.AirPcapDeviceHandle, channelInfo))
                {
                    throw new InvalidOperationException("Failed to set channel ex");
                }
            }
        }

        /// <summary>
        /// Size in bytes of a key collection with a given count of keys
        /// </summary>
        /// <param name="keyCount"></param>
        /// <returns></returns>
        private static Int32 KeyCollectionSize(Int32 keyCount)
        {
            Int32 memorySize = (Int32)(Marshal.SizeOf(typeof(AirPcapUnmanagedStructures.AirpcapKeysCollection)) +
                                   (Marshal.SizeOf(typeof(AirPcapUnmanagedStructures.AirpcapKey)) * keyCount));
            return memorySize;
        }

        /// <summary>
        /// Convert a AirpcapKeysCollection unmanaged buffer to a list of managed keys
        /// </summary>
        /// <param name="pKeysCollection"></param>
        /// <returns></returns>
        private static List<AirPcapKey> IntPtrToKeys(IntPtr pKeysCollection)
        {
            var retval = new List<AirPcapKey>();

            // marshal the memory into a keys collection
            var keysCollection = (AirPcapUnmanagedStructures.AirpcapKeysCollection)Marshal.PtrToStructure(pKeysCollection,
                                                    typeof(AirPcapUnmanagedStructures.AirpcapKeysCollection));

            // go through the keys, offset from the start of the collection to the first key 
            IntPtr pKeys = new IntPtr(pKeysCollection.ToInt64() + Marshal.SizeOf(typeof(AirPcapUnmanagedStructures.AirpcapKeysCollection)));

            for (Int32 x = 0; x < keysCollection.nKeys; x++)
            {
                // convert the key entry from unmanaged memory to managed memory
                var airpcapKey = (AirPcapUnmanagedStructures.AirpcapKey)Marshal.PtrToStructure(pKeys, typeof(AirPcapUnmanagedStructures.AirpcapKey));

                // convert the now managed key into the key representation we want to see
                retval.Add(new AirPcapKey(airpcapKey));

                // advance the pointer to the next key in the collection
                pKeys = new IntPtr(pKeys.ToInt64() + Marshal.SizeOf(typeof(AirPcapUnmanagedStructures.AirpcapKey)));
            }

            return retval;
        }

        /// <summary>
        /// Convert an array of keys into unmanaged memory
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        private static IntPtr KeysToIntPtr(List<AirPcapKey> value)
        {
            // allocate memory for the entire collection
            IntPtr pKeyCollection = Marshal.AllocHGlobal(KeyCollectionSize(value.Count));
            var pKeyCollectionPosition = pKeyCollection;

            // build the collection struct
            var collection = new AirPcapUnmanagedStructures.AirpcapKeysCollection();
            collection.nKeys = (UInt32)value.Count;

            // convert this collection to unmanaged memory
            Marshal.StructureToPtr(collection, pKeyCollectionPosition, false);

            // advance the pointer
            pKeyCollectionPosition = new IntPtr(pKeyCollectionPosition.ToInt64() +
                                        Marshal.SizeOf(typeof(AirPcapUnmanagedStructures.AirpcapKeysCollection)));

            // write the keys to memory
            for (Int32 x = 0; x < value.Count; x++)
            {
                var key = new AirPcapUnmanagedStructures.AirpcapKey();
                key.KeyType = value[x].Type;
                key.KeyLen = (UInt32)value[x].Data.Length;

                // make sure we have the right size byte[], the fields in the structure passed to Marshal.StructureToPtr()
                // have to match the specified sizes or an exception will be thrown
                key.KeyData = new Byte[AirPcapUnmanagedStructures.WepKeyMaxSize];
                Array.Copy(value[x].Data, key.KeyData, value[x].Data.Length);

                // copy the managed memory into the unmanaged memory
                Marshal.StructureToPtr(key, pKeyCollectionPosition, false);

                // advance the pointer
                pKeyCollectionPosition = new IntPtr(pKeyCollectionPosition.ToInt64() + Marshal.SizeOf(typeof(AirPcapUnmanagedStructures.AirpcapKey)));
            }

            return pKeyCollection;
        }

        /// <summary>
        /// Decryption keys that are currently associated with the specified device
        /// </summary>
        public List<AirPcapKey> DeviceKeys
        {
            get
            {
                this.ThrowIfNotOpen();

                // Request the key collection size
                UInt32 keysCollectionSize = 0;
                if (AirPcapSafeNativeMethods.AirpcapGetDeviceKeys(this.AirPcapDeviceHandle, IntPtr.Zero,
                                                              ref keysCollectionSize))
                {
                    // return value of true with an input size of zero indicates there are no
                    // device keys
                    return null;
                }

                // now that we have the desired collection size, allocate the appropriate memory
                //var memorySize = AirPcapDevice.KeyCollectionSize(keysCollectionSize);
                var pKeysCollection = Marshal.AllocHGlobal((Int32)keysCollectionSize);

                try
                {
                    if (!AirPcapSafeNativeMethods.AirpcapGetDeviceKeys(this.AirPcapDeviceHandle, pKeysCollection,
                                                                      ref keysCollectionSize))
                    {
                        throw new InvalidOperationException("Unexpected false from AirpcapGetDeviceKeys()");
                    }

                    // convert the unmanaged memory to an array of keys
                    return IntPtrToKeys(pKeysCollection);
                }
                finally
                {
                    Marshal.FreeHGlobal(pKeysCollection);
                }
            }

            set
            {
                this.ThrowIfNotOpen();

                var pKeyCollection = KeysToIntPtr(value);
                try
                {
                    if (!AirPcapSafeNativeMethods.AirpcapSetDeviceKeys(this.AirPcapDeviceHandle, pKeyCollection))
                    {
                        throw new InvalidOperationException("Unable to set device keys");
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(pKeyCollection);
                }
            }
        }

        /// <summary>
        /// Global list of decryption keys that AirPcap is using with all the devices.
        /// </summary>
        public List<AirPcapKey> DriverKeys
        {
            get
            {
                this.ThrowIfNotOpen();

                // Request the key collection size
                UInt32 keysCollectionSize = 0;
                if (AirPcapSafeNativeMethods.AirpcapGetDriverKeys(this.AirPcapDeviceHandle, IntPtr.Zero,
                                                                  ref keysCollectionSize))
                {
                    // return value of true with an input size of zero indicates there are no
                    // device keys
                    return null;
                }

                // now that we have the desired collection size, allocate the appropriate memory
                //var memorySize = AirPcapDevice.KeyCollectionSize(keysCollectionSize);
                var pKeysCollection = Marshal.AllocHGlobal((Int32)keysCollectionSize);

                try
                {
                    if (!AirPcapSafeNativeMethods.AirpcapGetDriverKeys(this.AirPcapDeviceHandle, pKeysCollection,
                                                                       ref keysCollectionSize))
                    {
                        throw new InvalidOperationException("Unexpected false from AirpcapGetDriverKeys()");
                    }

                    // convert the unmanaged memory to an array of keys
                    return IntPtrToKeys(pKeysCollection);
                }
                finally
                {
                    Marshal.FreeHGlobal(pKeysCollection);
                }
            }

            set
            {
                this.ThrowIfNotOpen();

                var pKeyCollection = KeysToIntPtr(value);
                try
                {
                    if (!AirPcapSafeNativeMethods.AirpcapSetDriverKeys(this.AirPcapDeviceHandle, pKeyCollection))
                    {
                        throw new InvalidOperationException("Unable to set driver keys");
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(pKeyCollection);
                }
            }
        }

        /// <summary>
        /// Tells if decryption of the incoming frames with the <b>device-specific</b> keys.
        /// </summary>
        public AirPcapDecryptionState DecryptionState
        {
            get
            {
                this.ThrowIfNotOpen();

                AirPcapDecryptionState state;
                if (!AirPcapSafeNativeMethods.AirpcapGetDecryptionState(this.AirPcapDeviceHandle, out state))
                {
                    throw new InvalidOperationException("Failed to get decryption state");
                }
                return state;
            }

            set
            {
                this.ThrowIfNotOpen();

                if (!AirPcapSafeNativeMethods.AirpcapSetDecryptionState(this.AirPcapDeviceHandle, value))
                {
                    throw new InvalidOperationException("Failed to set decryption state");
                }
            }
        }

        /// <summary>
        /// Tells if this open instance is configured to perform the decryption of the incoming frames with the <b>global</b> set of keys.
        /// </summary>
        public AirPcapDecryptionState DriverDecryptionState
        {
            get
            {
                this.ThrowIfNotOpen();

                AirPcapDecryptionState state;
                if (!AirPcapSafeNativeMethods.AirpcapGetDriverDecryptionState(this.AirPcapDeviceHandle, out state))
                {
                    throw new InvalidOperationException("Failed to get driver decryption state");
                }
                return state;
            }

            set
            {
                this.ThrowIfNotOpen();

                if(AirPcapSafeNativeMethods.AirpcapSetDriverDecryptionState(this.AirPcapDeviceHandle, value))
                {
                    throw new InvalidOperationException("Failed to set decryption state");
                }
            }
        }

        /// <summary>
        /// Configures the adapter on whether to include the MAC Frame Check Sequence in the captured packets.
        /// </summary>
        public Boolean FcsPresence
        {
            get
            {
                this.ThrowIfNotOpen();

                Boolean isFcsPresent;
                if (!AirPcapSafeNativeMethods.AirpcapGetFcsPresence(this.AirPcapDeviceHandle, out isFcsPresent))
                {
                    throw new InvalidOperationException("Failed to get fcs presence");
                }
                return isFcsPresent;
            }

            set
            {
                this.ThrowIfNotOpen();

                if (!AirPcapSafeNativeMethods.AirpcapSetFcsPresence(this.AirPcapDeviceHandle, value))
                {
                    throw new InvalidOperationException("Failed to set fcs presence");
                }
            }
        }

        /// <summary>
        /// The kinds of frames that the device will capture
        /// By default all frames are captured
        /// </summary>
        public AirPcapValidationType FcsValidation
        {
            get
            {
                this.ThrowIfNotOpen();

                AirPcapValidationType validationType;
                if (!AirPcapSafeNativeMethods.AirpcapGetFcsValidation(this.AirPcapDeviceHandle, out validationType))
                {
                    throw new InvalidOperationException("Failed to get fcs validation");
                }
                return validationType;
            }

            set
            {
                this.ThrowIfNotOpen();

                if (!AirPcapSafeNativeMethods.AirpcapSetFcsValidation(this.AirPcapDeviceHandle, value))
                {
                    throw new InvalidOperationException("failed to set fcs validation");
                }
            }
        }

        /// <summary>
        /// Kernel packet buffer size for this adapter in bytes
        /// </summary>
        public override UInt32 KernelBufferSize
        {
            get
            {
                this.ThrowIfNotOpen();

                UInt32 kernelBufferSize;
                if(!AirPcapSafeNativeMethods.AirpcapGetKernelBufferSize(this.AirPcapDeviceHandle, out kernelBufferSize))
                {
                    throw new InvalidOperationException("failed to get kernel buffer size");
                }
                return kernelBufferSize;
            }

            set
            {
                this.ThrowIfNotOpen();

                if (!AirPcapSafeNativeMethods.AirpcapSetKernelBuffer(this.AirPcapDeviceHandle, value))
                {
                    throw new InvalidOperationException("failed to set kernel buffer size");
                }
            }
        }

        /// <summary>
        /// Number of leds on this adapter
        /// </summary>
        public Int32 LedCount
        {
            get
            {
                this.ThrowIfNotOpen();

                UInt32 numberOfLeds;
                AirPcapSafeNativeMethods.AirpcapGetLedsNumber(this.AirPcapDeviceHandle, out numberOfLeds);
                return (Int32)numberOfLeds;
            }
        }

        /// <summary>
        /// Led states
        /// </summary>
        public enum LedState
        {
            /// <summary>
            /// Led on
            /// </summary>
            On,

            /// <summary>
            /// Led off
            /// </summary>
            Off
        };

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="ledIndex">
        /// A <see cref="System.Int32"/>
        /// </param>
        /// <param name="newLedState">
        /// A <see cref="LedState"/>
        /// </param>
        public void Led(Int32 ledIndex, LedState newLedState)
        {
            this.ThrowIfNotOpen();

            if (newLedState == LedState.On)
            {
                AirPcapSafeNativeMethods.AirpcapTurnLedOn(this.AirPcapDeviceHandle, (UInt32)ledIndex);
            }
            else if (newLedState == LedState.Off)
            {
                AirPcapSafeNativeMethods.AirpcapTurnLedOff(this.AirPcapDeviceHandle, (UInt32)ledIndex);
            }
        }

        /// <summary>
        /// Link type
        /// </summary>
        public AirPcapLinkTypes AirPcapLinkType
        {
            get
            {
                this.ThrowIfNotOpen("Requires an open device");

                AirPcapLinkTypes linkType;

                AirPcapSafeNativeMethods.AirpcapGetLinkType(this.AirPcapDeviceHandle,
                                                            out linkType);


                return linkType;
            }

            set
            {
                this.ThrowIfNotOpen("Requires an open device");

                if (!AirPcapSafeNativeMethods.AirpcapSetLinkType(this.AirPcapDeviceHandle,
                                                                value))
                {
                    throw new InvalidOperationException("Setting link type failed");
                }
            }
        }

        /// <summary>
        /// Link type in terms of LinkLayers
        /// </summary>
        public override LinkLayers LinkType
        {
            get
            {
                var packetDotNetLinkLayer = LinkLayers.Null;

                switch(this.AirPcapLinkType)
                {
                    case AirPcapLinkTypes._802_11_PLUS_RADIO:
                        packetDotNetLinkLayer = LinkLayers.Ieee80211_Radio;
                        break;
                    case AirPcapLinkTypes._802_11:
                        packetDotNetLinkLayer = LinkLayers.Ieee80211;
                        break;
                    case AirPcapLinkTypes._802_11_PLUS_PPI:
                        packetDotNetLinkLayer = LinkLayers.PerPacketInformation;
                        break;
                    default:
                        throw new InvalidOperationException("Unexpected linkType " + this.AirPcapLinkType);
                }

                return packetDotNetLinkLayer;
            }
        }

        /// <summary>
        /// TODO: Get this from packet.net or another place in System.Net.xxx?
        /// </summary>
        private const Int32 MacAddressSizeInBytes = 6;

        /// <summary>
        /// Mac address
        /// </summary>
        public override PhysicalAddress MacAddress
        {
            get
            {
                this.ThrowIfNotOpen();

                var address = new Byte[MacAddressSizeInBytes];
                IntPtr addressUnmanaged = Marshal.AllocHGlobal(MacAddressSizeInBytes);
                try
                {
                    if (!AirPcapSafeNativeMethods.AirpcapGetMacAddress(this.AirPcapDeviceHandle, addressUnmanaged))
                    {
                        throw new InvalidOperationException("Unable to get mac address");
                    }

                    Marshal.Copy(addressUnmanaged, address, 0, address.Length);

                    return new PhysicalAddress(address);
                }
                finally
                {
                    Marshal.FreeHGlobal(addressUnmanaged);
                }
            }

            set
            {
                this.ThrowIfNotOpen();

                var address = value.GetAddressBytes();
                var addressUnmanaged = Marshal.AllocHGlobal(address.Length);
                try
                {
                    if (!AirPcapSafeNativeMethods.AirpcapSetMacAddress(this.AirPcapDeviceHandle, addressUnmanaged))
                    {
                        throw new InvalidOperationException("Unable to set mac address");
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(addressUnmanaged);
                }
            }
        }

        /// <summary>
        /// Mac flags
        /// </summary>
        public AirPcapMacFlags MacFlags
        {
            get
            {
                this.ThrowIfNotOpen();

                AirPcapMacFlags macFlags;
                if (!AirPcapSafeNativeMethods.AirpcapGetDeviceMacFlags(this.AirPcapDeviceHandle, out macFlags))
                {
                    throw new InvalidOperationException("Failed to get device mac flags");
                }
                return macFlags;
            }

            set
            {
                this.ThrowIfNotOpen();

                if (!AirPcapSafeNativeMethods.AirpcapSetDeviceMacFlags(this.AirPcapDeviceHandle, value))
                {
                    throw new InvalidOperationException("Failed to set device mac flags");
                }
            }
        }

        /// <summary>
        /// Adapter statistics
        /// </summary>
        public override ICaptureStatistics Statistics
        {
            get
            {
                return new AirPcapStatistics(this.AirPcapDeviceHandle);
            }
        }

        /// <summary>
        /// List of supported channels
        /// </summary>
        public List<AirPcapChannelInfo> SupportedChannels
        {
            get
            {
                this.ThrowIfNotOpen();

                var retval = new List<AirPcapChannelInfo>();
                IntPtr pChannelInfo;
                UInt32 numChannelInfo;

                if (!AirPcapSafeNativeMethods.AirpcapGetDeviceSupportedChannels(this.AirPcapDeviceHandle, out pChannelInfo, out numChannelInfo))
                {
                    throw new InvalidOperationException("Failed to get device supported channels");
                }

                for (Int32 x = 0; x < numChannelInfo; x++)
                {
                    var unmanagedChannelInfo = (AirPcapUnmanagedStructures.AirpcapChannelInfo)Marshal.PtrToStructure(pChannelInfo,
                                                                                                            typeof(AirPcapUnmanagedStructures.AirpcapChannelInfo));

                    var channelInfo = new AirPcapChannelInfo(unmanagedChannelInfo);

                    retval.Add(channelInfo);

                    // advance the pointer to the next address
                    pChannelInfo = new IntPtr(pChannelInfo.ToInt64() + Marshal.SizeOf(typeof(AirPcapUnmanagedStructures.AirpcapChannelInfo)));
                }

                return retval;
            }
        }

        /// <summary>
        /// Transmit power
        /// </summary>
        public UInt32 TxPower
        {
            get
            {
                this.ThrowIfNotOpen();

                UInt32 power;
                if (!AirPcapSafeNativeMethods.AirpcapGetTxPower(this.AirPcapDeviceHandle, out power))
                {
                    throw new NotSupportedException("Unable to retrieve the tx power for this adapter");
                }
                return power;
            }

            set
            {
                this.ThrowIfNotOpen();

                if (!AirPcapSafeNativeMethods.AirpcapSetTxPower(this.AirPcapDeviceHandle, value))
                {
                    throw new NotSupportedException("Unable to set the tx power for this adapter");
                }
            }
        }

        /// <summary>
        /// Device timestamp
        /// </summary>
        public AirPcapDeviceTimestamp Timestamp
        {
            get
            {
                this.ThrowIfNotOpen();

                var pTimestamp = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(AirPcapUnmanagedStructures.AirpcapDeviceTimestamp)));
                try
                {
                    if (!AirPcapSafeNativeMethods.AirpcapGetDeviceTimestamp(this.AirPcapDeviceHandle, pTimestamp))
                    {
                        throw new NotSupportedException("Failed to get device timestamp");
                    }

                    var timestamp = (AirPcapUnmanagedStructures.AirpcapDeviceTimestamp)Marshal.PtrToStructure(pTimestamp,
                                                        typeof(AirPcapUnmanagedStructures.AirpcapDeviceTimestamp));

                    return new AirPcapDeviceTimestamp(timestamp);
                }
                finally
                {
                    Marshal.FreeHGlobal(pTimestamp);
                }
            }
        }

        /// <summary>
        /// AirPcap specific capture thread
        /// </summary>
        protected override void CaptureThread()
        {
            IntPtr ReadEvent;
            IntPtr WaitIntervalMilliseconds = (IntPtr)500;

            //
            // Get the read event
            //
            if (!AirPcapSafeNativeMethods.AirpcapGetReadEvent(this.AirPcapDeviceHandle, out ReadEvent))
            {
                this.SendCaptureStoppedEvent(CaptureStoppedEventStatus.ErrorWhileCapturing);
                this.Close();
                return;
            }

            // allocate a packet bufer in unmanaged memory
            var packetBufferSize = 256000;
            var packetBuffer = Marshal.AllocHGlobal(packetBufferSize);

            UInt32 BytesReceived;

            List<RawCapture> packets;

            while (!this.shouldCaptureThreadStop)
            {
                // capture the packets
                if (!AirPcapSafeNativeMethods.AirpcapRead(this.AirPcapDeviceHandle,
                    packetBuffer,
                   (UInt32)packetBufferSize,
                    out BytesReceived))
                {
                    Marshal.FreeHGlobal(packetBuffer);
                    this.Close();
                    this.SendCaptureStoppedEvent(CaptureStoppedEventStatus.ErrorWhileCapturing);
                    return;
                }

                var bufferEnd = new IntPtr(packetBuffer.ToInt64() + (Int64)BytesReceived);

                this.MarshalPackets(packetBuffer, bufferEnd, out packets);

                foreach (var p in packets)
                {
                    this.SendPacketArrivalEvent(p);
                }

                // wait until some packets are available. This prevents polling and keeps the CPU low. 
                Win32SafeNativeMethods.WaitForSingleObject(ReadEvent, WaitIntervalMilliseconds);
            }

            Marshal.FreeHGlobal(packetBuffer);
        }

        /// <summary>
        /// Marshal a chunk of captured packets into a packet list
        /// </summary>
        /// <param name="packetsBuffer"></param>
        /// <param name="bufferEnd"></param>
        /// <param name="packets"></param>
        protected virtual void MarshalPackets(IntPtr packetsBuffer, IntPtr bufferEnd,
                                              out List<RawCapture> packets)
        {
            RawCapture p;

            var linkType = this.LinkType;

            packets = new List<RawCapture>();

            IntPtr bufferPointer = packetsBuffer;

            while (bufferPointer.ToInt64() < bufferEnd.ToInt64())
            {
                // marshal the header
                var header = new AirPcapPacketHeader(bufferPointer);

                // advance the pointer to the packet data and marshal that data
                // into a managed buffer
                bufferPointer = new IntPtr(bufferPointer.ToInt64() + header.Hdrlen);
                var pkt_data = new Byte[header.Caplen];
                Marshal.Copy(bufferPointer, pkt_data, 0, (Int32)header.Caplen);

                p = new RawCapture(linkType,
                                   new PosixTimeval(header.TsSec,
                                                    header.TsUsec),
                                   pkt_data);

                packets.Add(p);

                // advance the pointer by the size of the data
                // and round up to the next word offset since each frame header is on a word boundry
                Int32 alignment = 4;
                var pointer = bufferPointer.ToInt64() + header.Caplen;
                pointer = RoundUp(pointer, alignment);
                bufferPointer = new IntPtr(pointer);
            }
        }

        private static Int64 RoundUp(Int64 num, Int32 multiple)
        {
            if (multiple == 0)
                return 0;
            Int32 add = multiple / Math.Abs(multiple);
            return ((num + multiple - add) / multiple) * multiple;
        }
        internal static Int32 AIRPCAP_ERRBUF_SIZE = 512;
    }
}
