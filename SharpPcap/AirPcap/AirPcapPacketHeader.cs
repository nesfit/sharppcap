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
using System.Runtime.InteropServices;

namespace SharpPcap.AirPcap
{
    /// <summary>
    /// Packet header
    /// </summary>
    public class AirPcapPacketHeader
    {
        /// <summary>
        /// Seconds field
        /// </summary>
        public UInt64 TsSec
        {
            get;
            set;
        }

        /// <summary>
        /// Microseconds field
        /// </summary>
        public UInt64 TsUsec
        {
            get;
            set;
        }

        /// <summary>
        /// Number of bytes captured
        /// </summary>
        public Int64 Caplen
        {
            get;
            set;
        }

        /// <summary>
        /// On-line packet size in bytes
        /// </summary>
        public Int64 Originallen
        {
            get;
            set;
        }

        /// <summary>
        /// Header length in bytes
        /// </summary>
        public Int64 Hdrlen
        {
            get;
            set;
        }

        internal AirPcapPacketHeader(IntPtr packetHeader)
        {
            var pkthdr = (AirPcapUnmanagedStructures.AirpcapBpfHeader)Marshal.PtrToStructure(packetHeader,
                                                                                             typeof(AirPcapUnmanagedStructures.AirpcapBpfHeader));

            this.TsSec          = (UInt64)pkthdr.TsSec;
            this.TsUsec         = (UInt64)pkthdr.TsUsec;
            this.Caplen         = (Int64)pkthdr.Caplen;
            this.Originallen    = (Int64)pkthdr.Originallen;
            this.Hdrlen         = (Int64)pkthdr.Hdrlen;
        }

        /// <summary>
        /// ToString() override
        /// </summary>
        /// <returns>
        /// A <see cref="System.String"/>
        /// </returns>
        public override String ToString()
        {
            return String.Format("TsSec {0}, TsUSec {1}, Caplen {2}, Originallen {3}, Hdrlen {4}", this.TsSec, this.TsUsec, this.Caplen, this.Originallen, this.Hdrlen);
        }
    }
}
