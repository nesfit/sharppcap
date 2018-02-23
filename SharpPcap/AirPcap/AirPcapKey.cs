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

namespace SharpPcap.AirPcap
{
    /// <summary>
    /// WEB key container
    /// </summary>
    public class AirPcapKey
    {
        /// <summary>
        /// Number of bytes in a wep key
        /// </summary>
        public const Int32 WepKeyMaxSize = 32;

        /// <summary>
        /// Type of key, can be on of: \ref AIRPCAP_KEYTYPE_WEP, \ref AIRPCAP_KEYTYPE_TKIP, \ref AIRPCAP_KEYTYPE_CCMP. Only AIRPCAP_KEYTYPE_WEP is supported by the driver at the moment.
        /// </summary>
        public AirPcapKeyType Type;

        /// <summary>
        /// Key data
        /// </summary>
        public Byte[] Data;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="Type"></param>
        /// <param name="Data"></param>
        public AirPcapKey(AirPcapKeyType Type, Byte[] Data)
        {
            this.Type = Type;
            this.Data = Data;
        }

        internal AirPcapKey(AirPcapUnmanagedStructures.AirpcapKey key)
        {
            this.Type = key.KeyType;

            this.Data = new Byte[key.KeyData.Length];
            Array.Copy(key.KeyData, this.Data, this.Data.Length);
        }

        /// <summary>
        ///
        /// </summary>
        /// <returns>
        /// A <see cref="System.String"/>
        /// </returns>
        public override String ToString()
        {
            return String.Format("[AirPcapKey Type: {0}, Data.Length: {1}]", this.Type, this.Data.Length);
        }
    }
}
