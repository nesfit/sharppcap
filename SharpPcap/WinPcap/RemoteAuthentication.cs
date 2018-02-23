using System;
using System.Runtime.InteropServices;

namespace SharpPcap.WinPcap
{
    /// <summary>
    /// Remote authentication type and parameters
    /// </summary>
    public class RemoteAuthentication
    {
        /// <summary>
        /// Type of authentication
        /// </summary>
        public AuthenticationTypes Type { get; set; }

        /// <summary>
        /// Username
        /// </summary>
        public String Username { get; set; }

        /// <summary>
        /// Password
        /// </summary>
        public String Password { get; set; }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="Type">
        /// A <see cref="AuthenticationTypes"/>
        /// </param>
        /// <param name="Username">
        /// A <see cref="System.String"/>
        /// </param>
        /// <param name="Password">
        /// A <see cref="System.String"/>
        /// </param>
        public RemoteAuthentication (AuthenticationTypes Type,
                                     String Username,
                                     String Password)
        {
            this.Type = Type;
            this.Username = Username;
            this.Password = Password;
        }

        /// <summary>
        /// Converts this structure to an unmanaged IntPtr. Should be
        /// freed with Marshal.FreeHGlobal(IntPtr);
        /// </summary>
        /// <returns>
        /// A <see cref="IntPtr"/>
        /// </returns>
        internal IntPtr GetUnmanaged()
        {
            UnmanagedStructures.pcap_rmtauth rmauth;
            rmauth.type = (IntPtr) this.Type;
            rmauth.username = this.Username;
            rmauth.password = this.Password;

            // Initialize unmanged memory to hold the struct.
            IntPtr rmAuthPointer = Marshal.AllocHGlobal(Marshal.SizeOf(rmauth));

            // marshal pcap_rmtauth
            Marshal.StructureToPtr(rmauth, rmAuthPointer, false);

            return rmAuthPointer;
        }
    }
}
