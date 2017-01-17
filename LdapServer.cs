using log4net;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Flexinets.Ldap
{
    public class LdapServer
    {
        private readonly ILog _log = LogManager.GetLogger(typeof(LdapServer));
        private readonly TcpListener _server;

        public Boolean Running
        {
            get;
            private set;
        }


        /// <summary>
        /// Create a new server on endpoint
        /// </summary>
        /// <param name="serverEndpoint"></param>
        /// <param name="dictionary"></param>
        public LdapServer(IPEndPoint serverEndpoint)
        {
            _server = new TcpListener(serverEndpoint);
        }


        /// <summary>
        /// Start listening for requests
        /// </summary>
        public void Start()
        {
            _server.Start();
            _server.BeginAcceptTcpClient(ReceiveCallback, null);
            Running = true;
        }


        /// <summary>
        /// Stop listening
        /// </summary>
        public void Stop()
        {
            _server.Stop();
            Running = false;
        }


        /// <summary>
        /// Receive packets
        /// </summary>
        /// <param name="ar"></param>
        private void ReceiveCallback(IAsyncResult ar)
        {
            if (Running)
            {
                var client = _server.EndAcceptTcpClient(ar);
                _server.BeginAcceptTcpClient(ReceiveCallback, null);

                _log.Debug($"Connection from {client.Client.RemoteEndPoint}");
                
                try
                {
                    var stream = client.GetStream();
                    var bytes = new Byte[1024];
                    String data;
                    var i = stream.Read(bytes, 0, bytes.Length);
   
                    while (i != 0)
                    {
                        data = Encoding.UTF8.GetString(bytes, 0, i);
                        _log.Debug($"Received {i} bytes: {data}");
                        _log.Debug(Utils.ByteArrayToString(bytes));
                        ParseLdapPacket(bytes);

                        // 30 29 02 01 01 60 24 02 01 03 04 19 63 6e 3d 66 6f 6f 2c 6f 75 3d 66 6c 65 78 69 6e 65 74 73 2c 6f 75 3d 73 65 80 04 68 75 72 72 00 00
                        if (data.Contains("cn=foo,ou=flexinets,ou=se"))
                        {
                            var bindresponse = Utils.StringToByteArray("300c02010161070a010004000400"); // bind success...
                            stream.Write(bindresponse, 0, bindresponse.Length);
                        }
                        if (data.Contains("uid"))
                        {
                            var searchresponse = Utils.StringToByteArray("300c02010265070a012004000400");   // object not found
                            stream.Write(searchresponse, 0, searchresponse.Length);
                        }

                        i = stream.Read(bytes, 0, bytes.Length);
                    }
                }
                catch (IOException ioex)
                {
                    _log.Warn("oops", ioex);
                }
            }
        }


        private void ParseLdapPacket(Byte[] packetBytes)
        {
            int i = 1;
            _log.Debug($"Packet length byte {packetBytes[i]}");
            var firstbit = packetBytes[i] >> 7;
            if (firstbit == 1)    // Long notation
            {
                var lengthoflengthbytes = packetBytes[i] &= 127;
                _log.Debug($"Length of length: {lengthoflengthbytes}");

                // todo hurgh...
                if (lengthoflengthbytes == 1)
                {
                    _log.Debug($"Packet length: { packetBytes[i + 1]}");
                }
                else if (lengthoflengthbytes == 2)
                {
                    var floff = new Byte[2];
                    Buffer.BlockCopy(packetBytes, i + 1, floff, 0, 2);
                    _log.Debug($"Packet length: { BitConverter.ToUInt16(floff.Reverse().ToArray(), 0)}"); // todo, flip byte order... meh
                }

            }
            else // Short notation
            {
                var lengthbytes = packetBytes[i] &= 127;
                _log.Debug($"Short length notation: {lengthbytes}");
            }
        }
    }
}

