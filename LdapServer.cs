using log4net;
using System;
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
                _log.Debug("huurr");
                var client = _server.EndAcceptTcpClient(ar);
                _log.Debug("got a connection?");

                // Immediately start listening for the next packet
                _server.BeginAcceptTcpClient(ReceiveCallback, null);

                var stream = client.GetStream();
                var reader = new StreamReader(stream);
                var writer = new StreamWriter(stream) { AutoFlush = true };
                try
                {
                    byte[] bytes = new byte[1024];
                    string data;
                    int i;
                    
                    i = stream.Read(bytes, 0, bytes.Length);

                    while (i != 0)
                    {
                        data = Encoding.UTF8.GetString(bytes, 0, i);
                        _log.Debug(Utils.ByteArrayToString(bytes));
                        _log.Debug(String.Format("Received: {0}", data));

                        if (data.Contains("cn=foo,ou=flexinets,ou=se"))
                        {
                            var bindresponse = Utils.StringToByteArray("300c02010161070a010004000400");
                            stream.Write(bindresponse, 0, bindresponse.Length);
                        }
                        if (data.Contains("uid"))
                        {
                            var searchresponse = Utils.StringToByteArray("300c02010265070a012004000400");
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
    }
}

