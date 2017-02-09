using log4net;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

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

                    int i = 0;
                    while (true)
                    {
                        var bytes = new Byte[1024];
                        i = stream.Read(bytes, 0, bytes.Length);
                        if (i == 0)
                        {
                            break;
                        }

                        
                        var data = Encoding.UTF8.GetString(bytes, 0, i);
                        _log.Debug($"Received {i} bytes: {data}");
                        _log.Debug(Utils.ByteArrayToString(bytes));

                        var ldapPacket = LdapAttribute.ParsePacket(bytes);
                        PrintValue(ldapPacket);


                        if (data.Contains("cn=bindUser,cn=Users,dc=dev,dc=company,dc=com"))
                        {
                            var bindresponse = Utils.StringToByteArray("300c02010161070a010004000400"); // bind success...
                            stream.Write(bindresponse, 0, bindresponse.Length);
                        }
                        if (data.Contains("sAMAccountName"))
                        {
                            var searchresponse = Utils.StringToByteArray("300c02010265070a012004000400");   // object not found
                            //_log.Debug(Utils.BitsToString(new System.Collections.BitArray(searchresponse)));
                            stream.Write(searchresponse, 0, searchresponse.Length);
                        }

                        _log.Debug(" --- ");
                    }

                    _log.Debug($"Connection closed to {client.Client.RemoteEndPoint}");
                    client.Close();
                }
                catch (IOException ioex)
                {
                    _log.Warn("oops", ioex);
                }
            }
        }

        private void PrintValue(LdapAttribute attribute)
        {
            if (attribute.Tag.Class == TagClass.Universal)
            {
                _log.Debug($"{Utils.Repeat(">", depth)} {attribute.Tag.Class} tag, DataType: {attribute.Tag.DataType} Value type: {attribute.GetValue().GetType()} {attribute.GetValue()}");
            }
            else if (attribute.Tag.Class == TagClass.Application)
            {
                _log.Debug($"{Utils.Repeat(">", depth)} {attribute.Tag.Class} tag, LdapOperation: {attribute.Tag.LdapOperation} Value type: {attribute.GetValue().GetType()} {attribute.GetValue()}");
            }
            else if (attribute.Tag.Class == TagClass.Context)
            {
                _log.Debug($"{Utils.Repeat(">", depth)} {attribute.Tag.Class} tag, Context: {attribute.Tag.ContextType} Value type: {attribute.GetValue().GetType()} {attribute.GetValue()}");
            }

            if (attribute.Tag.IsConstructed)
            {                
                foreach (var attr in attribute.ChildAttributes)
                {
                    depth++;
                    PrintValue(attr);
                    depth--;
                }                
            }            
        }
        private Int32 depth = 1;        
    }
}