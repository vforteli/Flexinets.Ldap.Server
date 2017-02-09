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

                        _log.Debug($"Received {i} bytes: {Utils.ByteArrayToString(bytes)}");

                        var ldapPacket = LdapAttribute.ParsePacket(bytes);
                        PrintValue(ldapPacket);


                        var bindrequest = ldapPacket.ChildAttributes.SingleOrDefault(o => o.Class == TagClass.Application && o.LdapOperation == LdapOperation.BindRequest);
                        if (bindrequest != null)
                        {
                            var responseBytes = HandleBindRequest(bindrequest);
                            stream.Write(responseBytes, 0, responseBytes.Length);
                        }

                        var searchRequest = ldapPacket.ChildAttributes.SingleOrDefault(o => o.Class == TagClass.Application && o.LdapOperation == LdapOperation.SearchRequest);
                        if (searchRequest != null)
                        {
                            var searchresponse = Utils.StringToByteArray("300c02010265070a012004000400");   // object not found
                            stream.Write(searchresponse, 0, searchresponse.Length);
                        }
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


        /// <summary>
        /// Handle bindrequests
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="bindrequest"></param>
        private static Byte[] HandleBindRequest(LdapAttribute bindrequest)
        {
            var username = bindrequest.ChildAttributes[1].GetValue().ToString();
            var password = bindrequest.ChildAttributes[2].GetValue().ToString();

            var response = LdapResult.invalidCredentials;

            if (username == "cn=bindUser,cn=Users,dc=dev,dc=company,dc=com" && password == "bindUserPassword")
            {
                response = LdapResult.success;
            }
            
            var packet = new LdapAttribute(UniversalDataType.Sequence, true);
            packet.ChildAttributes.Add(new LdapAttribute(UniversalDataType.Integer, false) { Value = new Byte[] { 1 } }); // messageId

            var bindResponse = new LdapAttribute(LdapOperation.BindResponse, true);
            bindResponse.ChildAttributes.Add(new LdapAttribute(UniversalDataType.Enumerated, false) { Value = new Byte[] { (byte)response } }); // success
            bindResponse.ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, false));  // matchedDN
            bindResponse.ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, false));  // diagnosticMessage

            packet.ChildAttributes.Add(bindResponse);

            return packet.GetBytes();
        }


        /// <summary>
        /// Dump the packet to log
        /// </summary>
        /// <param name="attribute"></param>
        private void PrintValue(LdapAttribute attribute, Int32 depth = 1)
        {
            if (attribute != null)
            {
                if (attribute.Class == TagClass.Universal)
                {
                    _log.Debug($"{Utils.Repeat(">", depth)} {attribute.Class} tag, DataType: {attribute.DataType} Value type: {attribute.GetValue().GetType()} {attribute.GetValue()}");
                }
                else if (attribute.Class == TagClass.Application)
                {
                    _log.Debug($"{Utils.Repeat(">", depth)} {attribute.Class} tag, LdapOperation: {attribute.LdapOperation} Value type: {attribute.GetValue().GetType()} {attribute.GetValue()}");
                }
                else if (attribute.Class == TagClass.Context)
                {
                    _log.Debug($"{Utils.Repeat(">", depth)} {attribute.Class} tag, Context: {attribute.ContextType} Value type: {attribute.GetValue().GetType()} {attribute.GetValue()}");
                }

                if (attribute.IsConstructed)
                {
                    foreach (var attr in attribute.ChildAttributes)
                    {
                        depth++;
                        PrintValue(attr, depth);
                        depth--;
                    }
                }
            }
        }
    }
}