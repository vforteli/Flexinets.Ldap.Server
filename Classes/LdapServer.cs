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
                using (var client = _server.EndAcceptTcpClient(ar))
                {
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
                                var response = HandleSearchRequest(searchRequest);
                                stream.Write(response, 0, response.Length);
                            }
                        }

                        _log.Debug($"Connection closed to {client.Client.RemoteEndPoint}");
                    }
                    catch (IOException ioex)
                    {
                        _log.Warn("oops", ioex);
                    }
                }
            }
        }


        /// <summary>
        /// Handle search requests
        /// </summary>
        /// <param name="searchRequest"></param>
        /// <returns></returns>
        private Byte[] HandleSearchRequest(LdapAttribute searchRequest)
        {
            var filter = searchRequest.ChildAttributes[6];
            if (filter.ContextType == 3) // equalityMatch
            {
                if ($"{filter.ChildAttributes[0].GetValue()}={filter.ChildAttributes[1].GetValue()}" == "sAMAccountName=testuser")
                {
                    _log.Debug($"filter: {filter.ChildAttributes[0].GetValue()}={filter.ChildAttributes[1].GetValue()}");
                }
            }

            var packet = LdapAttribute.CreatePacket(2); // todo sort out this message id...
            var response = new LdapAttribute(LdapOperation.SearchResultDone, true);
            response.ChildAttributes.Add(new LdapAttribute(UniversalDataType.Enumerated, false) { Value = new Byte[] { (Byte)LdapResult.success } }); // success
            response.ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, false));  // matchedDN
            response.ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, false));  // diagnosticMessage
            packet.ChildAttributes.Add(response);
            return packet.GetBytes();
        }


        /// <summary>
        /// Handle bindrequests
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="bindrequest"></param>
        private Byte[] HandleBindRequest(LdapAttribute bindrequest)
        {
            var username = bindrequest.ChildAttributes[1].GetValue().ToString();
            var password = bindrequest.ChildAttributes[2].GetValue().ToString();

            var response = LdapResult.invalidCredentials;

            if (username == "cn=bindUser,cn=Users,dc=dev,dc=company,dc=com" && password == "bindUserPassword")
            {
                response = LdapResult.success;
            }

            var packet = LdapAttribute.CreatePacket(1); // todo sort out this message id...
            var bindResponse = new LdapAttribute(LdapOperation.BindResponse, true);
            bindResponse.ChildAttributes.Add(new LdapAttribute(UniversalDataType.Enumerated, false) { Value = new Byte[] { (Byte)response } }); // success
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