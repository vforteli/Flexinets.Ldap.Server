using log4net;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;

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

                            var requestPacket = LdapPacket.ParsePacket(bytes);
                            PrintValue(requestPacket);

                            if (requestPacket.ChildAttributes.Any(o => o.Class == TagClass.Application && o.LdapOperation == LdapOperation.BindRequest))
                            {
                                var responseBytes = HandleBindRequest(requestPacket);
                                stream.Write(responseBytes, 0, responseBytes.Length);
                            }

                            if (requestPacket.ChildAttributes.Any(o => o.Class == TagClass.Application && o.LdapOperation == LdapOperation.SearchRequest))
                            {
                                var response = HandleSearchRequest(requestPacket);
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
        private Byte[] HandleSearchRequest(LdapPacket requestPacket)
        {
            var searchRequest = requestPacket.ChildAttributes.SingleOrDefault(o => o.Class == TagClass.Application && o.LdapOperation == LdapOperation.SearchRequest);
            var filter = searchRequest.ChildAttributes[6];
            if (filter.ContextType == 3) // equalityMatch
            {
                if ($"{filter.ChildAttributes[0].GetValue<String>()}={filter.ChildAttributes[1].GetValue<String>()}" == "sAMAccountName=testuser")
                {
                    _log.Debug($"filter: {filter.ChildAttributes[0].GetValue<String>()}={filter.ChildAttributes[1].GetValue<String>()}");
                }
            }

            var responsePacket = new LdapPacket(requestPacket.MessageId);
            var response = new LdapAttribute(LdapOperation.SearchResultDone, true);
            response.ChildAttributes.Add(new LdapAttribute(UniversalDataType.Enumerated, false) { Value = new Byte[] { (Byte)LdapResult.success } }); // success
            response.ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, false));  // matchedDN
            response.ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, false));  // diagnosticMessage
            responsePacket.ChildAttributes.Add(response);
            return responsePacket.GetBytes();
        }


        /// <summary>
        /// Handle bindrequests
        /// </summary>
        /// <param name="bindrequest"></param>
        private Byte[] HandleBindRequest(LdapPacket requestPacket)
        {
            var bindrequest = requestPacket.ChildAttributes.SingleOrDefault(o => o.Class == TagClass.Application && o.LdapOperation == LdapOperation.BindRequest);
            var username = bindrequest.ChildAttributes[1].GetValue<String>();
            var password = bindrequest.ChildAttributes[2].GetValue<String>();

            var response = LdapResult.invalidCredentials;
            if (username == "cn=bindUser,cn=Users,dc=dev,dc=company,dc=com" && password == "bindUserPassword")
            {
                response = LdapResult.success;
            }

            var responsePacket = new LdapPacket(requestPacket.MessageId);
            var bindResponse = new LdapAttribute(LdapOperation.BindResponse, true);
            bindResponse.ChildAttributes.Add(new LdapAttribute(UniversalDataType.Enumerated, false) { Value = new Byte[] { (Byte)response } }); // success
            bindResponse.ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, false));  // matchedDN
            bindResponse.ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, false));  // diagnosticMessage
            responsePacket.ChildAttributes.Add(bindResponse);
            return responsePacket.GetBytes();
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