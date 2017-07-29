using Flexinets.Ldap.Core;
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
        /// <param name="localEndpoint"></param>
        public LdapServer(IPEndPoint localEndpoint)
        {
            _server = new TcpListener(localEndpoint);
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

                        while (true)
                        {
                            var bytes = new Byte[1024];
                            var i = stream.Read(bytes, 0, bytes.Length);
                            if (i == 0)
                            {
                                break;
                            }

                            _log.Debug($"Received {i} bytes: {Utils.ByteArrayToString(bytes)}");

                            var requestPacket = LdapPacket.ParsePacket(bytes);
                            PrintValue(requestPacket);

                            if (requestPacket.ChildAttributes.Any(o => o.LdapOperation == LdapOperation.BindRequest))
                            {
                                var responseBytes = HandleBindRequest(requestPacket);
                                stream.Write(responseBytes, 0, responseBytes.Length);
                            }

                            if (requestPacket.ChildAttributes.Any(o => o.LdapOperation == LdapOperation.SearchRequest))
                            {
                                HandleSearchRequest(stream, requestPacket);
                            }
                        }

                        _log.Debug($"Connection closed to {client.Client.RemoteEndPoint}");
                    }
                    catch (IOException ioex)
                    {
                        _log.Warn("oops", ioex);
                    }
                    catch (Exception ex)
                    {
                        _log.Error("Something went wrong", ex);
                    }
                }
            }
        }


        /// <summary>
        /// Handle search requests
        /// </summary>
        /// <param name="searchRequest"></param>
        /// <returns></returns>
        private void HandleSearchRequest(NetworkStream stream, LdapPacket requestPacket)
        {
            var searchRequest = requestPacket.ChildAttributes.SingleOrDefault(o => o.Class == TagClass.Application && o.LdapOperation == LdapOperation.SearchRequest);
            var filter = searchRequest.ChildAttributes[6];

            if (filter.ContextType == (Byte)LdapFilterChoice.equalityMatch && filter.ChildAttributes[0].GetValue<String>() == "sAMAccountName" && filter.ChildAttributes[1].GetValue<String>() == "testuser") // equalityMatch
            {
                var responseEntryPacket = new LdapPacket(requestPacket.MessageId);
                var searchResultEntry = new LdapAttribute(LdapOperation.SearchResultEntry, true);
                searchResultEntry.ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, false, "cn=testuser,cn=Users,dc=dev,dc=company,dc=com"));
                searchResultEntry.ChildAttributes.Add(new LdapAttribute(UniversalDataType.Sequence, true));
                responseEntryPacket.ChildAttributes.Add(searchResultEntry);
                var responsEntryBytes = responseEntryPacket.GetBytes();
                stream.Write(responsEntryBytes, 0, responsEntryBytes.Length);
            }

            var responseDonePacket = new LdapPacket(requestPacket.MessageId);
            var response = new LdapAttribute(LdapOperation.SearchResultDone, true);
            response.ChildAttributes.Add(new LdapAttribute(UniversalDataType.Enumerated, false, (Byte)LdapResult.success));
            response.ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, false));  // matchedDN
            response.ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, false));  // diagnosticMessage
            responseDonePacket.ChildAttributes.Add(response);
            var responsDoneBytes = responseDonePacket.GetBytes();
            stream.Write(responsDoneBytes, 0, responsDoneBytes.Length);
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
            if (username == "cn=bindUser,cn=Users,dc=dev,dc=company,dc=com" && password == "bindUserPassword"
                || username == "cn=testuser,cn=Users,dc=dev,dc=company,dc=com" && password == "123")
            {
                response = LdapResult.success;
            }

            var responsePacket = new LdapPacket(requestPacket.MessageId);
            var bindResponse = new LdapAttribute(LdapOperation.BindResponse, true);
            bindResponse.ChildAttributes.Add(new LdapAttribute(UniversalDataType.Enumerated, false, (Byte)response));
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