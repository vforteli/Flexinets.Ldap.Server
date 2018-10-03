using Flexinets.Ldap.Core;
using log4net;
using System;
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
            var receiveTask = StartAcceptingClientsAsync();
        }


        /// <summary>
        /// Stop listening
        /// </summary>
        public void Stop()
        {
            _server?.Stop();
        }


        /// <summary>
        /// Start the loop used for accepting clients
        /// </summary>
        /// <returns></returns>
        private async Task StartAcceptingClientsAsync()
        {
            while (_server.Server.IsBound)
            {
                try
                {
                    var client = await _server.AcceptTcpClientAsync();
                    var task = Task.Factory.StartNew(() => HandleClient(client), TaskCreationOptions.LongRunning);
                }
                catch (ObjectDisposedException) { } // Thrown when server is stopped while still receiving. This can be safely ignored
                catch (Exception ex)
                {
                    _log.Fatal("Something went wrong accepting client", ex);
                }
            }
        }

        /// <summary>
        /// Handle clients
        /// </summary>
        /// <param name="ar"></param>
        private void HandleClient(TcpClient client)
        {
            try
            {
                _log.Debug($"Connection from {client.Client.RemoteEndPoint}");

                var isBound = false;
                var stream = client.GetStream();

                while (LdapPacket.TryParsePacket(stream, out var requestPacket))
                {
                    LogPacket(requestPacket);
                    _log.Debug(Utils.ByteArrayToString(requestPacket.GetBytes()));

                    if (requestPacket.ChildAttributes.Any(o => o.LdapOperation == LdapOperation.BindRequest))
                    {
                        isBound = HandleBindRequest(stream, requestPacket);
                    }

                    if (isBound)    // Only handle other requests if the client is bound, dont allow any anonymous searches
                    {
                        if (requestPacket.ChildAttributes.Any(o => o.LdapOperation == LdapOperation.SearchRequest))
                        {
                            HandleSearchRequest(stream, requestPacket);
                        }
                    }
                }

                _log.Debug($"Connection closed to {client.Client.RemoteEndPoint}");
            }
            catch (IOException ioex)
            {
                _log.Warn("oops", ioex);
            }
            
        }


        /// <summary>
        /// Handle search requests
        /// </summary>
        /// <param name="searchRequest"></param>
        /// <returns></returns>
        private void HandleSearchRequest(NetworkStream stream, LdapPacket requestPacket)
        {
            var searchRequest = requestPacket.ChildAttributes.SingleOrDefault(o => o.LdapOperation == LdapOperation.SearchRequest);
            var filter = searchRequest.ChildAttributes[6];

            if ((LdapFilterChoice)filter.ContextType == LdapFilterChoice.equalityMatch && filter.ChildAttributes[0].GetValue<String>() == "sAMAccountName" && filter.ChildAttributes[1].GetValue<String>() == "testuser") // equalityMatch
            {
                var responseEntryPacket = new LdapPacket(requestPacket.MessageId);
                var searchResultEntry = new LdapAttribute(LdapOperation.SearchResultEntry);
                searchResultEntry.ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, "cn=bindUser,cn=Users,dc=dev,dc=company,dc=com"));   //  objectName

                var partialAttributeList = new LdapAttribute(UniversalDataType.Sequence);


                var givenNameAttribute = new LdapAttribute(UniversalDataType.Sequence);
                givenNameAttribute.ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, "givenName"));
                givenNameAttribute.ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, "osefsjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjfskejfkjejkjlkjlkjlkjlkjlkjflsjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjkejflswfwefwefwefkejfslekjfslkejfslekjfsefsfsefeslekfjslekfjslekfjslekjffskje"));
                partialAttributeList.ChildAttributes.Add(givenNameAttribute);

                var partialAttributeUid = new LdapAttribute(UniversalDataType.Sequence);
                partialAttributeUid.ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, "uid"));   // type
                var partialAttributeUidValues = new LdapAttribute(UniversalDataType.Set);
                partialAttributeUidValues.ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, "useruidgoeshere"));
                partialAttributeUid.ChildAttributes.Add(partialAttributeUidValues);
                partialAttributeList.ChildAttributes.Add(partialAttributeUid);

                var partialAttributeObjectClass = new LdapAttribute(UniversalDataType.Sequence);
                partialAttributeObjectClass.ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, "objectClass"));   // type
                var partialAttributeObjectClassValues = new LdapAttribute(UniversalDataType.Set);
                partialAttributeObjectClassValues.ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, "posixAccount"));
                partialAttributeObjectClassValues.ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, "shadowAccount"));
                partialAttributeObjectClassValues.ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, "inetOrgPerson"));
                partialAttributeObjectClass.ChildAttributes.Add(partialAttributeObjectClassValues);
                partialAttributeList.ChildAttributes.Add(partialAttributeObjectClass);

                searchResultEntry.ChildAttributes.Add(partialAttributeList);
                responseEntryPacket.ChildAttributes.Add(searchResultEntry);
                var responsEntryBytes = responseEntryPacket.GetBytes();
                stream.Write(responsEntryBytes, 0, responsEntryBytes.Length);
            }

            var responseDonePacket = new LdapPacket(requestPacket.MessageId);
            responseDonePacket.ChildAttributes.Add(new LdapResultAttribute(LdapOperation.SearchResultDone, LdapResult.success));
            var responseDoneBytes = responseDonePacket.GetBytes();
            stream.Write(responseDoneBytes, 0, responseDoneBytes.Length);
        }


        /// <summary>
        /// Handle bindrequests
        /// </summary>
        /// <param name="bindrequest"></param>
        private Boolean HandleBindRequest(Stream stream, LdapPacket requestPacket)
        {
            var bindrequest = requestPacket.ChildAttributes.SingleOrDefault(o => o.LdapOperation == LdapOperation.BindRequest);
            var username = bindrequest.ChildAttributes[1].GetValue<String>();
            var password = bindrequest.ChildAttributes[2].GetValue<String>();

            var response = LdapResult.invalidCredentials;
            if (username == "cn=bindUser,cn=Users,dc=dev,dc=company,dc=com" && password == "bindUserPassword"
                || username == "cn=user,dc=example,dc=com" && password == "123")
            {
                response = LdapResult.success;
            }
            

            var responsePacket = new LdapPacket(requestPacket.MessageId);
            responsePacket.ChildAttributes.Add(new LdapResultAttribute(LdapOperation.BindResponse, response));
            var responseBytes = responsePacket.GetBytes();
            _log.Debug("response");
            var sb = new StringBuilder();
            RecurseAttributes(sb, responsePacket);
            _log.Debug(sb);
            stream.Write(responseBytes, 0, responseBytes.Length);
            return response == LdapResult.success;
        }


        /// <summary>
        /// Dump the packet to log
        /// </summary>
        /// <param name="attribute"></param>
        private void LogPacket(LdapAttribute attribute)
        {
            var sb = new StringBuilder();
            RecurseAttributes(sb, attribute);
            _log.Debug($"Packet dump\n{sb}");
        }

        private void RecurseAttributes(StringBuilder sb, LdapAttribute attribute, Int32 depth = 1)
        {
            if (attribute != null)
            {
                sb.AppendLine($"{Utils.Repeat(">", depth)} {attribute.Class}:{attribute.DataType}{attribute.LdapOperation}{attribute.ContextType} - Type: {attribute.GetValue().GetType()} - {attribute.GetValue()}");
                if (attribute.IsConstructed)
                {
                    attribute.ChildAttributes.ForEach(o => RecurseAttributes(sb, o, depth + 1));
                }
            }
        }
    }
}