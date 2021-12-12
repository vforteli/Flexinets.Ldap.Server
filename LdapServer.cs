using Flexinets.Ldap.Core;
using Microsoft.Extensions.Logging;
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
        private readonly TcpListener _server;
        private readonly ILogger<LdapServer> _logger;


        /// <summary>
        /// Create a new server on endpoint
        /// </summary>
        /// <param name="localEndpoint"></param>
        public LdapServer(IPEndPoint localEndpoint, ILogger<LdapServer> logger)
        {
            _server = new TcpListener(localEndpoint);
            _logger = logger;
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
                    _logger.LogCritical("Something went wrong accepting client", ex);
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
                _logger.LogCritical($"Connection from {client.Client.RemoteEndPoint}");

                var isBound = false;
                var stream = client.GetStream();

                while (LdapPacket.TryParsePacket(stream, out var requestPacket))
                {
                    LogPacket(requestPacket);

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

                _logger.LogDebug($"Connection closed to {client.Client.RemoteEndPoint}");
            }
            catch (IOException ioex)
            {
                _logger.LogWarning("oops", ioex);
            }
            catch (Exception ex)
            {
                _logger.LogError("Something went wrong", ex);
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
                searchResultEntry.ChildAttributes.Add(new LdapAttribute(UniversalDataType.OctetString, "cn=testuser,cn=Users,dc=dev,dc=company,dc=com"));
                searchResultEntry.ChildAttributes.Add(new LdapAttribute(UniversalDataType.Sequence));
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
            _logger.LogDebug($"Packet dump\n{sb}");
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