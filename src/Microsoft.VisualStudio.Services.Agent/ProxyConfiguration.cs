using Microsoft.VisualStudio.Services.Agent.Util;
using Microsoft.VisualStudio.Services.Common;
using System;
using System.Linq;
using System.Net;
using System.IO;

namespace Microsoft.VisualStudio.Services.Agent
{
    [ServiceLocator(Default = typeof(ProxyConfiguration))]
    public interface IProxyConfiguration : IAgentService
    {
        String ProxyUrl { get; }
        void ApplyProxySettings();
    }

    public class ProxyConfiguration : AgentService, IProxyConfiguration
    {
        private bool _proxySettingsApplied = false;

        public String ProxyUrl { get; private set; }

        public void ApplyProxySettings()
        {
            Trace.Entering();
            if (_proxySettingsApplied)
            {
                return;
            }

            string proxyConfigFile = IOUtil.GetProxyConfigFilePath();
            if (File.Exists(proxyConfigFile))
            {
                // we expect the first line of the file is the proxy url
                Trace.Verbose($"Try read proxy setting from file: {proxyConfigFile}.");
                ProxyUrl = File.ReadLines(proxyConfigFile).FirstOrDefault();
                if (!Uri.IsWellFormedUriString(ProxyUrl, UriKind.Absolute))
                {
                    Trace.Info($"UrlString read from proxy setting file is not a well formed absolute uri string: {ProxyUrl}.");
                    ProxyUrl = string.Empty;
                }
            }

            if (string.IsNullOrEmpty(ProxyUrl))
            {
                Trace.Verbose("Try read proxy setting from environment variable: 'VSTS_HTTP_PROXY'.");
                ProxyUrl = Environment.GetEnvironmentVariable("VSTS_HTTP_PROXY");
            }

            if (!string.IsNullOrEmpty(ProxyUrl))
            {
                Trace.Info($"Config proxy at: {ProxyUrl}.");

                string username = Environment.GetEnvironmentVariable("VSTS_HTTP_PROXY_USERNAME");
                string password = Environment.GetEnvironmentVariable("VSTS_HTTP_PROXY_PASSWORD");

                if (!string.IsNullOrEmpty(password))
                {
                    var secretMasker = HostContext.GetService<ISecretMasker>();
                    secretMasker.AddValue(password);
                }

                ICredentials cred = null;
                if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
                {
                    Trace.Info($"Config proxy use DefaultNetworkCredentials.");
                    cred = CredentialCache.DefaultNetworkCredentials;
                }
                else
                {
                    Trace.Info($"Config authentication proxy as: {username}.");
                    cred = new NetworkCredential(username, password);
                }

                VssHttpMessageHandler.DefaultWebProxy = new WebProxy(new Uri(ProxyUrl))
                {
                    Credentials = cred
                };

                _proxySettingsApplied = true;
            }
            else
            {
                Trace.Info($"No proxy setting found.");
            }
        }
    }

    public class WebProxy : IWebProxy
    {
        public WebProxy(Uri proxyAddress)
        {
            if (proxyAddress == null)
            {
                throw new ArgumentNullException(nameof(proxyAddress));
            }

            ProxyAddress = proxyAddress;
        }

        public Uri ProxyAddress { get; private set; }

        public ICredentials Credentials { get; set; }

        public Uri GetProxy(Uri destination) => ProxyAddress;

        public bool IsBypassed(Uri uri)
        {
            return uri.IsLoopback;
        }
    }
}
