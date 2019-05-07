using System;
using System.Collections.Generic;
using System.Text;
using System.Net.Security;
using System.Net.Sockets;
using System.Net;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace SSLTunnel
{
	class SSLTunnelClient : SSLTunnel
	{
		private const Int32 PROXY_SERVER_BACKLOG = 5;
		private TcpClient _sslTcpClient;

		public SSLTunnelClient(string host, Int32 port, string proxyHost, Int32 proxyPort, Int32 proxyTimeOut = TEN_MINUTES_MS) : base(host, port, proxyHost, proxyPort, proxyTimeOut){}

		protected override void InitProxy() 
		{
			// Put proxy socket in listening mode.
			this._proxySocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
			this._proxySocket.Bind(new IPEndPoint(this._proxyHost, this._proxyPort));
			this._proxySocket.Listen(SSLTunnelClient.PROXY_SERVER_BACKLOG);

			Console.WriteLine("Proxy on {0}:{1} waiting for connection...", this._proxyHost.ToString(), this._proxyPort);
			this._proxySide = this._proxySocket.Accept();
		}

		protected override void InitSSL()
		{
			Console.WriteLine("Connecting to SSL Tunnel server on {0}:{1}", this._host.ToString(), this._port);
			this._sslTcpClient = new TcpClient(this._host.ToString(), this._port);
			this._sslStream = new SslStream(
				this._sslTcpClient.GetStream(), // The underlying stream,
				false, // Dont leave underlying stream open when ssl stream closes
				new RemoteCertificateValidationCallback(this.ValidateCert)// Callback for certificate validation process
				);
			Console.WriteLine("Initiating SSL");
			try
			{
				this._sslStream.AuthenticateAsClient(this._host.ToString());
			}
			catch (Exception e)
			{
				Console.WriteLine("Exception at initssl: {0}", e.ToString());
				Environment.Exit(-1);
			}
		}

		public override void Run() {
			try
			{
			this.InitProxy();

			this.InitSSL();

			this.Tunnel(this._proxySide, this._sslTcpClient.Client, this._proxyTimeOut);
			} catch (Exception e) {
				Console.WriteLine("Exception at run {0}", e.ToString());
			}
		}

		protected override void safeExit(Int32 exitCode)
		{
			Console.WriteLine("\nCalling safe exit!");
			this._proxySide.Close();
			this._proxySocket.Close();
			this._sslStream.Close();
			this._sslTcpClient.Close();
			Environment.Exit(exitCode);
		}

		private bool ValidateCert(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
		{
			// Allow untrusted certificates
			Console.WriteLine("Validating Certificate");
			return true;
		}
	}
}
