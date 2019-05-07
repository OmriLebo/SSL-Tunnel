using System;
using System.Collections.Generic;
using System.Text;
using System.Net.Sockets;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using System.Security.Authentication;

namespace SSLTunnel
{
	class SSLTunnelServer : SSLTunnel
	{

		private X509Certificate2 _certificate;
		private TcpClient _sslTcpClient;
		private TcpListener _sslTcpListener;

		public SSLTunnelServer(string host, Int32 port, string proxyHost, Int32 proxyPort, string certFile, string certPassword, Int32 proxyTimeOut = TEN_MINUTES_MS)
		: base(host, port, proxyHost, proxyPort, proxyTimeOut)
		{
			this._certificate = new X509Certificate2(certFile, certPassword);
			this._sslTcpClient = null;
			Console.WriteLine("Created SSLTunnelServer!");
		}

		protected override void InitProxy() {
			this._proxySocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
			this._proxySocket.Connect(this._proxyHost, this._proxyPort);
		}

		protected override void InitSSL() {
			this._sslTcpListener = new TcpListener(this._host, this._port);
			this._sslTcpListener.Start();
			Console.WriteLine("Waiting for a client to connect...");
			this._sslTcpClient = this._sslTcpListener.AcceptTcpClient();
			Console.WriteLine("Connection Received!");
			this.wrapNewConnection();
		}

		public override void Run()
		{
			Console.WriteLine("Running Server");
			try {
				// Initiate wrapping SSL stream
				this.InitSSL();

				// Initiate proxy
				this.InitProxy();

				// Tunnel data
				this.Tunnel(this._proxySocket, this._sslTcpClient.Client, this._proxyTimeOut);
			} catch (Exception e) {
				Console.WriteLine("Exception at run {0}", e.ToString());
			}
		}

		protected override void safeExit(Int32 exitCode)
		{
			Console.WriteLine("\nCalling safe exit!");
			this._sslStream.Close();
			this._sslTcpClient.Close();
			this._sslTcpListener.Stop();
			this._proxySocket.Close();
			Environment.Exit(exitCode);
		}

		private void wrapNewConnection() {
			this._sslStream = new SslStream(
				this._sslTcpClient.GetStream(), false);
			this._sslStream.AuthenticateAsServer(this._certificate);
		}

	}
}
