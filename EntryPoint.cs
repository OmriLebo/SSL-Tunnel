/*
	SSL tunneling for any TCP/IP connection

	Author:	Omri Leybovich
*/

using System;
using System.Collections.Generic;
using System.Text;

namespace SSLTunnel
{
	class EntryClass
	{
		private const string CLIENT_ARG = "-c";
		private const string SERVER_ARG = "-s";
		private const string LISTEN_ARG = "-l";
		private const string HOST_ARG = "-i";
		private const string PORT_ARG = "-p";
		private const string PROXY_HOST_ARG = "-m";
		private const string PROXY_PORT_ARG = "-d";
		private const string CERT_PATH_ARG = "-pkcs";
		private const string CERT_PASSWORD_ARG = "-pkcspass";
		private const string PROXY_TIMEOUT_ARG = "--timeout";
		private const string UNIX_HELP_ARG = "-h";
		private const string WINDOWS_HELP_ARG = "/?";

		private const string HELP_MESSAGE =
@"Usage: SSLTunnel [-c/-s] -h <HOST> -p <PORT>
-c : client mode
-s : server mode
-i : host to ssl listen/connect
-p : port to ssl listen/connect 
-m : host to proxy listen/connect
-d : port to proxy listen/connect
-pkcs : path to certificate (PKCS#12 Format File)
-pkcspass : password for the PKCS#12
--timeout : proxy listen timeout in seconds (defaults to 10 minutes)";

		public static void Main(string[] args)
		{
			if (!validateArguments(args))
			{
				exitWithHelp();
			}

			// Client mode
			if (Array.IndexOf(args, CLIENT_ARG) > -1)
			{
				Int32 connectPort;
				Int32 proxyPort;
				SSLTunnelClient sslTunnelClient = null;
				string connectHost = args[Array.IndexOf(args, HOST_ARG) + 1];
				string proxyHost = args[Array.IndexOf(args, PROXY_HOST_ARG) + 1];
				Int32.TryParse(args[Array.IndexOf(args, PROXY_PORT_ARG) + 1], out proxyPort);
				Int32.TryParse(args[Array.IndexOf(args, PORT_ARG) + 1], out connectPort);
				
				if (arrayContains(args, PROXY_TIMEOUT_ARG)) {
					Int32 proxyTimeout;
					Int32.TryParse(args[Array.IndexOf(args, PROXY_TIMEOUT_ARG) + 1], out proxyTimeout);

					sslTunnelClient = new SSLTunnelClient(
						connectHost,
						connectPort,
						proxyHost,
						proxyPort,
						proxyTimeout);
				
				} else {
					sslTunnelClient = new SSLTunnelClient(
					connectHost,
					connectPort,
					proxyHost,
					proxyPort);	
				}
				try
				{
					sslTunnelClient.Run();
				}
				catch (Exception e)
				{
					Console.WriteLine("Exception at EntryPoint.cs client run: {0}", e.ToString());
				}
			}

			// Server mode
			else if (Array.IndexOf(args, SERVER_ARG) > -1)
			{
				Int32 connectPort;
				Int32 proxyPort;
				SSLTunnelServer sslTunnelServer = null;
				string connectHost = args[Array.IndexOf(args, HOST_ARG) + 1];
				string certificatePath = args[Array.IndexOf(args, CERT_PATH_ARG) + 1];
				string certPassword = args[Array.IndexOf(args, CERT_PASSWORD_ARG) + 1];
				string proxyHost = args[Array.IndexOf(args, PROXY_HOST_ARG) + 1];
				Int32.TryParse(args[Array.IndexOf(args, PROXY_PORT_ARG) + 1], out proxyPort);
				Int32.TryParse(args[Array.IndexOf(args, PORT_ARG) + 1], out connectPort);

				if (arrayContains(args, PROXY_TIMEOUT_ARG)) {
					Int32 proxyTimeout;
					Int32.TryParse(args[Array.IndexOf(args, PROXY_TIMEOUT_ARG) + 1], out proxyTimeout);

					sslTunnelServer = new SSLTunnelServer(
						connectHost,
						connectPort,
						proxyHost,
						proxyPort,
						certificatePath,
						certPassword,
						proxyTimeout
						);
				} else {
					sslTunnelServer = new SSLTunnelServer(
					connectHost,
					connectPort,
					proxyHost,
					proxyPort,
					certificatePath,
					certPassword);
				}
				try
				{
					sslTunnelServer.Run();
				}
				catch (Exception e)
				{
					Console.WriteLine("Exception at entrypoint.cs server run: {0}", e.ToString());
				}
				
			}
		}

		private static bool validateArguments(string[] arguments)
		{
			if (
				arrayContains(arguments, CLIENT_ARG) && !arrayContains(arguments, SERVER_ARG)
				&& arrayContains(arguments, HOST_ARG) && arrayContains(arguments, PORT_ARG)
				&& arrayContains(arguments, PROXY_HOST_ARG) && arrayContains(arguments, PROXY_PORT_ARG))
				{
					return true;
				}
			else if (
				arrayContains(arguments, SERVER_ARG) && !arrayContains(arguments, CLIENT_ARG)
			 	&& arrayContains(arguments, HOST_ARG) && arrayContains(arguments, PORT_ARG)
				&& arrayContains(arguments, CERT_PATH_ARG) && arrayContains(arguments, CERT_PASSWORD_ARG))
				{
					return true;
				}
				return false;
			}

		private static void exitWithHelp()
		{
			Console.WriteLine(HELP_MESSAGE);
			System.Environment.Exit(-1);
		}

		private static bool arrayContains<T>(T[] array, T arg)
		{
			return (Array.IndexOf(array, arg) > -1);
		}
	}
}
