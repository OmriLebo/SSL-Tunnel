using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Collections;
using System.IO;

namespace SSLTunnel
{
	public abstract class SSLTunnel 
	{
		protected IPAddress _host;
		protected Int32 _port;

		protected SslStream _sslStream;

		protected Socket _proxySocket;
		protected Socket _proxySide;
		protected Int32 _proxyTimeOut;
		
		protected IPAddress _proxyHost;
		protected Int32 _proxyPort;		

		private const int MAX_READ_LENGTH = 2048;
		protected const int MICRO_SECOND = 1000000;
		protected const int MICRO_MINUTE = 60 * MICRO_SECOND;
		protected const int TEN_MINUTES_MS = 10 * MICRO_MINUTE;
		private const int INFINITE_TIMEOUT = -1;
		private static readonly byte[] MAGIC_HEADER = new byte[5] {0x2A, 0x7F, 0x53, 0x54, 0x4D}; // 0x2A-0x7F-STM (SSL Tunnel Message)

		protected SSLTunnel(string host, Int32 port, string proxyHost, Int32 proxyPort, Int32 proxyTimeOut)
		{
			this._host = IPAddress.Parse(host);
			this._port = port;
			this._proxyHost = IPAddress.Parse(proxyHost);
			this._proxyPort = proxyPort;
			this._proxyTimeOut = proxyTimeOut * MICRO_SECOND;
			this._sslStream = null;
			this._proxySocket = null;
			this._proxySide = null;
		}

		public abstract void Run();

		// For situations of error exit safely
		protected abstract void safeExit(Int32 exitCode);

		// Initiating the proxy socket
		protected abstract void InitProxy();

		// Initiating the SSL tunnel
		protected abstract void InitSSL();

		private static bool isValidHeader(byte[] header) {
			if(header.Length != MAGIC_HEADER.Length)
				return false;
			for (int i = 0; i < MAGIC_HEADER.Length; i++) {
				if (header[i] != MAGIC_HEADER[i]) {
					return false;
				}
			}
			return true;
		}

		protected byte[] ReadMessage()
		{
			/*	Read a message from the SslStream

				Message format:
				[:5] : MAGIC_HEADER
				[5:9] : MESSAGE LENGTH
				[:MESSAGE LENGTH] : MESSAGE

				|   |   |   |   |   |   |   |   |   |  
				-------------------------------------
				|   MAGIC HEADER    | MESSAGE LENGTH|
				-------------------------------------
				|               MESSAGE             |
				-------------------------------------
			*/
			try
			{
				byte[] tempArray = new byte[MAX_READ_LENGTH];
				byte[] messageHeader = new byte[MAGIC_HEADER.Length];
				byte[] messageLengthByteArray = new byte[4];
				Int32 messageLength;
				Int32 bytesRead = 0;
				Int32 bytesReadInSession = 0;

				// Read and validate message-header
				do {
					bytesRead = this._sslStream.Read(tempArray, 0, MAGIC_HEADER.Length - bytesReadInSession);
					if (bytesRead == 0)
					{
						// 0 bytes read, something went wrong, abort.
						safeExit(-1);
					}
					Array.Copy(tempArray, 0, messageHeader, bytesReadInSession, MAGIC_HEADER.Length - bytesReadInSession);
					bytesReadInSession += bytesRead;
				} while (bytesReadInSession < MAGIC_HEADER.Length);

				if (! isValidHeader(messageHeader))
					return null;

				// Read message length
				do {
					bytesRead = this._sslStream.Read(tempArray, 0, 4 - ((bytesReadInSession - MAGIC_HEADER.Length)));
					Array.Copy(tempArray, 0, messageLengthByteArray, (bytesReadInSession - MAGIC_HEADER.Length), 4 - (bytesReadInSession - MAGIC_HEADER.Length));
					bytesReadInSession += bytesRead;
				} while ((bytesReadInSession - MAGIC_HEADER.Length) < 4);

				messageLength = BitConverter.ToInt32(messageLengthByteArray, 0);
				byte[] message = new byte[messageLength];

				// Read message itself
				do {
					bytesRead = this._sslStream.Read(tempArray, 0, messageLength - ((bytesReadInSession - MAGIC_HEADER.Length - 4)));
					Array.Copy(tempArray, 0, message, (bytesReadInSession - MAGIC_HEADER.Length - 4),
						messageLength - (bytesReadInSession - MAGIC_HEADER.Length - 4));
					bytesReadInSession += bytesRead;
				} while ((bytesReadInSession - MAGIC_HEADER.Length - 4) < messageLength);
				
				return message;
			}
			catch (Exception e)
			{
				Console.WriteLine("Exception: at readmessage{0}", e.ToString());
				Environment.Exit(-1);
				return null;
			}
		}

		protected void SendMessage(byte[] message)
		{
			try
			{
				// Get message length
				byte[] messageLengthByteArray = BitConverter.GetBytes((Int32)(message.Length));

				// Wrap message with message header and message length
				byte[] validMessage = new byte[MAGIC_HEADER.Length + 4 + message.Length];
				// Append message header
				Array.Copy(MAGIC_HEADER, 0, validMessage, 0, MAGIC_HEADER.Length);

				// Append true message length
				Array.Copy(messageLengthByteArray, 0, validMessage, MAGIC_HEADER.Length, messageLengthByteArray.Length);

				// Append true message
				Array.Copy(message, 0, validMessage, MAGIC_HEADER.Length + messageLengthByteArray.Length, message.Length);

				// Write and flush to stream
				this._sslStream.Write(validMessage);
				this._sslStream.Flush();
			}
			catch (Exception e)
			{
				Console.WriteLine("Exception at sendmessage: {0}", e.ToString());
				Environment.Exit(-1);
			}
		}

		// Generic method for passing data between the two endpoints
		protected void Tunnel(Socket insecureEndPoint, Socket secureEndpoint, Int32 msTimeout) {
			Console.WriteLine("Tunneling Data");
			Int32 bytesRead = 0;
			Int32 packetsTunneled = 0;
			while (insecureEndPoint.Connected && secureEndpoint.Connected) {
				try {
					ArrayList readList = new ArrayList();
					readList.Add(insecureEndPoint);
					readList.Add(secureEndpoint);
					Console.Write("\rPackets tunneled: {0}", packetsTunneled);
					Socket.Select(readList, null, null, msTimeout);
					/*	Checking for secure-endpoint readability first
						due to the fact that the insecure-endpoint initiates the connection.						
					*/

					// Message from secure-endpoint
					if (readList.Contains(secureEndpoint)) {
						byte[] message = this.ReadMessage();
						// Pass data to insecure-endpoint
						if (message != null) {
							insecureEndPoint.Send(message);
							packetsTunneled++;
						}
							
					}
					// Message from insecure-endpoint
					else if (readList.Contains(insecureEndPoint)) {
						byte[] inData = new Byte[MAX_READ_LENGTH];
						bytesRead = insecureEndPoint.Receive(inData, 0, MAX_READ_LENGTH, SocketFlags.None);
						// Pass data to secure-endpoint
						Array.Resize(ref inData, bytesRead);
						if (bytesRead == 0)
							safeExit(-1);
						this.SendMessage(inData);
						packetsTunneled++;
					}
					else {
						safeExit(0);
					}				
				} catch (Exception e) {
					Console.WriteLine("Tunnel failed with error {0}", e.ToString());
					safeExit(-1);
				}
			}
		} 
	}
}