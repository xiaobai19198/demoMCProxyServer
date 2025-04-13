using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Security;

namespace SimpleMCProxyServer
{
    class Program
    {
        // 监听端口
        private const int PORT = 25565;
        
        static void Main(string[] args)
        {
            Console.WriteLine("简易Minecraft代理服务器 - ServerID提取器");
            Console.WriteLine("监听端口: " + PORT);
            Console.WriteLine("按Ctrl+C停止服务器");
            Console.WriteLine();
            
            // 创建TCP监听器
            TcpListener server = new TcpListener(IPAddress.Any, PORT);
            
            try
            {
                // 启动服务器
                server.Start();
                Console.WriteLine("服务器已启动，等待连接...");
                
                while (true)
                {
                    // 接受客户端连接
                    TcpClient client = server.AcceptTcpClient();
                    Console.WriteLine("客户端已连接: " + ((IPEndPoint)client.Client.RemoteEndPoint).Address);
                    
                    // 为每个客户端创建一个新线程
                    new Thread(() => HandleClient(client)).Start();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("服务器错误: " + ex.Message);
            }
            finally
            {
                // 停止服务器
                server.Stop();
            }
        }
        
        static void HandleClient(TcpClient client)
        {
            try
            {
                using (NetworkStream stream = client.GetStream())
                {
                    // 读取数据
                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    
                    while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        // 处理接收到的数据
                        ProcessPacket(buffer, bytesRead);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("客户端处理错误: " + ex.Message);
            }
            finally
            {
                // 关闭客户端连接
                client.Close();
                Console.WriteLine("客户端连接已关闭");
            }
        }
        
        static void ProcessPacket(byte[] data, int length)
        {
            try
            {
                // 检查数据是否足够长
                if (length < 5) return;
                
                using (MemoryStream ms = new MemoryStream(data, 0, length))
                using (BinaryReader reader = new BinaryReader(ms))
                {
                    // 读取数据包长度
                    int packetLength = ReadVarInt(reader);
                    
                    // 读取数据包ID
                    int packetId = ReadVarInt(reader);
                    
                    // 检查是否是握手包 (ID 0x00)
                    if (packetId == 0x00)
                    {
                        // 读取协议版本
                        int protocolVersion = ReadVarInt(reader);
                        
                        // 读取服务器地址
                        string serverAddress = ReadString(reader);
                        
                        // 读取服务器端口
                        ushort serverPort = reader.ReadUInt16();
                        
                        // 读取下一个状态
                        int nextState = ReadVarInt(reader);
                        
                        Console.WriteLine($"握手包: 协议版本={protocolVersion}, 服务器={serverAddress}:{serverPort}, 下一状态={nextState}");
                    }
                    // 检查是否是加密请求包 (ID 0x01, 登录状态)
                    else if (packetId == 0x01)
                    {
                        // 读取服务器ID
                        string serverId = ReadString(reader);
                        
                        // 读取公钥长度
                        int publicKeyLength = ReadVarInt(reader);
                        
                        // 读取公钥
                        byte[] publicKey = reader.ReadBytes(publicKeyLength);
                        
                        // 读取验证令牌长度
                        int verifyTokenLength = ReadVarInt(reader);
                        
                        // 读取验证令牌
                        byte[] verifyToken = reader.ReadBytes(verifyTokenLength);
                        
                        Console.WriteLine("检测到加密请求包");
                        
                        // 提取ServerID
                        string extractedServerId = ExtractServerId(serverId, publicKey);
                        Console.WriteLine($"提取的ServerID: {extractedServerId}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("数据包处理错误: " + ex.Message);
            }
        }
        
        // 从加密请求中提取ServerID
        static string ExtractServerId(string hashServerID, byte[] publicKeyData)
        {
            try
            {
                // 生成AES密钥
                var keyGenerator = new CipherKeyGenerator();
                keyGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 128));
                var aesKey = keyGenerator.GenerateKey();

                // 计算ServerID
                string serverID;
                using (var sha1 = SHA1.Create())
                using (var memStream = new MemoryStream(20))
                {
                    var tempBytes = Encoding.GetEncoding("ISO-8859-1").GetBytes(hashServerID);
                    memStream.Write(tempBytes, 0, tempBytes.Length);
                    memStream.Write(aesKey, 0, aesKey.Length);
                    memStream.Write(publicKeyData, 0, publicKeyData.Length);

                    memStream.Position = 0;
                    var hashBytes = sha1.ComputeHash(memStream);
                    Array.Reverse(hashBytes);
                    var b = new BigInteger(hashBytes);
                    if (b < 0)
                        serverID = $"-{(-b).ToString("x").TrimStart('0')}";
                    else
                        serverID = b.ToString("x").TrimStart('0');
                }
                
                return serverID;
            }
            catch (Exception ex)
            {
                Console.WriteLine("ServerID提取错误: " + ex.Message);
                return "提取失败";
            }
        }
        
        // 读取VarInt
        static int ReadVarInt(BinaryReader reader)
        {
            int value = 0;
            int position = 0;
            byte currentByte;

            while (true)
            {
                currentByte = reader.ReadByte();
                value |= (currentByte & 0x7F) << position;

                if ((currentByte & 0x80) == 0) break;

                position += 7;

                if (position >= 32) throw new Exception("VarInt太大");
            }

            return value;
        }
        
        // 读取字符串
        static string ReadString(BinaryReader reader)
        {
            int length = ReadVarInt(reader);
            byte[] bytes = reader.ReadBytes(length);
            return Encoding.UTF8.GetString(bytes);
        }
    }
}
