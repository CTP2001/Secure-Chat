using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Numerics;
using System.Windows.Forms;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using Rijndael256;

namespace SecureChat
{
    public partial class Form2 : Form
    {
        public Form2()
        {
            InitializeComponent();
            CheckForIllegalCrossThreadCalls = false;
            Connect();
        }

        long p, g;
        long b = Random();
        long A, B;

        static long Random()
        {
            Random random = new Random();
            long res = random.Next(2, 100);
            return res;
        }

        long Key()
        {
            long res = power(A, b, p);
            return res;
        }

        string VigenereEncrypt(string key, string plaintext)
        {
            plaintext = plaintext.ToUpper();
            string ciphertext = "";
            int c = 0;
            foreach (var s in plaintext)
            {
                if ((int)s < (int)'A' || (int)s > (int)'Z')
                {
                    ciphertext += s;
                    continue;
                }
                ciphertext += (char)(((int)s + (int)key[c] + 17 - (2 * (int)'A')) % 26 + (int)'A');
                c = (c + 1) % key.Length;
            }
            return ciphertext;
        }

        string VigenereDecrypt(string key, string ciphertext)
        {
            ciphertext = ciphertext.ToUpper();
            string plaintext = "";
            int c = 0;
            foreach (var s in ciphertext)
            {
                if ((int)s < (int)'A' || (int)s > (int)'Z')
                {
                    plaintext += s;
                    continue;
                }
                plaintext += (char)(((int)s - (int)key[c] - 17 + 26) % 26 + (int)'A');
                c = (c + 1) % key.Length;
            }
            return plaintext;
        }

        int mod(string num, int a)
        {
            int res = 0;
            for (int i = 0; i < num.Length; i++)
                res = (res * 10 + (int)num[i] - '0') % a;
            return res;
        }

        string CaesarEncrypt(long key, string plaintext)
        {
            plaintext = plaintext.ToUpper();
            string ciphertext = "";
            foreach (var s in plaintext)
            {
                if ((int)s < (int)'A' || (int)s > (int)'Z')
                {
                    ciphertext += s;
                    continue;
                }
                ciphertext += (char)(mod(((int)s - 65 + key).ToString(), 26) + 'A');
            }
            return ciphertext;
        }

        string CaesarDecrypt(long key, string ciphertext)
        {
            ciphertext = ciphertext.ToUpper();
            string plaintext = "";
            foreach (var s in ciphertext)
            {
                if ((int)s < (int)'A' || (int)s > (int)'Z')
                {
                    plaintext += s;
                    continue;
                }
                int k = mod(key.ToString(), 26);
                plaintext += (char)(mod(((int)s - 65 - k + 26).ToString(), 26) + 'A');
            }
            return plaintext;
        }

        private void button1_Click(object sender, EventArgs e)
        {
           if (comboBox1.Text == "Send P, G")
            {
                AddMessage("SERVER: Send P, G");
                Send(client);
            }
            else if (comboBox1.Text == "Chat")
            {
                Send(client);
                AddMessage("SERVER: " + textBox2.Text);
            }
            else if (comboBox1.Text == "Public Key")
            {
                AddMessage("SERVER: Public Key");
                Send(client);
            }
        }

        IPEndPoint IP;
        Socket server;
        Socket client;

        void Connect()
        {
            IP = new IPEndPoint(IPAddress.Any, 8080);
            server = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.IP);
            server.Bind(IP);
            Thread Listen = new Thread(() =>
            {
                try
                {
                    while (true)
                    {
                        server.Listen(100);
                        client = server.Accept();
                        listView1.Items.Add(new ListViewItem("New client connected"));
                        Thread receive = new Thread(Receive);
                        receive.IsBackground = true;
                        receive.Start(client);
                    }
                }
                catch
                {
                    IP = new IPEndPoint(IPAddress.Any, 8080);
                    server = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.IP);
                }
            });
            Listen.IsBackground = true;
            Listen.Start();
        }

        void ServerClose()
        {
            server.Close();
        }

        void Send(Socket client)
        {
            if (comboBox1.Text == "Chat")
            {
                if (textBox2.Text != string.Empty)
                {
                    string message = "SERVER: " + textBox2.Text;
                    if (comboBox2.Text == "AES")
                    {
                        string encrypted = Rijndael256.Rijndael.Encrypt(message, Key().ToString(), KeySize.Aes256);
                        AddMessage2(encrypted);
                        client.Send(Serialize(encrypted));
                    }
                    else if (comboBox2.Text == "Vigenere")
                    {
                        string encrypted = VigenereEncrypt(Key().ToString(), message);
                        AddMessage2(encrypted);
                        client.Send(Serialize(encrypted));
                    }
                    else if (comboBox2.Text == "Caesar")
                    {
                        string encrypted = CaesarEncrypt(Key(), message);
                        AddMessage2(encrypted);
                        client.Send(Serialize(encrypted));
                    }
                    else
                        client.Send(Serialize(message));
                }
            }
            if (comboBox1.Text == "Receive P, G")
            {
                string mess = p + " " + g;
                client.Send(Serialize(mess));
                AddMessage("SERVER: " + mess);
            }
            if (comboBox1.Text == "Public Key")
            {
                B = power(g, b, p);
                client.Send(Serialize(B.ToString()));
                AddMessage("SERVER: " + B.ToString());
            }
        }

        void Receive(object obj)
        {
            Socket client = obj as Socket;
            try
            {
                while (true)
                {
                    byte[] data = new byte[1024 * 5000];
                    client.Receive(data);
                    string text = (string)Deserialize(data);
                    if (comboBox1.Text == "Receive P, G")
                    {
                        string[] array = text.Split(' ');
                        p = long.Parse(array[0]);
                        g = long.Parse(array[1]);
                        AddMessage(text);
                    }
                    else if (comboBox1.Text == "Public Key")
                    {
                        A = long.Parse(text);
                        AddMessage(text);
                    }
                    else if (comboBox1.Text == "Chat")
                    {
                        if (comboBox2.Text == "AES")
                        {
                            string decrypted = Rijndael256.Rijndael.Decrypt(text, Key().ToString(), KeySize.Aes256);
                            AddMessage(decrypted);
                        }
                        else if (comboBox2.Text == "Vigenere")
                        {
                            string decrypted = VigenereDecrypt(Key().ToString(), text);
                            AddMessage(decrypted);
                        }
                        else if (comboBox2.Text == "Caesar")
                        {
                            string decrypted = CaesarDecrypt(Key(), text);
                            AddMessage(decrypted);
                        }
                        else
                            AddMessage(text);
                    }
                }
            }
            catch
            {
                client.Close();
            }

        }

        void AddMessage(string s)
        {
            listView1.Items.Add(new ListViewItem() { Text = s });
            textBox2.Clear();
        }

        void AddMessage2(string s)
        {
            listView2.Clear();
            listView2.Items.Add(new ListViewItem() { Text = s });
        }

        byte[] Serialize(object obj)
        {
            MemoryStream stream = new MemoryStream();
            BinaryFormatter formatter = new BinaryFormatter();
            formatter.Serialize(stream, obj);
            return stream.ToArray();
        }

        object Deserialize(byte[] data)
        {
            MemoryStream stream = new MemoryStream(data);
            BinaryFormatter formatter = new BinaryFormatter();
            return formatter.Deserialize(stream);
        }

        static long power(long x, long y, long p)
        {
            long res = 1;
            x = x % p;
            while (y > 0)
            {
                if (y % 2 == 1)
                {
                    res = (res * x) % p;
                }
                y = y >> 1;
                x = (x * x) % p;
            }
            return res;
        }

        static bool MillerRabin(long q, long n)
        {
            Random r = new Random();
            int k = (int)n - 2;
            long a = r.Next(2, k);
            long x = power(a, q, n);
            if (x == 1 || x == n - 1)
                return true;
            while (q != n - 1)
            {
                x = (x * x) % n;
                q *= 2;

                if (x == 1)
                    return false;
                if (x == n - 1)
                    return true;
            }
            return false;
        }

        static bool isPrime(long n)
        {
            if (n <= 1 || n == 4)
                return false;
            if (n <= 3)
                return true;

            long q = n - 1;
            while (q % 2 == 0)
                q /= 2;

            for (int i = 1; i <= 50; i++)
            {
                if (MillerRabin(q, n) == false)
                    return false;
            }

            return true;
        }

        static long RandomPrime(int size)
        {
            Random r = new Random();
            int a = (int)(Math.Pow(2, size - 1));
            int b = (int)(Math.Pow(2, size));
            long beg_rand = r.Next(a, b);
            if (beg_rand % 2 == 0)
                beg_rand += 1;

            for (long possiblePrime = beg_rand; possiblePrime <= b; possiblePrime++)
            {
                if (isPrime(possiblePrime))
                {
                    return possiblePrime;
                }
            }
            return 0;
        }
    }
}
