using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
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
    public partial class Form3 : Form
    {
        public Form3()
        {
            InitializeComponent();
            CheckForIllegalCrossThreadCalls = false;
            Connect();
        }

        long p, g;
        long a = Random();
        long A, B;

        long Key()
        {
            long res = power(B, a, p);
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
                AddMessage("CLIENT: Send P, G");
                Send();
            }
            else if (comboBox1.Text == "Chat")
            {
                Send();
                AddMessage("CLIENT: " + textBox2.Text);
            }
            else if (comboBox1.Text == "Public Key")
            {
                AddMessage("CLIENT: Public Key");
                Send();
            }
        }

        IPEndPoint IP;
        Socket client;

        static long Random()
        {
            Random random = new Random();
            long res = random.Next(2, 300);
            return res;
        }

        void Connect()
        {
            IP = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 8080);
            client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.IP);
            try
            {
                client.Connect(IP);
            }
            catch
            {
                MessageBox.Show("Không thể kết nối server!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            Thread listen = new Thread(Receive);
            listen.IsBackground = true;
            listen.Start();
        }

        void ClientClose()
        {
            client.Close();
        }

        void Send()
        {
            if (comboBox1.Text == "Send P, G")
            {
                p = RandomPrime(20);
                g = (long)findPrimitive((int)p);
                string mess = p + " " + g;
                client.Send(Serialize(mess));
                AddMessage("CLIENT: " + mess);
            }
            if (comboBox1.Text == "Chat")
            {
                if (textBox2.Text != string.Empty)
                {
                    string message = "CLIENT: " + textBox2.Text;
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
            if (comboBox1.Text == "Public Key")
            {
                A = power(g, a, p);
                client.Send(Serialize(A.ToString()));
                AddMessage("CLIENT: " + A.ToString());
            }
        }

        void Receive()
        {
            try
            {
                while (true)
                {
                    byte[] data = new byte[1024 * 5000];
                    client.Receive(data);
                    string text = (string)Deserialize(data);
                    if (comboBox1.Text == "Chat")
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
                    if (comboBox1.Text == "Public Key")
                    {
                        AddMessage(text);
                        B = long.Parse(text);
                    }
                }
            }
            catch
            {
                ClientClose();
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

        static int power(int x, int y, int p)
        {
            int res = 1;
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

        static void findPrimefactors(HashSet<int> s, int n)
        {
            while (n % 2 == 0)
            {
                s.Add(2);
                n = n / 2;
            }
            for (int i = 3; i <= Math.Sqrt(n); i = i + 2)
            {
                while (n % i == 0)
                {
                    s.Add(i);
                    n = n / i;
                }
            }
            if (n > 2)
            {
                s.Add(n);
            }
        }

        static int findPrimitive(int n)
        {
            HashSet<int> s = new HashSet<int>();
            int phi = n - 1;
            findPrimefactors(s, phi);
            for (int r = 2; r <= phi; r++)
            {
                bool flag = false;
                foreach (int a in s)
                {
                    if (power(r, phi / (a), n) == 1)
                    {
                        flag = true;
                        break;
                    }
                }
                if (flag == false)
                {
                    return r;
                }
            }
            return -1;
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
