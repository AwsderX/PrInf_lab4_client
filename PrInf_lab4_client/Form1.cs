using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace PrInf_lab4_client
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs eventArg)
        {
            BigInteger message = 555;
            // ��������� ��������� �����
            string privateKeyPath = $"privatekey.pem";
            string publicKeyPath = $"publickey.pem";
            string privateKeyCommand = $"genpkey -algorithm RSA -out {privateKeyPath} -pkeyopt rsa_keygen_bits:1024";
            ExecuteOpenSSLCommand(privateKeyCommand);

            // ���������� ��������� ����� �� ���������
            string publicKeyCommand = $"rsa -pubout -in {privateKeyPath} -out {publicKeyPath}";
            ExecuteOpenSSLCommand(publicKeyCommand);

            string privateKeyOutput = ExecuteOpenSSLCommand($"rsa -in {privateKeyPath} -noout -text");
            string publicKeyOutput = ExecuteOpenSSLCommand($"rsa -pubin -in {publicKeyPath} -noout -text");
            BigInteger e, n, d;
            ExtractExponents(privateKeyOutput, publicKeyOutput, out e, out n, out d);
            //ExtractExponents(publicKeyOutput, out e, out n);

            //// ������ ��������� ����� �� �����
            //string publicKeyContents = File.ReadAllText(publicKeyPath);
            //// ������� ��������� ����� � PEM �������
            //PemReader reader = new PemReader(new StringReader(publicKeyContents));
            //RsaKeyParameters publicKeyParams = (RsaKeyParameters)reader.ReadObject();
            //// ���������� �������� e (�������� ����������)
            //BigInteger e = new BigInteger(publicKeyParams.Exponent.ToByteArrayUnsigned());
            //textBox1.Text += "���������� = " + e.ToString() + Environment.NewLine;
            //// ���������� �������� n (������)
            //BigInteger n = new BigInteger(publicKeyParams.Modulus.ToByteArrayUnsigned());
            //textBox1.Text += "������ = " + n.ToString() + Environment.NewLine;

            // ��������� ���������� ������������ ��������� (blinding factor)
            Random random = new Random();
            BigInteger r = GenerateRandomBigInteger(random, BigInteger.One, n - BigInteger.One);

            // ��������� ���������� ������������ ���������
            //BigInteger r = 200;
            // ��������� ��������� �� ����������� ���������
            BigInteger blindedMessage = message * r % n;
            textBox1.Text += "��������� ��������� = " + blindedMessage + Environment.NewLine;

            // ������ ��������� ����� �� �����
            string privateKeyContents = File.ReadAllText(privateKeyPath);
            // ������� ��������� ����� � PEM �������
            PemReader reader2 = new PemReader(new StringReader(privateKeyContents));
            RsaPrivateCrtKeyParameters privateKeyParams = (RsaPrivateCrtKeyParameters)reader2.ReadObject();
            // ���������� �������� d (�������� ����������)
            BigInteger privateKey_d = new BigInteger(privateKeyParams.Exponent.ToByteArrayUnsigned());
            // ���������� ���������� ���������
            BigInteger blindedSignature = ModPow(blindedMessage, privateKey_d, n);
            textBox1.Text += "����������� ��������� = " + blindedSignature + Environment.NewLine;

            // �������� ������������ ���������
            BigInteger unblindedSignature = ModInverse(r, n) * blindedSignature % n;
            textBox1.Text += "��������� ��������� = " + unblindedSignature + Environment.NewLine;

            // ���������� ��������� � ������� � �����
            string messageFilePath = "message.txt";
            File.WriteAllText(messageFilePath, message.ToString());
            string signatureFilePath = "signature.bin";
            File.WriteAllBytes(signatureFilePath, unblindedSignature.ToByteArray());

            // �������� ������� � �������������� OpenSSL
            string opensslCommand = $"dgst -sha256 -verify {publicKeyPath} -signature {signatureFilePath} {messageFilePath}";
            textBox1.Text += ExecuteOpenSSLCommand(opensslCommand);

        }
        private BigInteger GenerateRandomBigInteger(Random random, BigInteger minValue, BigInteger maxValue)
        {
            int maxBytes = Math.Max(minValue.ToByteArray().Length, maxValue.ToByteArray().Length);
            byte[] randomBytes = new byte[maxBytes];
            BigInteger result;

            do
            {
                random.NextBytes(randomBytes);
                randomBytes[randomBytes.Length - 1] &= 0x7F;  // Ensure positive value
                result = new BigInteger(randomBytes);
            }
            while (result <= minValue || result >= maxValue);

            return result;
        }
        private void ExtractExponents(string output, string output1, out BigInteger e, out BigInteger n, out BigInteger d)
        {
            e = n = d = default;

            for (int i = 0; i < 2; i++)
            {
                string pattern = @"modulus:\s+([\s\S]+?)publicExponent:";
                Match match = Regex.Match(output, pattern);
                if (match.Success)
                {
                    string value = match.Groups[1].Value.Replace(":", "").Replace(" ", "").Replace(Environment.NewLine, "");
                    n = BigInteger.Parse(value, System.Globalization.NumberStyles.HexNumber);
                }

                pattern = @"publicExponent:\s+([\s\S]+?)privateExponent:";
                match = Regex.Match(output, pattern);
                if (match.Success)
                {
                    string value = match.Groups[1].Value.Replace(":", "").Replace(" ", "").Replace(Environment.NewLine, "").Replace("(0x10001)", "");
                    e = BigInteger.Parse(value, System.Globalization.NumberStyles.HexNumber);
                }

                pattern = @"privateExponent:\s+([\s\S]+?)prime1:";
                match = Regex.Match(output, pattern);
                if (match.Success)
                {
                    string value = match.Groups[1].Value.Replace(":", "").Replace(" ", "").Replace(Environment.NewLine, "");
                    d = BigInteger.Parse(value, System.Globalization.NumberStyles.HexNumber);
                }
                output = output1;
            }
        }
        //private void ExtractExponents(string output, out BigInteger e, out BigInteger n)
        //{
        //    string pattern = @"modulus:\s+([\s\S]+?)publicExponent:";
        //    Match match = Regex.Match(output, pattern);
        //    if (match.Success)
        //    {
        //        string value = match.Groups[1].Value.Replace(":", "").Replace(" ", "").Replace(Environment.NewLine, "");
        //        n = BigInteger.Parse(value, System.Globalization.NumberStyles.HexNumber);
        //    }

        //    pattern = @"publicExponent:\s+([\s\S]+?)privateExponent:";
        //    match = Regex.Match(output, pattern);
        //    if (match.Success)
        //    {
        //        string value = match.Groups[1].Value.Replace(":", "").Replace(" ", "").Replace(Environment.NewLine, "");
        //        e = BigInteger.Parse(value, System.Globalization.NumberStyles.HexNumber);
        //    }
        //}
        private BigInteger ModPow(BigInteger baseValue, BigInteger exponent, BigInteger modulus)
        {
            BigInteger result = 1;
            while (exponent > 0)
            {
                if (exponent % 2 == 1)
                    result = (result * baseValue) % modulus;
                baseValue = (baseValue * baseValue) % modulus;
                exponent /= 2;
            }
            return result;
        }

        private string ExecuteOpenSSLCommand(string arguments)
        {
            string command = "openssl";
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = command;
            startInfo.Arguments = arguments;
            startInfo.RedirectStandardOutput = true;

            Process process = new Process();
            process.StartInfo = startInfo;
            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(); // Wait for the process to finish
            return output;
        }

        public BigInteger ModInverse(BigInteger a, BigInteger n)
        {
            BigInteger m0 = n;
            BigInteger y = 0, x = 1;

            if (n == 1)
                return 0;

            while (a > 1)
            {
                BigInteger q = a / n;
                BigInteger t = n;

                n = a % n;
                a = t;
                t = y;

                y = x - q * y;
                x = t;
            }

            if (x < 0)
                x += m0;

            return x;
        }

    }
}