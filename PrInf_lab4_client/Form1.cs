using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
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

            // ������ ��������� ����� �� �����
            string publicKeyContents = File.ReadAllText(publicKeyPath);
            // ������� ��������� ����� � PEM �������
            PemReader reader = new PemReader(new StringReader(publicKeyContents));
            RsaKeyParameters publicKeyParams = (RsaKeyParameters)reader.ReadObject();
            // ���������� �������� e (�������� ����������)
            BigInteger e = new BigInteger(publicKeyParams.Exponent.ToByteArrayUnsigned());
            textBox1.Text += "���������� = " + e.ToString() + Environment.NewLine;
            // ���������� �������� n (������)
            BigInteger n = new BigInteger(publicKeyParams.Modulus.ToByteArrayUnsigned());
            textBox1.Text += "������ = " + n.ToString() + Environment.NewLine;

            // ��������� ���������� ������������ ���������
            BigInteger r = GenerateBlindingFactor(n);
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
            ExecuteOpenSSLCommand(opensslCommand);

        }
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

        private void ExecuteOpenSSLCommand(string arguments)
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
            textBox1.Text += output + Environment.NewLine;
            process.WaitForExit();
        }

        public BigInteger GenerateBlindingFactor(BigInteger n)
        {
            BigInteger r;

            do
            {
                r = GenerateRandomNumber(n); // ��������� ���������� ����� � ��������� �� 1 �� n-1
            } while (!IsCoprime(r, n)); // �������� �� �������� �������� ����� r � n

            return r;
        }

        public bool IsCoprime(BigInteger a, BigInteger b)
        {
            BigInteger gcd = BigInteger.GreatestCommonDivisor(a, b);

            return gcd.Equals(BigInteger.One);
        }

        public BigInteger GenerateRandomNumber(BigInteger n)
        {
            byte[] bytes = n.ToByteArray();
            BigInteger randomNumber;

            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                do
                {
                    rng.GetBytes(bytes);
                    randomNumber = new BigInteger(bytes);
                } while (randomNumber >= n);
            }

            return randomNumber;
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