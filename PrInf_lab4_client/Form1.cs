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
            // Генерация закрытого ключа
            string privateKeyPath = $"privatekey.pem";
            string publicKeyPath = $"publickey.pem";
            string privateKeyCommand = $"genpkey -algorithm RSA -out {privateKeyPath} -pkeyopt rsa_keygen_bits:1024";
            ExecuteOpenSSLCommand(privateKeyCommand);

            // Извлечение открытого ключа из закрытого
            string publicKeyCommand = $"rsa -pubout -in {privateKeyPath} -out {publicKeyPath}";
            ExecuteOpenSSLCommand(publicKeyCommand);

            // Чтение открытого ключа из файла
            string publicKeyContents = File.ReadAllText(publicKeyPath);
            // Парсинг открытого ключа в PEM формате
            PemReader reader = new PemReader(new StringReader(publicKeyContents));
            RsaKeyParameters publicKeyParams = (RsaKeyParameters)reader.ReadObject();
            // Извлечение значения e (открытая экспонента)
            BigInteger e = new BigInteger(publicKeyParams.Exponent.ToByteArrayUnsigned());
            textBox1.Text += "Экспонента = " + e.ToString() + Environment.NewLine;
            // Извлечение значения n (модуль)
            BigInteger n = new BigInteger(publicKeyParams.Modulus.ToByteArrayUnsigned());
            textBox1.Text += "Модуль = " + n.ToString() + Environment.NewLine;

            // Генерация случайного затемняющего множителя
            BigInteger r = GenerateBlindingFactor(n);
            // Умножение сообщения на затемняющий множитель
            BigInteger blindedMessage = message * r % n;
            textBox1.Text += "Склеенное сообщение = " + blindedMessage + Environment.NewLine;

            // Чтение закрытого ключа из файла
            string privateKeyContents = File.ReadAllText(privateKeyPath);
            // Парсинг закрытого ключа в PEM формате
            PemReader reader2 = new PemReader(new StringReader(privateKeyContents));
            RsaPrivateCrtKeyParameters privateKeyParams = (RsaPrivateCrtKeyParameters)reader2.ReadObject();
            // Извлечение значения d (закрытая экспонента)
            BigInteger privateKey_d = new BigInteger(privateKeyParams.Exponent.ToByteArrayUnsigned());
            // Подписание склеенного сообщения
            BigInteger blindedSignature = ModPow(blindedMessage, privateKey_d, n);
            textBox1.Text += "Подписанное сообщение = " + blindedSignature + Environment.NewLine;

            // Снимание затемняющего множителя
            BigInteger unblindedSignature = ModInverse(r, n) * blindedSignature % n;
            textBox1.Text += "Раскрытое сообщение = " + unblindedSignature + Environment.NewLine;

            // Сохранение сообщения и подписи в файлы
            string messageFilePath = "message.txt";
            File.WriteAllText(messageFilePath, message.ToString());
            string signatureFilePath = "signature.bin";
            File.WriteAllBytes(signatureFilePath, unblindedSignature.ToByteArray());

            // Проверка подписи с использованием OpenSSL
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
                r = GenerateRandomNumber(n); // Генерация случайного числа в диапазоне от 1 до n-1
            } while (!IsCoprime(r, n)); // Проверка на взаимную простоту чисел r и n

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