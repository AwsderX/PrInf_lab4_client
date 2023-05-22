
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
            // Генерация закрытого ключа
            string privateKeyPath = $"privatekey.pem";
            string publicKeyPath = $"publickey.pem";
            string privateKeyCommand = $"genpkey -algorithm RSA -out {privateKeyPath} -pkeyopt rsa_keygen_bits:1024";
            ExecuteOpenSSLCommand(privateKeyCommand);

            // Извлечение открытого ключа из закрытого
            string publicKeyCommand = $"rsa -pubout -in {privateKeyPath} -out {publicKeyPath}";
            ExecuteOpenSSLCommand(publicKeyCommand);

            string privateKeyOutput = ExecuteOpenSSLCommand($"rsa -in {privateKeyPath} -noout -text");
            string publicKeyOutput = ExecuteOpenSSLCommand($"rsa -pubin -in {publicKeyPath} -noout -text");
            BigInteger e, n, d;
            ExtractExponents(privateKeyOutput, publicKeyOutput, out e, out n, out d);

            // Генерация случайного затемняющего множителя
            BigInteger r = GenerateBlindingFactor(n);
            // Умножение сообщения на затемняющий множитель
            BigInteger blindedMessage = message * ModPow(r,e,n) % n;

            textBox1.Text += "Склеенное сообщение = " + blindedMessage + Environment.NewLine;


            // Подписание склеенного сообщения
            BigInteger blindedSignature = ModPow(blindedMessage, d, n);
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
            if (ModPow(unblindedSignature, e, n) == message) 
            {
                textBox1.Text = "Проверка пройдёна";
            }
            else
            {
                textBox1.Text = $"Проверка провалена {ModPow(unblindedSignature, e, n)}   {message}";
            }

        }

        // Метод для генерации маскировочного множителя для слепой подписи RSA
        public static BigInteger GenerateBlindingFactor(BigInteger modulus)
        {
            BigInteger blindingFactor;
            do
            {
                blindingFactor = GenerateRandomBigInteger(modulus);
            } while (!IsCoprime(blindingFactor, modulus));
            return blindingFactor;
        }

        // Метод для генерации случайного BigInteger в пределах заданного модуля
        private static BigInteger GenerateRandomBigInteger(BigInteger modulus)
        {
            byte[] randomBytes = new byte[modulus.ToByteArray().Length];
            using (var rng = new RNGCryptoServiceProvider())
            {
                do
                {
                    rng.GetBytes(randomBytes);
                    randomBytes[randomBytes.Length - 1] &= 0x7F; // установка старшего бита в 0, чтобы получить положительное значение
                } while (new BigInteger(randomBytes) >= modulus);
            }
            return new BigInteger(randomBytes);
        }

        // Метод для проверки взаимной простоты двух чисел
        private static bool IsCoprime(BigInteger a, BigInteger b)
        {
            BigInteger gcd = BigInteger.GreatestCommonDivisor(a, b);
            return gcd.Equals(BigInteger.One);
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
                    e = BigInteger.Parse(value);
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