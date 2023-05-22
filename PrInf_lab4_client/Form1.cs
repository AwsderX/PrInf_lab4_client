
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
            //ExtractExponents(publicKeyOutput, out e, out n);

            //// Чтение открытого ключа из файла
            //string publicKeyContents = File.ReadAllText(publicKeyPath);
            //// Парсинг открытого ключа в PEM формате
            //PemReader reader = new PemReader(new StringReader(publicKeyContents));
            //RsaKeyParameters publicKeyParams = (RsaKeyParameters)reader.ReadObject();
            //// Извлечение значения e (открытая экспонента)
            //BigInteger e = new BigInteger(publicKeyParams.Exponent.ToByteArrayUnsigned());
            //textBox1.Text += "Экспонента = " + e.ToString() + Environment.NewLine;
            //// Извлечение значения n (модуль)
            //BigInteger n = new BigInteger(publicKeyParams.Modulus.ToByteArrayUnsigned());
            //textBox1.Text += "Модуль = " + n.ToString() + Environment.NewLine;

            // Генерация случайного затемняющего множителя (blinding factor)
            //Random random = new Random();
            // BigInteger r = GenerateRandomBigInteger(random, BigInteger.One, n - BigInteger.One);
            BigInteger r = GenerateBlindingFactor(n);
            // Генерация случайного затемняющего множителя
            //BigInteger r = 200;
            // Умножение сообщения на затемняющий множитель
            BigInteger blindedMessage = message * ModPow(r,e,n) % n;

            textBox1.Text += "Склеенное сообщение = " + blindedMessage + Environment.NewLine;

            // Чтение закрытого ключа из файла
            //string privateKeyContents = File.ReadAllText(privateKeyPath);
            //// Парсинг закрытого ключа в PEM формате
            //PemReader reader2 = new PemReader(new StringReader(privateKeyContents));
            //RsaPrivateCrtKeyParameters privateKeyParams = (RsaPrivateCrtKeyParameters)reader2.ReadObject();
            //// Извлечение значения d (закрытая экспонента)
            //BigInteger privateKey_d = new BigInteger(privateKeyParams.Exponent.ToByteArrayUnsigned());
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

            if (ModPow(unblindedSignature, e, n) == message) 
            {
                textBox1.Text = "Проверка пройдёна";
            }
            else
            {
                textBox1.Text = $"Проверка провалена {ModPow(unblindedSignature, e, n)}   {message}";
            }
            // Проверка подписи с использованием OpenSSL
            //string opensslCommand = $"dgst -sha256 -verify {publicKeyPath} -signature {signatureFilePath} {messageFilePath}";
            //textBox1.Text += ExecuteOpenSSLCommand(opensslCommand);

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


        // Метод для генерации маскировочного множителя
        //public BigInteger GenerateRandomBigInteger(BigInteger m)
        //{
        //    BigInteger r;
        //    do
        //    {
        //        r = new BigInteger(m.ToByteArray());
        //        using (var random = new RNGCryptoServiceProvider())
        //        {
        //            byte[] bytes = new byte[m.ToByteArray().Length];
        //            do
        //            {
        //                random.GetBytes(bytes);
        //                r = new BigInteger(bytes);
        //            } while (r >= m || !BigInteger.One.Equals(BigInteger.GreatestCommonDivisor(r, m)));
        //        }
        //    } while (r >= m || !BigInteger.One.Equals(BigInteger.GreatestCommonDivisor(r, m))); // Проверка на взаимно простоту с модулем
        //    return r;
        //}

        //private BigInteger GenerateRandomBigInteger(Random random, BigInteger minValue, BigInteger maxValue)
        //{
        //    int maxBytes = Math.Max(minValue.ToByteArray().Length, maxValue.ToByteArray().Length);
        //    byte[] randomBytes = new byte[maxBytes];
        //    BigInteger result;

        //    do
        //    {
        //        random.NextBytes(randomBytes);
        //        randomBytes[randomBytes.Length - 1] &= 0x7F;  // Ensure positive value
        //        result = new BigInteger(randomBytes);
        //    }
        //    while (result <= minValue || result >= maxValue);

        //    return result;
        //}
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