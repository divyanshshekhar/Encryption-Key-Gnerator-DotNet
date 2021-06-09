
using System;

namespace Encryption_Key_Generator
{
    class Program
    {
        static void Main(string[] args)
        {
            const int USER_CHOICE_RSA = 1;
            bool invalidChoice = true;
            while (invalidChoice)
            {
                Console.WriteLine("This application creates encryption keys and stores them in .key file.");
                Console.WriteLine("\t1 : Generate RSA key pair.");
                Console.WriteLine("Enter your choice.");

                int choose = Convert.ToInt32(Console.ReadLine());

                invalidChoice = false;

                switch (choose)
                {
                    case USER_CHOICE_RSA:
                        RSAAdapter.genrateRSA();
                        Console.WriteLine("Keys generated.");
                        break;
                    default:
                        Console.WriteLine("Invalid choice. Try again.");
                        invalidChoice = true;
                        break;
                }
                Console.WriteLine("Press enter to exit...");
                Console.ReadLine();
            }
        }

        /*
    private static void genrateRSA()
    {
        //lets take a new CSP with a new 2048 bit rsa key pair
        var csp = new RSACryptoServiceProvider(2048);

        //how to get the private key
        var privKey = csp.ExportParameters(true);

        //and the public key ...
        var pubKey = csp.ExportParameters(false);

        //converting the private key into a string representation
        string privKeyString;
        {
            //we need some buffer
            var sw = new System.IO.StringWriter();
            //we need a serializer
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            //serialize the key into the stream
            xs.Serialize(sw, privKey);
            //get the string from the stream
            privKeyString = sw.ToString();
        }

        //converting the public key into a string representation
        string pubKeyString;
        {
            //we need some buffer
            var sw = new System.IO.StringWriter();
            //we need a serializer
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            //serialize the key into the stream
            xs.Serialize(sw, pubKey);
            //get the string from the stream
            pubKeyString = sw.ToString();
        }

        writeXml("privateKeyRSA2048.key", privKeyString);
        writeXml("publicKeyRSA2048.key", pubKeyString);*/

        /*RSACryptoServiceProvider rsa = null;
        string publicPrivateKeyXML;
        const int PROVIDER_RSA_FULL = 1;
        const string CONTAINER_NAME = "KeyContainer";

        CspParameters cspParams;
        cspParams = new CspParameters(PROVIDER_RSA_FULL);
        cspParams.KeyContainerName = CONTAINER_NAME;
        cspParams.Flags = CspProviderFlags.UseMachineKeyStore;
        cspParams.ProviderName = "Microsoft Strong Cryptographic Provider";
        rsa = new RSACryptoServiceProvider(cspParams);
        //Pair of public and private key as XML string.
        //Do not share this to other party
        publicPrivateKeyXML = rsa.ToXmlString(true);

    }
        writeXml("publicPrivateKeyRSA.xml", publicPrivateKeyXML);*/

    }
}
