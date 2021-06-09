using System.Xml;

namespace Encryption_Key_Generator
{
    class Writer
    {

        public static void writeXml(string filename, string content)
        {
            XmlDocument xdoc = new XmlDocument();
            xdoc.LoadXml(content);
            xdoc.Save(filename);
        }
    }
}
