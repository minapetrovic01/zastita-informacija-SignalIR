namespace Chat3
{
    public class Message
    {
        public string Content { get; set; }
        public string Sender { get; set; }
        public string EncryptedContent { get; set; }

        public Message(string content, string sender, string encryptedContent)
        {
            Content = content;
            Sender = sender;
            EncryptedContent = encryptedContent;
        }
    }
}
