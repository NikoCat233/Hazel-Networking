using System;

namespace Hazel.UnitTests
{
    public class TestLogger : ILogger
    {
        private readonly string prefix;

        public TestLogger(string prefix = "")
        {
            this.prefix = prefix;
        }

        public void WriteVerbose(string msg)
        {
            if (string.IsNullOrEmpty(this.prefix))
            {
                Console.WriteLine($"[VERBOSE] {msg}");
            }
            else
            {
                Console.WriteLine($"[{this.prefix}][VERBOSE] {msg}");
            }
        }

        public void WriteWarning(string msg)
        {
            if (string.IsNullOrEmpty(this.prefix))
            {
                Console.WriteLine($"[WARN] {msg}");
            }
            else
            {
                Console.WriteLine($"[{this.prefix}][WARN] {msg}");
            }
        }

        public void WriteError(string msg)
        {
            if (string.IsNullOrEmpty(this.prefix))
            {
                Console.WriteLine($"[ERROR] {msg}");
            }
            else
            {
                Console.WriteLine($"[{this.prefix}][ERROR] {msg}");
            }
        }

        public void WriteInfo(string msg)
        {
            if (string.IsNullOrEmpty(this.prefix))
            {
                Console.WriteLine($"[INFO] {msg}");
            }
            else
            {
                Console.WriteLine($"[{this.prefix}][INFO] {msg}");
            }
        }
    }
}
