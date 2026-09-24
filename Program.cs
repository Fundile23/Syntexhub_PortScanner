using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace PortScanner
{
    internal class Program
    {
        private static readonly ConcurrentBag<ScanResult> Results = new();
        private static readonly object LogLock = new();
        private const string LogFile = "portscan.log";

        static async Task Main(string[] args)
        {
            // ---- Get input from user ----
            Console.Write("Enter host (e.g. scanme.nmap.org or localhost): ");
            string host = Console.ReadLine()?.Trim() ?? "";

            Console.Write("Start port (default 1): ");
            string startInput = Console.ReadLine();
            int startPort = string.IsNullOrWhiteSpace(startInput) ? 1 : int.Parse(startInput);

            Console.Write("End port (default 1024): ");
            string endInput = Console.ReadLine();
            int endPort = string.IsNullOrWhiteSpace(endInput) ? 1024 : int.Parse(endInput);

            Console.Write("Timeout ms (default 2000): ");
            string timeoutInput = Console.ReadLine();
            int timeoutMs = string.IsNullOrWhiteSpace(timeoutInput) ? 2000 : int.Parse(timeoutInput);

            Console.Write("Threads (default 100): ");
            string threadInput = Console.ReadLine();
            int threads = string.IsNullOrWhiteSpace(threadInput) ? 100 : int.Parse(threadInput);

            // ---- Resolve the host to an IP address ----
            System.Net.IPAddress ip;
            try
            {
                var addrs = await System.Net.Dns.GetHostAddressesAsync(host);
                ip = addrs.First(a => a.AddressFamily == AddressFamily.InterNetwork);
            }
            catch (Exception ex)
            {
                Log($"ERROR: Cannot resolve host '{host}': {ex.Message}");
                Console.WriteLine("\nPress any key to exit.");
                Console.ReadKey();
                return;
            }

            Log($"Starting scan on {host} ({ip}) ports {startPort}-{endPort} timeout={timeoutMs}ms threads={threads}");

            var sw = Stopwatch.StartNew();
            using var semaphore = new SemaphoreSlim(threads);

            var tasks = new List<Task>();
            for (int port = startPort; port <= endPort; port++)
            {
                int p = port;
                await semaphore.WaitAsync();
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var r = await ScanPortAsync(ip.ToString(), p, timeoutMs);
                        Results.Add(r);
                        Log($"Port {p,5}/tcp  {r.Status.ToString().ToUpper()}");
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }));
            }

            await Task.WhenAll(tasks);
            sw.Stop();

            // ---- Summary ----
            var grouped = Results.GroupBy(r => r.Status)
                                 .ToDictionary(g => g.Key, g => g.Select(r => r.Port).OrderBy(x => x).ToList());

            Log(new string('=', 60));
            Log($"Scan report for {host} ({ip})");
            Log($"Duration: {sw.Elapsed.TotalSeconds:F2} seconds");

            foreach (var status in new[] { PortStatus.Open, PortStatus.Closed, PortStatus.Filtered, PortStatus.Error })
            {
                var ports = grouped.TryGetValue(status, out var list) ? list : new List<int>();
                string portsText = ports.Count == 0
                    ? "-"
                    : ports.Count <= 20
                        ? string.Join(",", ports)
                        : string.Join(",", ports.Take(20)) + $", ... (+{ports.Count - 20} more)";

                Log($"{status,-8} ({ports.Count}): {portsText}");
            }
            Log(new string('=', 60));

            Console.WriteLine("\nDone. Results also saved to portscan.log");
            Console.WriteLine("Press any key to exit.");
            Console.ReadKey();
        }

        // ---- Core scan ----
        // The three outcomes that matter:
        //   OPEN     -> TCP handshake succeeded (SYN, SYN-ACK, ACK)
        //   CLOSED   -> server replied with RST (ConnectionRefused)
        //   FILTERED -> no reply at all within the timeout (firewall drop)
        private static async Task<ScanResult> ScanPortAsync(string ip, int port, int timeoutMs)
        {
            using var client = new TcpClient();
            try
            {
                using var cts = new CancellationTokenSource(timeoutMs);
                await client.ConnectAsync(ip, port, cts.Token);
                return new ScanResult(port, PortStatus.Open);
            }
            catch (OperationCanceledException)
            {
                // Timeout expired -> no response -> filtered
                return new ScanResult(port, PortStatus.Filtered);
            }
            catch (SocketException sex)
            {
                return sex.SocketErrorCode switch
                {
                    SocketError.ConnectionRefused => new ScanResult(port, PortStatus.Closed),
                    SocketError.TimedOut => new ScanResult(port, PortStatus.Filtered),
                    SocketError.HostUnreachable => new ScanResult(port, PortStatus.Filtered),
                    SocketError.NetworkUnreachable => new ScanResult(port, PortStatus.Filtered),
                    _ => new ScanResult(port, PortStatus.Error)
                };
            }
            catch
            {
                return new ScanResult(port, PortStatus.Error);
            }
        }

        private static void Log(string message)
        {
            string line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [INFO] {message}";
            lock (LogLock)
            {
                Console.WriteLine(line);
                File.AppendAllText(LogFile, line + Environment.NewLine);
            }
        }

        private record ScanResult(int Port, PortStatus Status);

        private enum PortStatus { Open, Closed, Filtered, Error }
    }
}