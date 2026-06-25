using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Opc.Ua;
using Opc.Ua.Client;
using Opc.Ua.Configuration;

class Program
{
    private static ISession? session;

    // Configuration constants
    private const int OperationTimeoutMs = 15000;
    private const int SessionTimeoutMs = 60000;
    private const int MaxErrorMessageLength = 80;
    private const uint StandardUaServerTimeNodeId = 2258;
    private const int PortScanTimeoutMs = 3000;  // Timeout per port during scan

    // Common OPC UA ports
    private static readonly int[] CommonOpcUaPorts = new[]
    {
        4840,    // Standard OPC UA port
        4843,    // Standard OPC UA secure port
        49320,   // UA standard alternative
        49321,   // UA standard alternative
        8080,    // Alternative HTTP
        8081,    // Alternative HTTP
        8443,    // Alternative HTTPS
        50000,   // Common alternative
        50001,   // Common alternative
    };

    // Port range for scanning
    private const int PortRangeStart = 4800;
    private const int PortRangeEnd = 5000;

    // Default OPC UA server URLs to probe
    private static readonly string[] DefaultServerUrls = new[]
    {
        "opc.tcp://localhost:49320",
        "opc.tcp://localhost:4840",
        "opc.tcp://localhost:4843",
    };

    static async Task Main(string[] args)
    {
        Console.WriteLine("=== OPC UA Server Connector ===\n");

        try
        {
            ApplicationConfiguration config = await BuildClientConfig();
            List<EndpointDescription> endpoints = new List<EndpointDescription>();

            // Try default ports first
            Console.WriteLine("Step 1: Scanning default OPC UA ports...");
            endpoints = await DiscoverEndpointsAsync(config, DefaultServerUrls);

            if (endpoints.Count > 0)
            {
                Console.WriteLine($"Found {endpoints.Count} server(s) on default ports.\n");
            }
            else
            {
                Console.WriteLine("No servers found on default ports.\n");
            }

            // Offer additional discovery options
            string? additionalChoice = PromptForAdditionalDiscovery();
            if (!string.IsNullOrEmpty(additionalChoice))
            {
                var additionalEndpoints = await PerformAdditionalDiscovery(config, additionalChoice);
                endpoints.AddRange(additionalEndpoints);
            }

            if (endpoints.Count == 0)
            {
                Console.WriteLine("No OPC UA servers found. Exiting.");
                return;
            }

            EndpointDescription? chosen = PromptUserSelection(endpoints);

            if (chosen == null)
            {
                Console.WriteLine("No server selected. Exiting.");
                return;
            }

            await ConnectAndVerify(config, chosen);
        }
        finally
        {
            session?.Dispose();
        }

        Console.WriteLine("\nPress any key to exit...");
        Console.ReadKey();
    }

    static string? PromptForAdditionalDiscovery()
    {
        Console.WriteLine("Step 2: Would you like to search for servers on other ports/hosts?");
        Console.WriteLine("  [1] Scan common OPC UA ports on localhost");
        Console.WriteLine("  [2] Scan a custom port range on localhost");
        Console.WriteLine("  [3] Enter custom endpoint URL(s)");
        Console.WriteLine("  [4] Scan ports on a specific host");
        Console.WriteLine("  [0] Skip additional discovery");
        Console.Write("\nEnter your choice (0-4): ");

        string? choice = Console.ReadLine()?.Trim();
        return choice;
    }

    static async Task<List<EndpointDescription>> PerformAdditionalDiscovery(ApplicationConfiguration config, string choice)
    {
        return choice switch
        {
            "1" => await DiscoverOnCommonPorts(config, "localhost"),
            "2" => await DiscoverOnCustomPortRange(config, "localhost"),
            "3" => await DiscoverOnCustomUrls(config),
            "4" => await DiscoverOnCustomHost(config),
            _ => new List<EndpointDescription>()
        };
    }

    static async Task<ApplicationConfiguration> BuildClientConfig()
    {
        var config = new ApplicationConfiguration()
        {
            ApplicationName = "OpcConnectorTest",
            ApplicationType = ApplicationType.Client,
            SecurityConfiguration = new SecurityConfiguration
            {
                AutoAcceptUntrustedCertificates = true,
                ApplicationCertificate = new CertificateIdentifier()
            },
            TransportQuotas = new TransportQuotas { OperationTimeout = OperationTimeoutMs },
            ClientConfiguration = new ClientConfiguration { DefaultSessionTimeout = SessionTimeoutMs }
        };

        // Validate and create certificate stores
        await config.Validate(ApplicationType.Client);

        // Accept all certificates for testing (not recommended for production)
        config.CertificateValidator.CertificateValidation += (sender, eventArgs) => { eventArgs.Accept = true; };

        return config;
    }

    static async Task<List<EndpointDescription>> DiscoverEndpointsAsync(ApplicationConfiguration config, string[] urlsToProbe)
    {
        var found = new List<EndpointDescription>();

        Console.WriteLine($"\nScanning {urlsToProbe.Length} endpoint(s)...");

        foreach (string url in urlsToProbe)
        {
            try
            {
                Console.Write($"  Probing {url} ... ");

                // Try to connect to each candidate URL to see if a server is listening
                var description = new EndpointDescription
                {
                    EndpointUrl = url,
                    SecurityMode = MessageSecurityMode.None,
                    SecurityPolicyUri = SecurityPolicies.None,
                    Server = new ApplicationDescription()
                };

                var endpoint = new ConfiguredEndpoint(null, description);

                // Try a quick connection attempt
                ISession? testSession = await Session.Create(
                    config,
                    endpoint,
                    false,
                    false,
                    "DiscoveryProbe",
                    PortScanTimeoutMs,
                    new UserIdentity(),
                    null
                );

                if (testSession != null)
                {
                    Console.WriteLine("FOUND");
                    found.Add(description);
                    testSession.Close();
                }
                else
                {
                    Console.WriteLine("no response");
                }
            }
            catch (Exception ex)
            {
                string reason = TruncateMessage(ex.Message, MaxErrorMessageLength);
                Console.WriteLine($"no response ({reason})");
            }
        }

        Console.WriteLine();
        return found;
    }

    static async Task<List<EndpointDescription>> DiscoverOnCommonPorts(ApplicationConfiguration config, string host)
    {
        Console.WriteLine($"\nScanning common OPC UA ports on {host}...");
        var urls = CommonOpcUaPorts.Select(port => $"opc.tcp://{host}:{port}").ToArray();
        return await DiscoverEndpointsAsync(config, urls);
    }

    static async Task<List<EndpointDescription>> DiscoverOnCustomPortRange(ApplicationConfiguration config, string host)
    {
        Console.Write($"\nEnter port range start (default {PortRangeStart}): ");
        string? startInput = Console.ReadLine()?.Trim();
        int start = int.TryParse(startInput, out int s) ? s : PortRangeStart;

        Console.Write($"Enter port range end (default {PortRangeEnd}): ");
        string? endInput = Console.ReadLine()?.Trim();
        int end = int.TryParse(endInput, out int e) ? e : PortRangeEnd;

        if (start > end)
        {
            (start, end) = (end, start);  // Swap if reversed
        }

        Console.WriteLine($"Scanning ports {start}-{end} on {host}. This may take a while...");

        var urls = Enumerable.Range(start, end - start + 1)
            .Select(port => $"opc.tcp://{host}:{port}")
            .ToArray();

        return await DiscoverEndpointsAsync(config, urls);
    }

    static async Task<List<EndpointDescription>> DiscoverOnCustomUrls(ApplicationConfiguration config)
    {
        var urls = new List<string>();

        Console.WriteLine("\nEnter custom endpoint URLs (one per line, empty line to finish):");
        while (true)
        {
            Console.Write("> ");
            string? url = Console.ReadLine()?.Trim();

            if (string.IsNullOrEmpty(url))
            {
                break;
            }

            // Ensure URL has proper prefix
            if (!url.StartsWith("opc.tcp://") && !url.StartsWith("opc.https://"))
            {
                url = "opc.tcp://" + url;
            }

            urls.Add(url);
        }

        if (urls.Count == 0)
        {
            Console.WriteLine("No URLs entered.");
            return new List<EndpointDescription>();
        }

        return await DiscoverEndpointsAsync(config, urls.ToArray());
    }

    static async Task<List<EndpointDescription>> DiscoverOnCustomHost(ApplicationConfiguration config)
    {
        Console.Write("Enter hostname or IP address: ");
        string? host = Console.ReadLine()?.Trim();

        if (string.IsNullOrEmpty(host))
        {
            Console.WriteLine("No host entered.");
            return new List<EndpointDescription>();
        }

        Console.WriteLine("Which ports would you like to scan?");
        Console.WriteLine("  [1] Common OPC UA ports");
        Console.WriteLine("  [2] Custom port range");
        Console.Write("Enter choice (1 or 2): ");

        string? choice = Console.ReadLine()?.Trim();

        if (choice == "1")
        {
            Console.WriteLine($"\nScanning common ports on {host}...");
            var urls = CommonOpcUaPorts.Select(port => $"opc.tcp://{host}:{port}").ToArray();
            return await DiscoverEndpointsAsync(config, urls);
        }
        else if (choice == "2")
        {
            Console.Write($"Enter port range start (default {PortRangeStart}): ");
            string? startInput = Console.ReadLine()?.Trim();
            int start = int.TryParse(startInput, out int s) ? s : PortRangeStart;

            Console.Write($"Enter port range end (default {PortRangeEnd}): ");
            string? endInput = Console.ReadLine()?.Trim();
            int end = int.TryParse(endInput, out int e) ? e : PortRangeEnd;

            if (start > end)
            {
                (start, end) = (end, start);
            }

            Console.WriteLine($"Scanning ports {start}-{end} on {host}. This may take a while...");
            var urls = Enumerable.Range(start, end - start + 1)
                .Select(port => $"opc.tcp://{host}:{port}")
                .ToArray();

            return await DiscoverEndpointsAsync(config, urls);
        }

        return new List<EndpointDescription>();
    }

    private static string TruncateMessage(string message, int maxLength)
    {
        return message.Length > maxLength 
            ? string.Concat(message.AsSpan(0, maxLength), "...") 
            : message;
    }

    static EndpointDescription? PromptUserSelection(List<EndpointDescription> endpoints)
    {
        Console.WriteLine("Discovered endpoints:");
        Console.WriteLine(new string('-', 60));

        for (int i = 0; i < endpoints.Count; i++)
        {
            var ep = endpoints[i];
            string secPolicy = ExtractSecurityPolicy(ep.SecurityPolicyUri);

            Console.WriteLine($"  [{i + 1}] URL      : {ep.EndpointUrl}");
            Console.WriteLine($"       Server   : {ep.Server?.ApplicationName?.Text ?? "Unknown"}");
            Console.WriteLine($"       Security : {secPolicy}");
            Console.WriteLine($"       Mode     : {ep.SecurityMode}");
            Console.WriteLine();
        }

        Console.Write("Enter the number of the server you want to connect to (or 0 to cancel): ");

        if (int.TryParse(Console.ReadLine()?.Trim(), out int choice) &&
            choice >= 1 && choice <= endpoints.Count)
        {
            EndpointDescription selected = endpoints[choice - 1];
            Console.WriteLine($"\nSelected: {selected.EndpointUrl}\n");
            return selected;
        }

        return null;
    }

    private static string ExtractSecurityPolicy(string? securityPolicyUri)
    {
        if (string.IsNullOrEmpty(securityPolicyUri))
            return "Unknown";

        int hashIndex = securityPolicyUri.IndexOf('#');
        return hashIndex >= 0 
            ? securityPolicyUri.Substring(hashIndex + 1) 
            : securityPolicyUri;
    }

    static async Task ConnectAndVerify(ApplicationConfiguration config, EndpointDescription endpointDesc)
    {
        Console.WriteLine("Attempting connection...");

        try
        {
            var endpoint = new ConfiguredEndpoint(
                null,
                endpointDesc,
                EndpointConfiguration.Create(config)
            );

            session = await Session.Create(
                config,
                endpoint,
                false,
                false,
                "ConnectorTestSession",
                SessionTimeoutMs,
                new UserIdentity(),
                null
            );

            if (!session.Connected)
            {
                Console.WriteLine("Session created but reports as NOT connected.");
                return;
            }

            Console.WriteLine("Session established.\n");

            NodeId currentTimeNode = new NodeId(StandardUaServerTimeNodeId, 0);
            DataValue serverTime = session.ReadValue(currentTimeNode);

            if (StatusCode.IsGood(serverTime.StatusCode))
            {
                Console.WriteLine("=== CONNECTION VERIFIED ===");
                Console.WriteLine($"  Endpoint   : {session.Endpoint.EndpointUrl}");
                Console.WriteLine($"  Server time: {serverTime.Value}");
                Console.WriteLine($"  Status     : {serverTime.StatusCode}");
                Console.WriteLine($"  Session ID : {session.SessionId}");
            }
            else
            {
                Console.WriteLine($"Connected but live-read returned bad status: {serverTime.StatusCode}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Connection failed: {ex.Message}");
        }
    }
}
