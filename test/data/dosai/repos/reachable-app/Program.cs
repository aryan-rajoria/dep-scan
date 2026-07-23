using System.IO;
// reachable-app: references Newtonsoft.Json AND reaches it via a recognized
// deserialization sink (fully-qualified JsonConvert.DeserializeObject invoked
// on a method-parameter source). dosai flags this as a DataFlowNode (High).
namespace reachable_app;
public record EchoRequest(string Method, object? Args);
static class Program
{
    public static int Run(TextReader input)
    {
        var line = input.ReadLine();
        var req = Newtonsoft.Json.JsonConvert.DeserializeObject<EchoRequest>(line);
        System.Console.WriteLine(req?.Method);
        return 0;
    }
    static void Main() => Run(System.Console.In);
}
