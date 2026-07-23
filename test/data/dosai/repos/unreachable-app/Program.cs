using System.IO;
// unreachable-app: references Newtonsoft.Json (listed in the .csproj / restored
// .deps.json) but the source NEVER calls any Newtonsoft API. dosai must NOT
// flag a DataFlowNode/CallGraphEdge reachability for the package (at most a
// Dependency-level/low-confidence reference).
namespace unreachable_app;
static class Program
{
    public static int Run(TextReader input)
    {
        var line = input.ReadLine();
        System.Console.WriteLine(line?.ToUpper());
        return 0;
    }
    static void Main() => Run(System.Console.In);
}
