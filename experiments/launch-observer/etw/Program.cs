using System.Text.Json;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

var root = Path.GetFullPath(args.Length > 0 ? args[0] : "..");
var logs = Path.Combine(root, "logs");
Directory.CreateDirectory(logs);
var path = Path.Combine(logs, $"etw-{DateTime.UtcNow:yyyy-MM-ddTHH-mm-ss.fffZ}.jsonl");
File.WriteAllText(Path.Combine(logs, "latest-etw.txt"), path);
var gate = new object();
using var output = new StreamWriter(new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read)) { AutoFlush = true };
void Emit(object record)
{
    lock (gate)
    {
        var line = JsonSerializer.Serialize(record);
        output.WriteLine(line);
        Console.WriteLine(line);
    }
}
var name = $"UniprocLaunchExperiment-{Environment.ProcessId}-{Guid.NewGuid():N}";
using var session = new TraceEventSession(name);
session.StopOnDispose = true;
long received = 0;
session.Source.Dynamic.All += data =>
{
    if (data.ProviderGuid != new Guid("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716")) return;
    var payload = new Dictionary<string, object?>();
    foreach (var key in data.PayloadNames)
    {
        try
        {
            var value = data.PayloadByName(key);
            payload[key] = value is DateTime date ? date.ToUniversalTime().ToString("o") : value;
        }
        catch (Exception error) { payload[key] = $"decode error: {error.Message}"; }
    }
    string? image = payload.TryGetValue("ImageName", out var imageValue) ? imageValue?.ToString() : null;
    if (image is null && payload.TryGetValue("ProcessID", out var processValue))
    {
        try
        {
            using var process = System.Diagnostics.Process.GetProcessById(Convert.ToInt32(processValue));
            image = process.ProcessName;
        }
        catch { }
    }
    Interlocked.Increment(ref received);
    Emit(new { source = "etw", @event = "process", at = data.TimeStamp.ToUniversalTime().ToString("o"),
        receivedAt = DateTime.UtcNow.ToString("o"), eventName = data.EventName, eventId = (int)data.ID,
        version = (int)data.Version, headerPid = data.ProcessID, headerTid = data.ThreadID, image, payload });
};
var stopped = 0;
void Stop()
{
    if (Interlocked.Exchange(ref stopped, 1) == 0) session.Stop();
}
Console.CancelKeyPress += (_, eventArgs) => { eventArgs.Cancel = true; Stop(); };
using var control = new Timer(_ =>
{
    if (File.Exists(Path.Combine(root, "STOP")) || File.Exists(Path.Combine(root, "STOP-ETW"))) Stop();
}, null, TimeSpan.FromSeconds(1), TimeSpan.FromMilliseconds(500));
using var deadline = new Timer(_ => Stop(), null, TimeSpan.FromMinutes(30), Timeout.InfiniteTimeSpan);
try
{
    session.EnableProvider("Microsoft-Windows-Kernel-Process", TraceEventLevel.Informational, 0x10);
    Emit(new { source = "etw", @event = "ready", at = DateTime.UtcNow.ToString("o"), session = name,
        provider = "Microsoft-Windows-Kernel-Process", keywords = "0x10", log = path, durationSeconds = 1800 });
    session.Source.Process();
    Emit(new { source = "etw", @event = "stopped", at = DateTime.UtcNow.ToString("o"), received,
        eventsLost = session.Source.EventsLost });
}
catch (Exception error)
{
    Emit(new { source = "etw", @event = "error", at = DateTime.UtcNow.ToString("o"), error = error.ToString() });
    Environment.ExitCode = 1;
}
