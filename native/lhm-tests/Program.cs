using System;
using Uniproc.Lhm;

static void Equal(double? expected, double? actual)
{
    if (expected != actual) throw new Exception($"Expected {expected}, got {actual}");
}

foreach (string name in new[] { "CPU Package", "Package" })
{
    Equal(12.5, CpuPackagePower.Read(new[] { (true, name, (float?)12.5f), (true, "CPU Cores", (float?)7f) }, false));
    Equal(0, CpuPackagePower.Read(new[] { (true, name, (float?)0f) }, false));
    Equal(null, CpuPackagePower.Read(new[] { (true, name, (float?)12f) }, true));
    Equal(null, CpuPackagePower.Read(new[] { (false, name, (float?)12f) }, false));
    foreach (float? invalid in new float?[] { null, -1f, float.NaN, float.PositiveInfinity, float.NegativeInfinity })
        Equal(null, CpuPackagePower.Read(new[] { (true, name, invalid) }, false));
}
Equal(null, CpuPackagePower.Read(new[] { (true, "CPU Package", (float?)12f), (true, "Package", (float?)13f) }, false));
Equal(null, CpuPackagePower.Read(new[] { (true, "CPU Platform", (float?)12f) }, false));
Equal(null, CpuPackagePower.Total(Array.Empty<double?>()));
Equal(0, CpuPackagePower.Total(new double?[] { 0, 0 }));
Equal(25.5, CpuPackagePower.Total(new double?[] { 12, 13.5 }));
foreach (double? invalid in new double?[] { null, -1, double.NaN, double.PositiveInfinity })
    Equal(null, CpuPackagePower.Total(new double?[] { 12, invalid }));
Console.WriteLine("CPU package power selection and complete aggregation passed");
