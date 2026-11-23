# Run after cargo build --release. Each phase uses the same fresh monitor instance.
param([ValidateRange(3,120)][int]$Observations = 12)
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class MonitorBench {
    [StructLayout(LayoutKind.Sequential)]
    struct Counters {
        public uint size, faults;
        public UIntPtr peakWs, ws, peakPaged, paged, peakNonpaged, nonpaged;
        public UIntPtr pagefile, peakPagefile, privateBytes, privateWs;
        public ulong sharedCommit;
    }
    [DllImport("psapi.dll", SetLastError=true)]
    static extern bool GetProcessMemoryInfo(IntPtr h, ref Counters m, uint n);
    public static ulong PrivateWs(IntPtr h) {
        var m = new Counters(); m.size=(uint)Marshal.SizeOf(typeof(Counters));
        if (!GetProcessMemoryInfo(h,ref m,m.size)) throw new Win32Exception();
        return m.privateWs.ToUInt64();
    }
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h,int mode);
    [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h,int id);
    [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h,int m,IntPtr a,IntPtr b);
    [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr h);
}
'@
$binary = Join-Path $PSScriptRoot '..\target\release\debloatR.exe'
$monitor = Start-Process $binary -PassThru -WindowStyle Normal
try {
    if (!$monitor.WaitForInputIdle(15000)) { throw 'Window startup timed out' }

    $monitor.Refresh()
    $window = $monitor.MainWindowHandle
    if ($window -eq [IntPtr]::Zero) { throw 'No monitor window' }
    foreach ($id in 45,10) {
        [void][MonitorBench]::SendMessage([MonitorBench]::GetDlgItem($window,$id),245,0,0)
        Start-Sleep -Milliseconds 500
    }
    Start-Sleep -Seconds 6
    foreach ($phase in 'Visible','Minimized') {
        $minimized = $phase -eq 'Minimized'
        if ($minimized) { [void][MonitorBench]::ShowWindow($window,6) }
        if ([MonitorBench]::IsIconic($window) -ne $minimized) { throw 'Window state mismatch' }
        $monitor.Refresh()
        $cpu = $monitor.TotalProcessorTime.TotalSeconds
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $ws = foreach ($i in 1..$Observations) {
            Start-Sleep -Seconds 5
            [MonitorBench]::PrivateWs($monitor.Handle) / 1MB
        }
        $monitor.Refresh()
        $seconds = $timer.Elapsed.TotalSeconds
        $cpuDelta = $monitor.TotalProcessorTime.TotalSeconds - $cpu
        $stats = $ws | Measure-Object -Minimum -Maximum -Average
        [pscustomobject]@{
            Phase=$phase; Seconds=[math]::Round($seconds,2); Samples=$Observations
            AvgPrivateWsMiB=[math]::Round($stats.Average,2)
            MinMiB=[math]::Round($stats.Minimum,2); MaxMiB=[math]::Round($stats.Maximum,2)
            MachineCPUPercent=[math]::Round(100*$cpuDelta/$seconds/[Environment]::ProcessorCount,3)
            OneCorePercent=[math]::Round(100*$cpuDelta/$seconds,3)
        } | Format-List
    }
} finally {
    if (!$monitor.HasExited) { [void]$monitor.CloseMainWindow(); [void]$monitor.WaitForExit(5000) }
}

