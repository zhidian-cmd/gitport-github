# Remove the Mandatory Integrity Label ACE from a directory (restore default "no label").
# LABEL_SECURITY_INFORMATION write needs no SeSecurityPrivilege; do not read the SACL.
# Usage: powershell -File strip_label.ps1 <path>
param([string]$Target)

$src = @'
using System;
using System.Runtime.InteropServices;

public static class LabelStrip {
    const int SE_FILE_OBJECT = 1;
    const uint LABEL_SECURITY_INFORMATION = 0x00000010;

    [StructLayout(LayoutKind.Sequential)]
    public struct ACL {
        public byte AclRevision;
        public byte Sbz1;
        public ushort AclSize;
        public ushort AceCount;
        public ushort Sbz2;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    static extern uint SetNamedSecurityInfoW(string name, int objType, uint info,
        IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);

    public static uint Strip(string path) {
        ACL empty = new ACL();
        empty.AclRevision = 2;
        empty.AclSize = (ushort)Marshal.SizeOf(typeof(ACL));
        empty.AceCount = 0;
        IntPtr pEmpty = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(ACL)));
        Marshal.StructureToPtr(empty, pEmpty, false);
        uint err = SetNamedSecurityInfoW(path, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION,
            IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, pEmpty);
        Marshal.FreeHGlobal(pEmpty);
        return err;
    }
}
'@
Add-Type -TypeDefinition $src -Language CSharp
$rc = [LabelStrip]::Strip($Target)
Write-Host ("strip '" + $Target + "' result: 0x" + $rc.ToString("X8"))
