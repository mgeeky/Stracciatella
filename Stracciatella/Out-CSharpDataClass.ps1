#
# A bit modified to conform Stracciatella needs Out-CSharpDataClass script, originally 
# created by: Lee Christensen (@_tifkin)
#
# Source:
#   https://raw.githubusercontent.com/leechristensen/SpoolSample/master/Out-CSharpDataClass.ps1
#

param(
    [Parameter(Mandatory=$true)]
    [String]
    $SolutionDir,

    [Parameter(Mandatory=$true)]
    [String]
    $Target1,

    [Parameter(Mandatory=$true)]
    [String]
    $Target2
)

function Get-ContentBytesAndXor {
    [CmdletBinding()]
    Param(
        [Parameter(Position=0, Mandatory=$true)]
        [string]
        $Path,

        [Parameter(Position=1, Mandatory=$false)]
        [int]
        $XorKey = 0
    )

    if(Test-Path -Path $Path -ErrorAction Stop -PathType Leaf) {
        $Fullname = (Get-ChildItem $Path).FullName

        if($XorKey -ne 0) {
            Write-Verbose "XORing ($XorKey) file: $Path"
            $bytes = ([System.IO.File]::ReadAllBytes($Fullname))
            $out = @(0) * ($bytes.Length)

            $i = 0
            foreach($Byte in $bytes) {
                $out[$i] = $Byte -bxor $XorKey
                $i += 1
            }
            return $out
        } else {
            return [System.IO.File]::ReadAllBytes($FullName)
        }
    }
}

function ConvertTo-CSharpDataClass {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [byte[]]
        $ByteArray,

        [Parameter(Mandatory=$false)]
        [int]
        $Columns = 32,

        [Parameter(Mandatory=$false)]
        [string]
        $Variable = 'Data'
    )

    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append("public static byte[] $($Variable) = new byte[] {")

    for($i = 0; $i -lt $ByteArray.Count; $i++) {
        if(($i % $Columns) -eq 0) {
            $null = $sb.Append("`n            ")
        }
        $null = $sb.Append("0x{0:X2}," -f $ByteArray[$i])
    }

    $null = $sb.Remove($sb.Length-1, 1) #Remove the last comman
    $null = $sb.Append(@"
        };
"@);
    $sb.ToString()
}

$XorKey = Get-Random -Maximum 255

# For whatever reason, VS keeps including a double quote in the pathst
$SolutionDir = $SolutionDir.Replace('"','')

Write-Verbose "Reading file: `"$Target1`""
$bytes1 = Get-ContentBytesAndXor -Path $Target1 -XorKey $XorKey
Write-Verbose "Reading file: `"$Target2`""
$bytes2 = Get-ContentBytesAndXor -Path $Target2 -XorKey $XorKey

Write-Verbose "Converting file: `"$Target1`""
$output1 = ConvertTo-CSharpDataClass -Variable 'ClmDisableAssemblyData' -ByteArray $bytes1
Write-Verbose "Converting file: `"$Target2`""
$output2 = ConvertTo-CSharpDataClass -Variable 'ClmDisableDllData' -ByteArray $bytes2

$x = "0x{0:X2}" -f $XorKey
$output = @"
namespace Stracciatella
{
    static class ClmEmbeddedFiles
    {
        public static byte FilesXorKey = $x;
        $output1
        $output2
    }
}
"@

Write-Verbose "Dumping outputs to: $($SolutionDir)\Stracciatella\ClmEmbeddedFiles.cs"
$output | Out-File -Encoding ascii -FilePath "$($SolutionDir)\Stracciatella\ClmEmbeddedFiles.cs"   