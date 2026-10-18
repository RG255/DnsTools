function Test-DnssecEd25519Signature
{
	<#
		.SYNOPSIS
		Verifies an Ed25519 signature (DNSSEC algorithm 15, RFC 8080) in pure managed code.

		.DESCRIPTION
		Added in 0.8. Neither Windows PowerShell 5.1 (.NET Framework) nor the .NET versions PowerShell 7 ships on have
		an Ed25519 primitive, so this carries a small RFC 8032 section 5.1.7 verifier written on System.Numerics.BigInteger
		and SHA-512. It VERIFIES only (public inputs, so timing is not a concern) and is compiled on first use with
		Add-Type. Checked against RFC 8032 test vectors and against signatures made by OpenSSL (see Tests).

		Cofactorless verification [S]B = R + [h]A, with the strict canonical checks: S < L, and R and A must decode to
		points on the curve.

		.PARAMETER PublicKey
		The 32-byte public key (the DNSKEY public key field for algorithm 15).

		.PARAMETER Signature
		The 64-byte signature (R || S).

		.PARAMETER Message
		The signed data.

		.OUTPUTS
		[bool]
	#>
	[CmdletBinding()]
	[OutputType([bool])]
	param(
		[Parameter(Mandatory)]
		[byte[]]$PublicKey,

		[Parameter(Mandatory)]
		[byte[]]$Signature,

		[Parameter(Mandatory)]
		[AllowEmptyCollection()]
		[byte[]]$Message
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	if ($PublicKey.Length -ne 32 -or $Signature.Length -ne 64)
	{return $false}

	if (-not ('DnsToolsEd25519V1' -as [type]))
	{
		$source = @'
using System;
using System.Numerics;
using System.Security.Cryptography;

public static class DnsToolsEd25519V1
{
    static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;
    static readonly BigInteger L = BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493");
    static readonly BigInteger D;
    static readonly BigInteger SqrtM1;
    static readonly BigInteger[] B;

    static BigInteger Mod(BigInteger a) { BigInteger r = a % P; return r.Sign < 0 ? r + P : r; }
    static BigInteger Inv(BigInteger a) { return BigInteger.ModPow(Mod(a), P - 2, P); }

    static DnsToolsEd25519V1()
    {
        D = Mod(-121665 * Inv(121666));
        SqrtM1 = BigInteger.ModPow(2, (P - 1) / 4, P);
        BigInteger by = Mod(4 * Inv(5));
        B = Decode(EncodeY(by), true);
    }

    static byte[] EncodeY(BigInteger y)
    {
        byte[] raw = y.ToByteArray();
        byte[] o = new byte[32];
        Array.Copy(raw, o, Math.Min(32, raw.Length));
        return o;
    }

    static BigInteger LE(byte[] b, int off, int len)
    {
        byte[] t = new byte[len + 1];
        Array.Copy(b, off, t, 0, len);
        return new BigInteger(t);
    }

    // Decode a compressed point (extended coordinates X,Y,Z,T) or null when it is not on the curve.
    static BigInteger[] Decode(byte[] enc, bool baseOk)
    {
        int sign = (enc[31] >> 7) & 1;
        byte[] yb = (byte[])enc.Clone();
        yb[31] = (byte)(yb[31] & 0x7F);
        BigInteger y = LE(yb, 0, 32);
        if (y >= P) return null;
        BigInteger y2 = Mod(y * y);
        BigInteger x2 = Mod((y2 - 1) * Inv(D * y2 + 1));
        BigInteger x = BigInteger.ModPow(x2, (P + 3) / 8, P);
        if (Mod(x * x - x2) != 0) x = Mod(x * SqrtM1);
        if (Mod(x * x - x2) != 0) return null;
        if (x.IsZero && sign == 1) return null;
        if ((int)(x & 1) != sign) x = Mod(P - x);
        return new BigInteger[] { x, y, 1, Mod(x * y) };
    }

    static BigInteger[] Add(BigInteger[] p, BigInteger[] q)
    {
        BigInteger a = Mod((p[1] - p[0]) * (q[1] - q[0]));
        BigInteger b = Mod((p[1] + p[0]) * (q[1] + q[0]));
        BigInteger c = Mod(p[3] * 2 * D * q[3]);
        BigInteger d = Mod(p[2] * 2 * q[2]);
        BigInteger e = b - a, f = d - c, g = d + c, h = b + a;
        return new BigInteger[] { Mod(e * f), Mod(g * h), Mod(f * g), Mod(e * h) };
    }

    static BigInteger[] Double(BigInteger[] p)
    {
        BigInteger a = Mod(p[0] * p[0]);
        BigInteger b = Mod(p[1] * p[1]);
        BigInteger c = Mod(2 * p[2] * p[2]);
        BigInteger h = a + b;
        BigInteger e = h - Mod((p[0] + p[1]) * (p[0] + p[1]));
        BigInteger g = a - b;
        BigInteger f = c + g;
        return new BigInteger[] { Mod(e * f), Mod(g * h), Mod(f * g), Mod(e * h) };
    }

    static BigInteger[] Mul(BigInteger s, BigInteger[] p)
    {
        BigInteger[] q = new BigInteger[] { 0, 1, 1, 0 };
        for (int i = 255; i >= 0; i--)
        {
            q = Double(q);
            if (((s >> i) & 1) == 1) q = Add(q, p);
        }
        return q;
    }

    static bool Equal(BigInteger[] p, BigInteger[] q)
    {
        if (Mod(p[0] * q[2] - q[0] * p[2]) != 0) return false;
        if (Mod(p[1] * q[2] - q[1] * p[2]) != 0) return false;
        return true;
    }

    public static bool Verify(byte[] pub, byte[] sig, byte[] msg)
    {
        if (pub == null || sig == null || pub.Length != 32 || sig.Length != 64) return false;
        BigInteger[] a = Decode(pub, false);
        if (a == null) return false;
        byte[] rEnc = new byte[32];
        Array.Copy(sig, 0, rEnc, 0, 32);
        BigInteger[] r = Decode(rEnc, false);
        if (r == null) return false;
        BigInteger s = LE(sig, 32, 32);
        if (s >= L) return false;

        byte[] hashInput = new byte[64 + msg.Length];
        Array.Copy(rEnc, 0, hashInput, 0, 32);
        Array.Copy(pub, 0, hashInput, 32, 32);
        Array.Copy(msg, 0, hashInput, 64, msg.Length);
        byte[] digest;
        using (SHA512 sha = SHA512.Create()) { digest = sha.ComputeHash(hashInput); }
        BigInteger h = LE(digest, 0, 64) % L;

        BigInteger[] left = Mul(s, B);
        BigInteger[] right = Add(r, Mul(h, a));
        return Equal(left, right);
    }
}
'@
		$addTypeParams = @{ TypeDefinition = $source; Language = 'CSharp'; ErrorAction = 'Stop' }
		if ($PSVersionTable.PSEdition -eq 'Desktop')
		{$addTypeParams['ReferencedAssemblies'] = @('System.Numerics')}
		Add-Type @addTypeParams
	}

	return [DnsToolsEd25519V1]::Verify($PublicKey, $Signature, $Message)
}
