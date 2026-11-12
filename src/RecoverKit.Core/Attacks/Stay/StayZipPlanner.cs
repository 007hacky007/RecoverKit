using System.Numerics;
using RecoverKit.Core.Formats;

namespace RecoverKit.Core.Attacks.Stay;

/// <summary>Translates the Stay attack into a prepared (internal, no hashcat run) attack.</summary>
public static class StayZipPlanner
{
    /// <summary>Expected work: the ~2^38 divide-and-conquer search over the cipher's carry structure.</summary>
    public static BigInteger Keyspace { get; } = BigInteger.One << 38;

    public static PreparedAttack Prepare(AttackSpec a, HashTarget target)
    {
        if (target.StayZip is null || !StayAttack.Supports(target.StayZip))
            throw new AttackPlanException("The fast key search applies only to ZIP archives with five or more ZipCrypto-encrypted files.");
        return new PreparedAttack { Description = a.Describe(), Keyspace = Keyspace };
    }
}
