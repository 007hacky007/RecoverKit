using System.Text;

namespace RecoverKit.Core.Formats;

internal static class BinaryWordRestrictions
{
    private sealed record Patch(string Stream, int Offset, byte[] Bytes);
    private sealed record Restrictions(List<Patch> Patches, bool Editing, bool Reservation, string? Password);

    internal static void Extract(CompoundFile cf, Detection detection)
    {
        var restrictions = Read(cf);
        if (restrictions.Patches.Count == 0) return;
        if (restrictions.Editing) Add("Word editing restrictions can be removed", null);
        if (restrictions.Reservation) Add("Word password to modify / read-only recommendation can be removed", restrictions.Password);
        detection.Message = "Word editing / write restrictions can be removed without a password.";

        void Add(string title, string? password) => detection.Unlocks.Add(new InstantUnlock
        {
            Title = title,
            Description = "Saving turns off editing restrictions and write reservation without changing stream sizes. " +
                (password is null ? "The password is not recovered; it is not needed to remove these restrictions." : "The write-reservation password is stored in the document."),
            Password = password,
            SaveLabel = "Save unrestricted copy...",
            SaveCopyAsync = (source, output, ct) => RestrictionCopy.SaveAsync(source, output, ct, stream =>
            {
                var copy = new CompoundFile(stream);
                var current = Read(copy);
                if (current.Patches.Count == 0) throw new FormatException("Word restrictions are no longer present.");
                foreach (var patch in current.Patches) copy.WriteStreamRange(patch.Stream, patch.Offset, patch.Bytes);
            }),
        });
    }

    private static Restrictions Read(CompoundFile cf)
    {
        var wd = cf.ReadStream("WordDocument", 4096) ?? throw new FormatException("Missing WordDocument stream.");
        Bin.Need(wd, 0, 34);
        if (Bin.U16(wd, 0) != 0xA5EC) throw new FormatException("Invalid Word FIB signature.");
        ushort flags = Bin.U16(wd, 10);
        if ((flags & 0x0100) != 0) throw new FormatException("Encrypted Word files cannot be unrestricted without decryption.");
        if (Bin.U16(wd, 2) is not (0xC1 or 0xD9 or 0x101 or 0x10C or 0x112))
            throw new UnsupportedFormatException("Editing restrictions are supported only for Word 97-2003 binary files.");

        int pos = 34 + Bin.U16(wd, 32) * 2;
        Bin.Need(wd, pos, 2);
        pos += 2 + Bin.U16(wd, pos) * 4;
        Bin.Need(wd, pos, 2);
        int count = Bin.U16(wd, pos);
        pos += 2;
        if (count < 34) throw new FormatException("Word FIB has no document properties.");
        Bin.Need(wd, pos, 34 * 8);
        string tableName = (flags & 0x0200) != 0 ? "1Table" : "0Table";
        const int limit = 32 * 1024 * 1024;
        var table = cf.ReadStream(tableName, limit) ?? throw new FormatException("Word table stream is missing.");
        (int Offset, int Size) Range(int index)
        {
            uint offset = Bin.U32(wd, pos + index * 8), size = Bin.U32(wd, pos + index * 8 + 4);
            if (offset > table.Length || size > table.Length - offset)
                throw new FormatException("Word property range is truncated or exceeds the 32 MiB restriction limit.");
            return ((int)offset, (int)size);
        }
        var dopRange = Range(31);
        if (dopRange.Size < 84) throw new FormatException("Word document properties are truncated.");
        int dop = dopRange.Offset;
        bool editing = (table[dop + 6] & 0x10) != 0 || (table[dop + 7] & 0x42) != 0;
        bool modern = dopRange.Size >= 600;
        if (modern) editing |= (table[dop + 594] & 0x22) != 0 || (table[dop + 598] & 8) != 0;
        bool reservation = (flags & 0x0c00) != 0;
        bool key = Bin.U32(table, dop + 78) != 0;
        var patches = new List<Patch>();
        string? password = null;

        // SttbfAssoc entry 17 holds the write-reservation password, not an encryption key.
        var assoc = Range(32);
        if (assoc.Size > 0 && reservation)
        {
            int cursor = assoc.Offset, end = cursor + assoc.Size;
            Bin.Need(table, cursor, 6);
            if (assoc.Size < 6 || Bin.U16(table, cursor) != 0xffff || Bin.U16(table, cursor + 2) != 18 || Bin.U16(table, cursor + 4) != 0)
                throw new FormatException("Unsupported Word associated-string table.");
            cursor += 6;
            for (int i = 0; i < 18; i++)
            {
                if (cursor > end - 2) throw new FormatException("Truncated Word associated string.");
                int length = Bin.U16(table, cursor);
                int bytes = length == 0xffff ? 0 : length * 2;
                if (bytes > end - cursor - 2 || (i == 17 && length != 0xffff && length > 15))
                    throw new FormatException("Invalid Word associated string length.");
                if (i == 17 && bytes > 0)
                {
                    password = Encoding.Unicode.GetString(table, cursor + 2, bytes);
                    patches.Add(new Patch(tableName, cursor, new byte[bytes + 2]));
                }
                cursor += 2 + bytes;
            }
        }
        if (!editing && !reservation && !key) return new(patches, false, false, null);
        patches.Add(new Patch("WordDocument", 10, [(byte)flags, (byte)((flags & ~0x0c00) >> 8)]));
        patches.Add(new Patch(tableName, dop + 5, [(byte)(table[dop + 5] & ~0x20), (byte)(table[dop + 6] & ~0x10), (byte)(table[dop + 7] & ~0x46)]));
        patches.Add(new Patch(tableName, dop + 78, new byte[4]));
        if (modern)
        {
            patches.Add(new Patch(tableName, dop + 594, [(byte)(table[dop + 594] & ~0x23)]));
            patches.Add(new Patch(tableName, dop + 598, [(byte)((table[dop + 598] & ~0x78) | 0x70)]));
        }
        return new(patches, editing, reservation || (!editing && key), password);
    }
}
