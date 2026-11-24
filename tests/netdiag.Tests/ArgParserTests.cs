using Xunit;

namespace NetDiag.Tests;

public class ArgParserTests
{
    [Fact]
    public void Parse_PositionalsAndOptions()
    {
        ArgParser parsed = ArgParser.Parse(new[] { "example.com", "--type", "AAAA" }, "type", "server");

        Assert.Equal("example.com", parsed.RequirePositional(0, "host"));
        Assert.Equal("AAAA", parsed.Option("type", "A"));
        Assert.False(parsed.HasOption("server"));
    }

    [Fact]
    public void Parse_EqualsForm()
    {
        ArgParser parsed = ArgParser.Parse(new[] { "--type=MX" }, "type");

        Assert.Equal("MX", parsed.Option("type", "A"));
    }

    [Fact]
    public void Parse_UnknownOption_ThrowsUsageException()
    {
        Assert.Throws<UsageException>(() => ArgParser.Parse(new[] { "--bogus", "x" }, "type"));
    }

    [Fact]
    public void OptionInt_InvalidValue_ThrowsUsageException()
    {
        ArgParser parsed = ArgParser.Parse(new[] { "--timeout", "abc" }, "timeout");

        Assert.Throws<UsageException>(() => parsed.OptionInt("timeout", 1000));
    }

    [Fact]
    public void OptionInt_MissingValue_ReturnsDefault()
    {
        ArgParser parsed = ArgParser.Parse(Array.Empty<string>(), "timeout");

        Assert.Equal(1000, parsed.OptionInt("timeout", 1000));
    }

    [Fact]
    public void RequirePositional_Missing_ThrowsUsageException()
    {
        ArgParser parsed = ArgParser.Parse(Array.Empty<string>());

        Assert.Throws<UsageException>(() => parsed.RequirePositional(0, "host"));
    }
}
