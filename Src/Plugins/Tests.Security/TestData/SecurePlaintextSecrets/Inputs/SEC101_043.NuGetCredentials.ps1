<packageSources>
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" protocolVersion="3" />
    <add key="Contoso" value="https://contoso.com/packages/" />
    <add key="Test Source" value="c:\packages" />
</packageSources>
<packageSourceCredentials>
    <Contoso>
        <add key="Username" value="user@contoso.com" />
        <add key="Password" value="..." />
    </Contoso>
    <Test_x0020_Source>
        <add key="Username" value="user" />
        <add key="Password" value="..." />
    </Test_x0020_Source>
</packageSourceCredentials>

<packageSources>
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" protocolVersion="3" />
    <add key="Contoso" value="https://contoso.com/packages/" />
    <add key="Test Source" value="c:\packages" />
</packageSources>
<packageSourceCredentials>
    <Contoso>
        <add key="Username" value="user@contoso.com" />
        <add key="ClearTextPassword" value="%ContosoPassword%" />
    </Contoso>
    <Test_x0020_Source>
        <add key="Username" value="user" />
        <add key="ClearTextPassword" value="%TestSourcePassword%" />
    </Test_x0020_Source>
</packageSourceCredentials>

<packageSources>\nstuff\n<\/packageSources>\n
<packageSourceCredentials >\n      <buildxl>\n          <add key=\"Username\" value=\"domino\" />\n          <add key=\"Password\" value=\"$(place.variable.name)\" />

<configuration><packageSources><add key=\"dummyKey\" value=\"https://location.visualstudio.com/_packaging/dummyKey/nuget/v3/index.json\" /></packageSources><packageSourceCredentials><dummyKey><add key=\"Username\" value=\"dummyUserName\" /><add key=\"ClearTextPassword\" value=\"dummyPassword\" /></dummyKey></packageSourceCredentials></configuration>