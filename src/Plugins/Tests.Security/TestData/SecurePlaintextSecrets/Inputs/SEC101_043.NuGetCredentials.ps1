<packageSources>
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" protocolVersion="3" />
    <add key="Contoso" value="https://contoso.com/packages/" />
    <add key="Test Source" value="c:\packages" />
</packageSources>
<packageSourceCredentials>
    <Contoso>
        <add key="Username" value="user1111@contoso.com" />
        <add key="Password" value="1111_Oneoneone" />
    </Contoso>
    <Test_x0020_Source>
        <add key="Username" value="user2222" />
        <add key="Password" value="2222_Twotwotwo" />
    </Test_x0020_Source>
</packageSourceCredentials>

<packageSources>
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" protocolVersion="3" />
    <add key="Contoso" value="https://contoso.com/packages/" />
    <add key="Test Source" value="c:\packages" />
</packageSources>
<packageSourceCredentials>
    <Contoso>
        <add key="Username" value="user4444@contoso.com" />
        <add key="ClearTextPassword" value="%passwordVariable4444_Fourfour%" />
    </Contoso>
    <Test_x0020_Source>
        <add key="Username" value="user5555" />
        <add key="ClearTextPassword" value="%passwordVariable5555_Fivefive%" />
    </Test_x0020_Source>
</packageSourceCredentials>

<packageSources>\nstuff\n<\/packageSources>\n
<packageSourceCredentials >\n      <buildxl>\n          <add key=\"Username\" value=\"user6666\" />\n          <add key=\"Password\" value=\"$(passwordVariable6666_Sixsixsix)\" />

<configuration><packageSources><add key=\"dummyKey\" value=\"https://location.visualstudio.com/_packaging/dummyKey/nuget/v3/index.json\" /></packageSources><packageSourceCredentials><dummyKey><add key=\"Username\" value=\"user7777\" /><add key=\"ClearTextPassword\" value=\"7777_Sevensevenseven\" /></dummyKey></packageSourceCredentials></configuration>