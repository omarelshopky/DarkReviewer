rule COMMAND-INJECTION : PERL {
    meta:
        author      = "Omar Elshopky"
        date        = "2022/Feb/9"
        description = "Find PHP scripts contains $_GET $_POST - possible SQL Injection vulns"
        filetype    = "perl"

    strings:
        $p1 = "<?"

        $s1 = "$_GET["
        $s2 = "$_POST["

        $d1 = "mysql_query("
        $d2 = "mysqli_query"
        $d3 = "mssql_query"
        $d4 = "sqlsrv_query"

  condition:
        $p1 at 0 and any of ($s*) and any of ($d*)
        $p1 at 0 and ( ($s1 and any of ($d*)) or ($n1 and any of ($d*)) )
}