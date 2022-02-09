rule SQL_INJECTION : PERL {
    meta:
        author      = "Omar Elshopky"
        date        = "2022/Feb/9"
        description = "Find PERL scripts use request's parameters in database query - possible sql injection vulns"
        filetype    = "perl"

    strings:
        $h1 = "#!/usr/bin/" // "#!/usr/bin/perl"

        $u1 = "Request" nocase
        $u2 = "param" nocase

        $f1 = "db" nocase
        $f2 = "select" nocase

        // Bind the parameter to the SQL query
        $s1 = /db.{0,5}?->.{0,20}?\(.{1,200}?,.{,200}?\)/is
        $s2 = /db.{0,5}?->.{0,20}?\(.{1,200}?\?.{1,200}?\)/is 

  condition:
        $h1 at 0 and (any of ($u*)) and (any of ($f*)) and not (any of ($s*))
}