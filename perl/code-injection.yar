rule CODE_INJECTION : PERL {
    meta:
        author      = "Omar Elshopky"
        date        = "2022/Feb/9"
        description = "Find PERL scripts use request's parameters in eval - possible code injection vulns"
        filetype    = "perl"

    strings:
        $h1 = "#!/usr/bin/" // "#!/usr/bin/perl"

        $u1 = "Request" nocase

        $f1 = "eval" nocase

  condition:
        $h1 at 0 and $u1 and $f1
}