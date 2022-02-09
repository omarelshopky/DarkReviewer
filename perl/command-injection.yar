rule COMMAND_INJECTION : PERL {
    meta:
        author      = "Omar Elshopky"
        date        = "2022/Feb/9"
        description = "Find PERL scripts use request's parameters in system - possible command injection vulns"
        filetype    = "perl"

    strings:
        $h1 = "#!/usr/bin/" // "#!/usr/bin/perl"

        $u1 = "Request" nocase

        $f1 = "system" nocase

  condition:
        $h1 at 0 and $u1 and $f1
}